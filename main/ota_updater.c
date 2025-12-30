#include "ota_updater.h"
#include "esp_log.h"
#include "esp_https_ota.h"
#include "esp_ota_ops.h"
#include "esp_task_wdt.h"
#include "esp_spiffs.h"
#include "esp_http_client.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "cJSON.h"
#include "mbedtls/sha512.h"
#include "mbedtls/error.h"
#include "../miniz/miniz.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include "certs/isrgrootx1.h"
#include "certs/fullchain.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "mqtt_app.h"
#include "ota_control.h"
#include "certs/pub_ecdsa.h"
#include "nvs_util.h"

// polinema server https
#define OTA_URL "https://ota.sinaungoding.com:8443/api/v1/firmware/firmware.zip"
// polinema server
// #define OTA_URL "http://103.172.249.254:8000/api/v1/firmware/firmware.zip"
// cloudflared server
// #define OTA_URL "https://fastapi.sinaungoding.com/api/v1/firmware/firmware.zip"
// apatos server
// #define OTA_URL "http://192.168.10.102:8000/api/v1/firmware/firmware.zip"
// local lab server
// #define OTA_URL "http://192.168.137.1:8000/api/v1/firmware/firmware.zip"
#define TAG "OTA_SECURE"
#define MAX_MANIFEST_SIZE 4096
#define SIG_LEN 128

#define UPDATE_ZIP_PATH "/spiffs/update.zip"
#define FIRMWARE_ENTRY_NAME "firmware-otaq.bin" // sesuai zipmu

static volatile bool ota_flag = false;
static uint64_t stage_start_time = 0;

#define HASH_LEN_BYTES 48
#define HASH_HEX_LEN (HASH_LEN_BYTES * 2)
#define HASH_HEX_BUF (HASH_HEX_LEN + 1)

#define SIG_BUF_LEN 256

// measure time spent in each stage
void ota_monitor_start_stage(void)
{
    stage_start_time = esp_timer_get_time();
}

// measure time, heap, CPU usage per task in stage
void ota_monitor_end_stage(const char *stage_name)
{
    // time log
    /* Reset WDT early in this monitoring function to avoid WDT trips while
       collecting task stats / publishing metrics. */
    esp_task_wdt_reset();
    time_t now;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);
    uint64_t elapsed_us = esp_timer_get_time() - stage_start_time;

    // Heap info
    size_t free_heap = esp_get_free_heap_size();
    size_t min_free_heap = esp_get_minimum_free_heap_size();

    // CPU usage per task
    UBaseType_t numTasks = uxTaskGetNumberOfTasks();
    TaskStatus_t *taskStatusArray = malloc(numTasks * sizeof(TaskStatus_t));
    uint32_t totalRunTime = 0;
    if (!taskStatusArray)
        return;

    numTasks = uxTaskGetSystemState(taskStatusArray, numTasks, &totalRunTime);

    // create timestamp ISO 8601
    char timestamp[64];
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02dT%02d:%02d:%02d",
             timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
             timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);

    // Publish global stage info
    char msg[512];
    snprintf(msg, sizeof(msg),
             "{\"stage\":\"%s\",\"elapsed_ms\":%llu,\"free_heap\":%u,\"min_free_heap\":%u,\"algorithm\":\"%s\",\"timestamp\":\"%s\"}",
             stage_name, (unsigned long long)(elapsed_us / 1000),
             (unsigned int)free_heap, (unsigned int)min_free_heap, FIRMWARE_ALGORITHM, timestamp);
    ESP_LOGI(TAG, "[%s] Stage %s completed in %llu ms, free_heap=%u, min_free_heap=%u", timestamp,
             stage_name, (unsigned long long)(elapsed_us / 1000), (unsigned int)free_heap, (unsigned int)min_free_heap);
    mqtt_publish("ota/metrics", msg);

    // Publish CPU usage per task
    for (int i = 0; i < numTasks; i++)
    {
        time(&now);
        localtime_r(&now, &timeinfo);
        snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02dT%02d:%02d:%02d",
                 timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                 timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
        float cpu_percent = 0.0f;
        if (totalRunTime > 0)
            cpu_percent = (float)taskStatusArray[i].ulRunTimeCounter / totalRunTime * 100.0f;

        // Di dalam loop for setiap task (setelah cpu_percent calculation):
        UBaseType_t stack_remaining = taskStatusArray[i].usStackHighWaterMark;
        size_t stack_free_bytes = stack_remaining * sizeof(StackType_t);

        // Tambahkan stack info ke JSON message
        snprintf(msg, sizeof(msg),
                 "{\"stage\":\"%s\",\"task\":\"%s\",\"cpu_percent\":%.2f,"
                 "\"stack_free\":%u,\"algorithm\":\"%s\",\"timestamp\":\"%s\"}",
                 stage_name, taskStatusArray[i].pcTaskName, cpu_percent,
                 (unsigned)stack_free_bytes, FIRMWARE_ALGORITHM, timestamp);

        ESP_LOGI(TAG, "[%s] Task %s CPU usage: %.2f%%", timestamp,
                 taskStatusArray[i].pcTaskName, cpu_percent);
        /* Reset WDT before publishing in case mqtt_publish blocks */
        esp_task_wdt_reset();
        mqtt_publish("ota/cpu", msg);
    }

    free(taskStatusArray);
}

void ota_trigger() { ota_flag = true; }
bool ota_triggered(void)
{
    if (ota_flag)
    {
        ota_flag = false;
        return true;
    }
    return false;
}

/* ---------------- SPIFS mount ---------------- */
void mount_spiffs()
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true};
    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to mount SPIFFS: %s", esp_err_to_name(ret));
    }
    else
    {
        size_t total = 0, used = 0;
        esp_spiffs_info(NULL, &total, &used);
        ESP_LOGI(TAG, "SPIFFS mounted. total: %d bytes, used: %d bytes", (int)total, (int)used);
    }
}

/* ---------------- Download ZIP -> SPIFFS (streaming) ----------------
   Avoid allocating whole zip in RAM.
*/
static bool download_zip_to_spiffs(const char *url)
{
    time_t now;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);

    // create timestamp ISO 8601
    char timestamp[64];
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02dT%02d:%02d:%02d",
             timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
             timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
    ESP_LOGI(TAG, "[%s] Starting download from %s", timestamp, url);
    nvs_util_set_u64("ota", "download_time", now);
    esp_http_client_config_t config = {
        .url = url,
        .cert_pem = fullchain_pem,
        .skip_cert_common_name_check = false,
        .timeout_ms = 30000};

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client)
    {
        ESP_LOGE(TAG, "Failed to init HTTP client");
        return false;
    }
    // Force no gzip (identity)
    esp_http_client_set_header(client, "Accept-Encoding", "identity");
    esp_http_client_set_header(client, "User-Agent", "ESP32");
    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_http_client_open failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return false;
    }
    int content_length = esp_http_client_fetch_headers(client);
    ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %d",
             esp_http_client_get_status_code(client),
             content_length);

    esp_task_wdt_reset(); // Reset WDT before fopen (SPIFFS open may block)
    FILE *f = fopen(UPDATE_ZIP_PATH, "wb");
    esp_task_wdt_reset(); // Reset WDT after fopen
    if (!f)
    {
        ESP_LOGE(TAG, "Failed to open %s for writing", UPDATE_ZIP_PATH);
        esp_http_client_cleanup(client);
        return false;
    }

    const int buf_size = 8192;
    const int PROGRESS_STEP = 5; // log every 5%
    uint8_t *buffer = malloc(buf_size);
    if (!buffer)
    {
        ESP_LOGE(TAG, "malloc failed for http buffer");
        fclose(f);
        esp_http_client_cleanup(client);
        return false;
    }

    ESP_LOGI(TAG, "[HTTP] Start download to %s", UPDATE_ZIP_PATH);
    int total_read = 0;
    int last_percent = -1;
    int last_logged = 0;

    while (1)
    {
        int read_len = esp_http_client_read(client, (char *)buffer, buf_size);
        // ESP_LOGI(TAG, "[HTTP] read_len=%d", read_len);
        if (read_len < 0)
        {
            ESP_LOGE(TAG, "[HTTP] read error");
            free(buffer);
            fclose(f);
            esp_http_client_cleanup(client);
            return false;
        }
        if (read_len == 0)
        {
            ESP_LOGI(TAG, "[HTTP] Download finished, total %d bytes", total_read);
            break;
        }
        size_t wrote = fwrite(buffer, 1, read_len, f);
        if (wrote != (size_t)read_len)
        {
            ESP_LOGE(TAG, "[SPIFFS] fwrite failed (wrote=%d expected=%d)", (int)wrote, read_len);
            free(buffer);
            fclose(f);
            esp_http_client_cleanup(client);
            esp_task_wdt_reset();
            return false;
        }
        total_read += read_len;
        esp_task_wdt_reset();

        // Logger progress
        if (content_length > 0)
        {
            int percent = (total_read * 100) / content_length;
            if (percent != last_percent && percent % PROGRESS_STEP == 0)
            {
                ESP_LOGI(TAG, "[HTTP] Download progress: %d%% (%d/%d bytes)", percent, total_read, content_length);
                last_percent = percent;
            }
        }
        else
        {
            // Fallback log per 64KB
            if (total_read - last_logged >= 65536)
            {
                ESP_LOGI(TAG, "[HTTP] Downloaded %d KB", total_read / 1024);
                last_logged = total_read;
            }
        }
    }

    free(buffer);
    fclose(f);
    esp_http_client_cleanup(client);
    return true;
}

/* ---------------- cJSON manifest parser ----------------
   Expects JSON keys "hash", "signature", and "version".
*/
static bool parse_manifest(const char *manifest_str, char *hash_out, size_t hash_len,
                           char *sig_out, size_t sig_len, char *version_out, size_t version_len)
{
    cJSON *root = cJSON_Parse(manifest_str);
    if (!root)
    {
        ESP_LOGE(TAG, "Failed to parse manifest JSON");
        return false;
    }

    const cJSON *hash_item = cJSON_GetObjectItemCaseSensitive(root, "hash");
    const cJSON *sig_item = cJSON_GetObjectItemCaseSensitive(root, "signature");
    const cJSON *version_item = cJSON_GetObjectItemCaseSensitive(root, "version");

    if (!cJSON_IsString(hash_item) || !cJSON_IsString(sig_item) || !cJSON_IsString(version_item))
    {
        ESP_LOGE(TAG, "Manifest fields missing or not strings");
        cJSON_Delete(root);
        return false;
    }

    ESP_LOGI(TAG, "Manifest field lengths -> hash: %d, sig: %d, version: %d",
             strlen(hash_item->valuestring),
             strlen(sig_item->valuestring),
             strlen(version_item->valuestring));

    if (strlen(hash_item->valuestring) >= hash_len ||
        strlen(sig_item->valuestring) >= sig_len ||
        strlen(version_item->valuestring) >= version_len)
    {
        ESP_LOGE(TAG, "Manifest values too long for buffers "
                      "(hash:%d/%d sig:%d/%d ver:%d/%d)",
                 strlen(hash_item->valuestring), hash_len,
                 strlen(sig_item->valuestring), sig_len,
                 strlen(version_item->valuestring), version_len);
        cJSON_Delete(root);
        return false;
    }

    strncpy(hash_out, hash_item->valuestring, hash_len);
    strncpy(sig_out, sig_item->valuestring, sig_len);
    strncpy(version_out, version_item->valuestring, version_len);

    cJSON_Delete(root);
    return true;
}

/* ---------------- helper: parse version string ----------------
   Expected formats:
   - "<hash>-YYYYMMDDTHHMM-local"
   - "<hash>-YYYYMMDDTHHMM-buildNN"
   We extract timestamp and optional build number. Returns true on success.
*/
static bool parse_version_components(const char *ver, char *ts_out, size_t ts_len, int *build_num_out)
{
    if (!ver || !ts_out || !build_num_out)
        return false;
    *build_num_out = -1;

    // find first '-' and second '-'
    const char *p1 = strchr(ver, '-');
    if (!p1)
        return false;
    const char *p2 = strchr(p1 + 1, '-');
    if (!p2)
        return false;

    size_t tlen = p2 - (p1 + 1);
    if (tlen + 1 > ts_len)
        return false;
    memcpy(ts_out, p1 + 1, tlen);
    ts_out[tlen] = '\0';

    // suffix after second '-'
    const char *suf = p2 + 1;
    if (strncmp(suf, "build", 5) == 0)
    {
        // parse number after 'build'
        const char *num = suf + 5;
        if (*num == '\0')
            return true; // no number, treat as no build
        char *endptr;
        long v = strtol(num, &endptr, 10);
        if (endptr != num && v >= 0)
            *build_num_out = (int)v;
    }
    // if suffix is 'local' or others, leave build_num_out = -1
    return true;
}

/* ---------------- helper: compare versions ----------------
   Returns: 1 if new_ver is newer than cur_ver
            0 if equal
           -1 if new_ver is older
   Rules:
   - Compare timestamps lexicographically (YYYYMMDDTHHMM).
   - If timestamps equal and both have build numbers, compare them numerically.
   - If timestamps equal and new has build while cur doesn't => new is newer.
   - If timestamps equal and cur has build while new doesn't => new is older.
*/
static int compare_firmware_versions(const char *cur_ver, const char *new_ver)
{
    char cur_ts[32] = {0};
    char new_ts[32] = {0};
    int cur_build = -1;
    int new_build = -1;

    if (!parse_version_components(cur_ver, cur_ts, sizeof(cur_ts), &cur_build))
        return 0; // can't parse -> treat as equal
    if (!parse_version_components(new_ver, new_ts, sizeof(new_ts), &new_build))
        return 0;

    int ts_cmp = strcmp(new_ts, cur_ts);
    /* If current build is a local build and the new version has a CI build
       identifier, prefer the CI build regardless of timestamps. This allows
       developer local images to be replaced by official build artifacts. */
    if (strstr(cur_ver, "-local") != NULL && new_build != -1)
        return 1;

    if (ts_cmp > 0)
        return 1;
    if (ts_cmp < 0)
        return -1;

    // timestamps equal
    if (new_build != -1 && cur_build != -1)
    {
        if (new_build > cur_build)
            return 1;
        if (new_build < cur_build)
            return -1;
        return 0;
    }

    // If neither has build number -> equal
    if (new_build == -1 && cur_build == -1)
        return 0;

    // If only one has build number, prefer the one with build number
    if (new_build != -1)
        return 1; // new has build number, current doesn't
    return -1;    // current has build number, new doesn't
}

/* ---------------- helper: hex -> bytes ---------------- */
int hexstr_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0 || out_len < hlen / 2)
        return -1;

    for (size_t i = 0; i < hlen / 2; ++i)
    {
        unsigned int v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1)
            return -2;
        out[i] = (uint8_t)v;
    }
    return (int)(hlen / 2); // return actual length
}

/* ---------------- Callback state for miniz extraction -> OTA ----------------
   This struct is passed as pOpaque to mz_zip_reader_extract_to_callback.
*/
typedef struct
{
    esp_ota_handle_t ota_handle;
    mbedtls_sha512_context sha_ctx;
    size_t total_written;
    size_t file_size;
    bool error; // set to true if any error occurred in callback
    const esp_partition_t *update_partition;
} extract_callback_state_t;

/* ---------------- mz callback: write chunk to OTA & update SHA ----------------
   Returns number of bytes written (n) on success, 0 on error.
*/
static size_t mz_to_ota_callback(void *pOpaque, mz_uint64 file_ofs, const void *pBuf, size_t n)
{
    (void)file_ofs; // we don't need random-access; miniz may pass offsets
    extract_callback_state_t *st = (extract_callback_state_t *)pOpaque;
    if (!st || st->error)
        return 0;

    // update SHA512
    mbedtls_sha512_update(&st->sha_ctx, (const unsigned char *)pBuf, n);

    // write to OTA
    esp_err_t err = esp_ota_write(st->ota_handle, pBuf, n);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "[OTA CB] esp_ota_write failed: %s", esp_err_to_name(err));
        st->error = true;
        return 0;
    }

    st->total_written += n;

    // progress log (every chunk)
    int progress = 0;
    if (st->file_size > 0)
    {
        progress = (int)((st->total_written * 100) / st->file_size);
    }
    ESP_LOGI(TAG, "[OTA CB] wrote %d bytes (total %d/%d) %d%%",
             (int)n, (int)st->total_written, (int)st->file_size, progress);

    // reset WDT while working
    esp_task_wdt_reset();

    return n;
}

/* ---------------- Main extraction & OTA flow using SPIFFS update.zip ----------------
   Steps:
    - open zip file from SPIFFS
    - extract manifest.json to heap
    - parse manifest (get expected hash hex, signature hex)
    - locate firmware entry and its uncompressed size
    - begin esp_ota on next update partition
    - init sha ctx, call mz_zip_reader_extract_to_callback to stream firmware to ota via callback
    - finalize sha, compare hex, verify signature
    - if ok, call esp_ota_end + esp_ota_set_boot_partition
*/
static bool extract_zip_and_flash_ota(const char *zip_path)
{
    ota_monitor_start_stage();
    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));

    /* Reset WDT before starting zip operations (may block on I/O) */
    esp_task_wdt_reset();

    if (!mz_zip_reader_init_file(&zip, zip_path, 0))
    {
        ESP_LOGE(TAG, "[ZIP] mz_zip_reader_init_file failed for %s", zip_path);
        return false;
    }
    ESP_LOGI(TAG, "[ZIP] Opened %s", zip_path);

    int num_files = (int)mz_zip_reader_get_num_files(&zip);
    ESP_LOGI(TAG, "[ZIP] entries: %d", num_files);

    // 1) extract manifest.json to heap
    int manifest_index = mz_zip_reader_locate_file(&zip, "manifest.json", NULL, 0);
    if (manifest_index < 0)
    {
        ESP_LOGE(TAG, "[ZIP] manifest.json not found");
        mz_zip_reader_end(&zip);
        return false;
    }
    mz_zip_archive_file_stat manifest_stat;
    if (!mz_zip_reader_file_stat(&zip, manifest_index, &manifest_stat))
    {
        ESP_LOGE(TAG, "[ZIP] stat manifest failed");
        mz_zip_reader_end(&zip);
        return false;
    }
    if (manifest_stat.m_uncomp_size == 0 || manifest_stat.m_uncomp_size > MAX_MANIFEST_SIZE - 1)
    {
        ESP_LOGE(TAG, "[ZIP] manifest.json size invalid: %llu", (unsigned long long)manifest_stat.m_uncomp_size);
        mz_zip_reader_end(&zip);
        return false;
    }
    /* Reset WDT before extracting manifest to heap (may allocate/copy several KB) */
    esp_task_wdt_reset();
    void *manifest_heap = mz_zip_reader_extract_to_heap(&zip, manifest_index, NULL, 0);
    if (!manifest_heap)
    {
        ESP_LOGE(TAG, "[ZIP] extract manifest to heap failed");
        mz_zip_reader_end(&zip);
        return false;
    }
    size_t manifest_len = (size_t)manifest_stat.m_uncomp_size;
    char *manifest = malloc(manifest_len + 1);
    if (!manifest)
    {
        ESP_LOGE(TAG, "[ZIP] malloc manifest failed");
        mz_free(manifest_heap);
        mz_zip_reader_end(&zip);
        return false;
    }
    memcpy(manifest, manifest_heap, manifest_len);
    manifest[manifest_len] = '\0';
    mz_free(manifest_heap);
    ESP_LOGI(TAG, "[ZIP] manifest extracted (%d bytes):\n%s", (int)manifest_len, manifest);

    // parse manifest
    char expected_hash_hex[HASH_HEX_BUF];
    char signature_hex[SIG_BUF_LEN];
    char new_version[64];
    if (!parse_manifest(manifest, expected_hash_hex, sizeof(expected_hash_hex),
                        signature_hex, sizeof(signature_hex),
                        new_version, sizeof(new_version)))
    {
        ESP_LOGE(TAG, "[OTA] parse manifest failed");
        free(manifest);
        mz_zip_reader_end(&zip);
        return false;
    }
    ESP_LOGI(TAG, "[OTA] expected hash: %s", expected_hash_hex);
    ESP_LOGI(TAG, "[OTA] signature hex: %s", signature_hex);
    ESP_LOGI(TAG, "[OTA] new version: %s", new_version);
    ESP_LOGI(TAG, "[OTA] current version: %s", FIRMWARE_VERSION);

    // Compare versions using compare_firmware_versions helper
    ota_monitor_start_stage();
    int cmp = compare_firmware_versions(FIRMWARE_VERSION, new_version);
    if (cmp < 0)
    {
        ESP_LOGI(TAG, "[OTA] Current firmware is newer than candidate. Skipping update.");
        free(manifest);
        mz_zip_reader_end(&zip);
        return false;
    }
    else if (cmp == 0)
    {
        ESP_LOGI(TAG, "[OTA] Current firmware version equals candidate. Skipping update.");
        free(manifest);
        mz_zip_reader_end(&zip);
        return false;
    }
    ESP_LOGI(TAG, "[OTA] Candidate firmware is newer. Proceeding with update.");
    ota_monitor_end_stage("version_check");
    ota_monitor_end_stage("parse_manifest");

    // 2) locate firmware entry
    ota_monitor_start_stage();
    int fw_index = mz_zip_reader_locate_file(&zip, FIRMWARE_ENTRY_NAME, NULL, 0);
    if (fw_index < 0)
    {
        ESP_LOGE(TAG, "[ZIP] firmware entry %s not found", FIRMWARE_ENTRY_NAME);
        free(manifest);
        mz_zip_reader_end(&zip);
        return false;
    }
    mz_zip_archive_file_stat fw_stat;
    if (!mz_zip_reader_file_stat(&zip, fw_index, &fw_stat))
    {
        ESP_LOGE(TAG, "[ZIP] stat firmware failed");
        free(manifest);
        mz_zip_reader_end(&zip);
        return false;
    }
    size_t fw_size = (size_t)fw_stat.m_uncomp_size;
    ESP_LOGI(TAG, "[ZIP] firmware entry found size=%u bytes", (unsigned)fw_size);
    if (fw_size == 0)
    {
        ESP_LOGE(TAG, "[ZIP] firmware size is zero");
        free(manifest);
        mz_zip_reader_end(&zip);
        return false;
    }

    // 3) begin OTA
    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (!update_partition)
    {
        ESP_LOGE(TAG, "[OTA] no update partition found");
        free(manifest);
        mz_zip_reader_end(&zip);
        return false;
    }
    esp_ota_handle_t ota_handle;
    /* Reset WDT before beginning OTA write (flash operations may block) */
    esp_task_wdt_reset();
    if (esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &ota_handle) != ESP_OK)
    {
        ESP_LOGE(TAG, "[OTA] esp_ota_begin failed");
        free(manifest);
        mz_zip_reader_end(&zip);
        return false;
    }
    ESP_LOGI(TAG, "[OTA] esp_ota_begin OK, partition addr=0x%x size=0x%x", update_partition->address, update_partition->size);

    // prepare callback state
    extract_callback_state_t cb_state;
    memset(&cb_state, 0, sizeof(cb_state));
    cb_state.ota_handle = ota_handle;
    cb_state.total_written = 0;
    cb_state.file_size = fw_size;
    cb_state.error = false;
    cb_state.update_partition = update_partition;

    // init SHA
    mbedtls_sha512_init(&cb_state.sha_ctx);
    mbedtls_sha512_starts(&cb_state.sha_ctx, 1); // use SHA-384
    // 4) extract firmware with callback (streaming -> OTA)
    ESP_LOGI(TAG, "[ZIP] Start streaming firmware from zip to OTA (callback)");
    if (!mz_zip_reader_extract_to_callback(&zip, fw_index, mz_to_ota_callback, &cb_state, 0))
    {
        ESP_LOGE(TAG, "[ZIP] extract_to_callback failed");
        cb_state.error = true;
    }

    // finish SHA
    uint8_t calc_hash[HASH_LEN_BYTES];
    mbedtls_sha512_finish(&cb_state.sha_ctx, calc_hash);
    mbedtls_sha512_free(&cb_state.sha_ctx);

    // close zip
    mz_zip_reader_end(&zip);
    ota_monitor_end_stage("extract_and_stream_ota");
    ESP_LOGI(TAG, "[ZIP] extraction finished, total written %u bytes", (unsigned)cb_state.total_written);

    // if callback flagged error -> abort OTA
    if (cb_state.error)
    {
        ESP_LOGE(TAG, "[OTA] Error during streaming - aborting OTA");
        esp_ota_end(ota_handle); // cleanup, don't set boot
        free(manifest);
        return false;
    }

    // 5) compare hash (calc_hash) with expected_hash_hex
    ota_monitor_start_stage();
    char calc_hash_hex[HASH_HEX_BUF];
    for (int i = 0; i < HASH_LEN_BYTES; ++i)
        sprintf(calc_hash_hex + i * 2, "%02x", calc_hash[i]);
    calc_hash_hex[HASH_HEX_LEN] = '\0';
    ESP_LOGI(TAG, "[OTA] computed hash: %s", calc_hash_hex);

    if (strcmp(calc_hash_hex, expected_hash_hex) != 0)
    {
        ESP_LOGE(TAG, "[OTA] Hash mismatch! expected: %s", expected_hash_hex);
        // cleanup: end ota but do not set boot
        esp_ota_end(ota_handle);
        free(manifest);
        return false;
    }
    ota_monitor_end_stage("verify_hash");

    // 6) verify signature: signature is hex in manifest -> bytes
    ota_monitor_start_stage();
    uint8_t signature[SIG_BUF_LEN];
    int sig_len = hexstr_to_bytes(signature_hex, signature, sizeof(signature));
    if (sig_len < 0)
    {
        ESP_LOGE(TAG, "[OTA] Signature hex->bytes conversion failed: %d", sig_len);
        esp_ota_end(ota_handle);
        free(manifest);
        return false;
    }
    // ESP_LOG_BUFFER_HEX(TAG, signature, sig_len);
    ota_monitor_end_stage("hexstr_to_bytes");

    // verify ECDSA over the 32-byte hash
    ota_monitor_start_stage();
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    int ret = mbedtls_pk_parse_public_key(&pk, PUBLIC_KEY_PEM_P384, sizeof(PUBLIC_KEY_PEM_P384));
    if (ret != 0)
    {
        ESP_LOGE(TAG, "[OTA] Failed to parse public key: -0x%04X", -ret);
        esp_ota_end(ota_handle);
        free(manifest);
        return false;
    }

    ESP_LOGI(TAG, "[OTA] pk type: %d", mbedtls_pk_get_type(&pk));
    ESP_LOGI(TAG, "[OTA] Signature length: %d", sig_len);
    ESP_LOGI(TAG, "[OTA] Hash length: %d", (int)sizeof(calc_hash));
    // ESP_LOG_BUFFER_HEX(TAG, calc_hash, sizeof(calc_hash));
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA384, calc_hash, 0, signature, sig_len);
    if (ret != 0)
    {
        char err_buf[200];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "[OTA] Signature verification FAILED: -0x%04X (%d): %s", -ret, ret, err_buf);
        esp_ota_end(ota_handle);
        free(manifest);
        return false;
    }

    mbedtls_pk_free(&pk);
    ota_monitor_end_stage("verify_signature");
    ESP_LOGI(TAG, "[OTA] Hash and signature verified OK");

    // 7) finalize OTA: esp_ota_end already necessary, then set boot partition
    ota_monitor_start_stage();
    if (esp_ota_end(ota_handle) != ESP_OK)
    {
        ESP_LOGE(TAG, "[OTA] esp_ota_end failed");
        free(manifest);
        return false;
    }
    if (esp_ota_set_boot_partition(update_partition) != ESP_OK)
    {
        ESP_LOGE(TAG, "[OTA] esp_ota_set_boot_partition failed");
        free(manifest);
        return false;
    }
    ota_monitor_end_stage("ota_set_boot_partition");
    ESP_LOGI(TAG, "[OTA] OTA committed. Rebooting in 500 ms...");
    free(manifest);
    // optionally remove update.zip from SPIFFS to free space
    remove(zip_path);

    vTaskDelay(pdMS_TO_TICKS(500)); // is needed because we're measuring time until application ready?
    esp_restart();
    return true;
}

/* ---------------- ota_task: orchestrate previous functions ----------------
   - mount spiffs
   - download zip to spiffs
   - extract & flash
*/
void ota_task(void *pvParameter)
{
    esp_task_wdt_add(NULL);
    mount_spiffs();

    while (1)
    {
        if (!ota_triggered())
        {
            vTaskDelay(pdMS_TO_TICKS(1000));
            esp_task_wdt_reset();
            continue;
        }

        ESP_LOGI(TAG, "[OTA] Triggered");

        // Pause sensor task to reduce CPU load during OTA
        ota_pause_sensors();

        // Download zip to SPIFFS
        ESP_LOGI(TAG, "[OTA] Downloading zip from %s ...", OTA_URL);
        ota_monitor_start_stage();
        esp_task_wdt_reset(); // Reset WDT before starting download
        if (!download_zip_to_spiffs(OTA_URL))
        {
            ESP_LOGE(TAG, "[OTA] download_zip_to_spiffs failed");
            ota_resume_sensors();
            continue;
        }
        esp_task_wdt_reset(); // Reset WDT after download
        ota_monitor_end_stage("download_zip_to_spiffs");

        // Extract manifest & stream firmware to OTA
        ESP_LOGI(TAG, "[OTA] Extracting and flashing firmware...");
        esp_task_wdt_reset(); // Reset WDT before extraction
        if (!extract_zip_and_flash_ota(UPDATE_ZIP_PATH))
        {
            ESP_LOGE(TAG, "[OTA] extract_zip_and_flash_ota failed");
            // optionally delete update.zip to retry next time
            // remove(UPDATE_ZIP_PATH);
            ota_resume_sensors();
            continue;
        }

        // Resume sensors if OTA flow returns (normally device will reboot on success)
        ota_resume_sensors();

        // normally won't reach here because extract_zip_and_flash_ota reboots on success
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    vTaskDelete(NULL);
}
/* ---------------- End of ota_updater.c ---------------- */
