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
#include "mbedtls/sha256.h"
#include "mbedtls/error.h"
#include "../miniz/miniz.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include "certs/isrgrootx1.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "mqtt_app.h"
#include "ota_control.h"
#include "certs/pub_ecdsa.h"
#include "esp_crt_bundle.h"

// polinema server https
#define MANIFEST_URL "https://ota.sinaungoding.com:8443/api/v1/firmware/manifest.json"
#define FIRMWARE_URL "https://ota.sinaungoding.com:8443/api/v1/firmware/firmware-otaq.bin"
#define TAG "OTA_SECURE"
#define MAX_MANIFEST_SIZE 4096

#define HASH_LEN_BYTES 32
#define HASH_HEX_LEN (HASH_LEN_BYTES * 2)
#define HASH_HEX_BUF (HASH_HEX_LEN + 1)

#define SIG_BUF_LEN 145

#define MANIFEST_PATH "/spiffs/manifest.json"
#define FIRMWARE_PATH "/spiffs/firmware-otaq.bin"

static volatile bool ota_flag = false;
static uint64_t stage_start_time = 0;

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

/* ---------------- Download single file to SPIFFS (generic) ---------------- */
static bool download_file_to_spiffs(const char *url, const char *dest_path)
{
    esp_http_client_config_t config = {
        .url = url,
        .crt_bundle_attach = esp_crt_bundle_attach,
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

    // Reset WDT before long operations
    esp_task_wdt_reset();
    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_http_client_open failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return false;
    }
    int content_length = esp_http_client_fetch_headers(client);
    int status_code = esp_http_client_get_status_code(client);
    ESP_LOGI(TAG, "[HTTP] GET %s Status=%d, Length=%d", url, status_code, content_length);

    if (status_code != 200)
    {
        ESP_LOGE(TAG, "[HTTP] Bad status code: %d", status_code);
        esp_http_client_cleanup(client);
        return false;
    }

    esp_task_wdt_reset();
    FILE *f = fopen(dest_path, "wb");
    esp_task_wdt_reset();
    if (!f)
    {
        ESP_LOGE(TAG, "Failed to open %s for writing", dest_path);
        esp_http_client_cleanup(client);
        return false;
    }

    const int buf_size = 8192;
    uint8_t *buffer = malloc(buf_size);
    if (!buffer)
    {
        ESP_LOGE(TAG, "malloc failed for http buffer");
        fclose(f);
        esp_http_client_cleanup(client);
        return false;
    }

    int total_read = 0;
    int last_percent = -1;

    while (1)
    {
        // Reset WDT while downloading
        esp_task_wdt_reset();
        int read_len = esp_http_client_read(client, (char *)buffer, buf_size);

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
            ESP_LOGI(TAG, "[HTTP] Download finished: %d bytes", total_read);
            break;
        }

        size_t wrote = fwrite(buffer, 1, read_len, f);
        if (wrote != (size_t)read_len)
        {
            ESP_LOGE(TAG, "[SPIFFS] fwrite failed");
            free(buffer);
            fclose(f);
            esp_http_client_cleanup(client);
            return false;
        }

        total_read += read_len;
        esp_task_wdt_reset();

        // Progress log
        if (content_length > 0)
        {
            int percent = (total_read * 100) / content_length;
            if (percent != last_percent && percent % 10 == 0)
            {
                ESP_LOGI(TAG, "[HTTP] Progress: %d%% (%d/%d)", percent, total_read, content_length);
                last_percent = percent;
            }
        }
    }

    free(buffer);
    // Reset WDT before finishing file operations
    esp_task_wdt_reset();
    fflush(f);
    fsync(fileno(f));
    fclose(f);

    // Reset WDT before cleaning up HTTP client
    esp_task_wdt_reset();
    esp_http_client_cleanup(client);

    // Verify file size
    struct stat st;
    if (stat(dest_path, &st) != 0)
    {
        ESP_LOGE(TAG, "[HTTP] Failed to stat %s", dest_path);
        return false;
    }

    ESP_LOGI(TAG, "[HTTP] File saved: %s (%d bytes)", dest_path, (int)st.st_size);

    if (st.st_size != total_read)
    {
        ESP_LOGE(TAG, "[HTTP] Size mismatch! Expected %d, got %d", total_read, (int)st.st_size);
        return false;
    }

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
    mbedtls_sha256_context sha_ctx;
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

    // update SHA256
    mbedtls_sha256_update(&st->sha_ctx, (const unsigned char *)pBuf, n);

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

/* ---------------- Flash OTA from .bin file in SPIFFS ---------------- */
static bool flash_firmware_from_spiffs(const char *bin_path, const char *expected_hash_hex, const char *signature_hex)
{
    ota_monitor_start_stage();

    // Open firmware file
    esp_task_wdt_reset();
    FILE *f = fopen(bin_path, "rb");
    if (!f)
    {
        ESP_LOGE(TAG, "[OTA] Failed to open %s", bin_path);
        return false;
    }

    // Get file size
    fseek(f, 0, SEEK_END);
    size_t fw_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    ESP_LOGI(TAG, "[OTA] Firmware size: %u bytes", (unsigned)fw_size);

    if (fw_size == 0)
    {
        ESP_LOGE(TAG, "[OTA] Firmware size is zero");
        fclose(f);
        return false;
    }

    // Begin OTA
    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (!update_partition)
    {
        ESP_LOGE(TAG, "[OTA] No update partition found");
        fclose(f);
        return false;
    }

    esp_ota_handle_t ota_handle;
    esp_task_wdt_reset();

    if (esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &ota_handle) != ESP_OK)
    {
        ESP_LOGE(TAG, "[OTA] esp_ota_begin failed");
        fclose(f);
        return false;
    }

    ESP_LOGI(TAG, "[OTA] Begin writing to partition 0x%x", update_partition->address);

    // Init SHA256
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);

    // Stream file to OTA partition
    const int buf_size = 8192;
    uint8_t *buffer = malloc(buf_size);
    if (!buffer)
    {
        ESP_LOGE(TAG, "[OTA] malloc failed");
        fclose(f);
        esp_ota_end(ota_handle);
        return false;
    }

    size_t total_written = 0;
    int last_percent = -1;

    while (1)
    {
        size_t read_len = fread(buffer, 1, buf_size, f);

        if (read_len == 0)
        {
            if (feof(f))
            {
                ESP_LOGI(TAG, "[OTA] File read complete: %u bytes", (unsigned)total_written);
                break;
            }
            else
            {
                ESP_LOGE(TAG, "[OTA] fread error");
                free(buffer);
                fclose(f);
                esp_ota_end(ota_handle);
                return false;
            }
        }

        // Update SHA
        mbedtls_sha256_update(&sha_ctx, buffer, read_len);

        // Write to OTA
        esp_err_t err = esp_ota_write(ota_handle, buffer, read_len);
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "[OTA] esp_ota_write failed: %s", esp_err_to_name(err));
            free(buffer);
            fclose(f);
            esp_ota_end(ota_handle);
            return false;
        }

        total_written += read_len;
        esp_task_wdt_reset();

        // Progress
        int percent = (int)((total_written * 100) / fw_size);
        if (percent != last_percent && percent % 10 == 0)
        {
            ESP_LOGI(TAG, "[OTA] Writing: %d%% (%u/%u)", percent, (unsigned)total_written, (unsigned)fw_size);
            last_percent = percent;
        }
    }

    free(buffer);
    fclose(f);

    // Finalize SHA
    uint8_t calc_hash[32];
    mbedtls_sha256_finish(&sha_ctx, calc_hash);
    mbedtls_sha256_free(&sha_ctx);

    ota_monitor_end_stage("flash_firmware");

    // Verify hash
    ota_monitor_start_stage();
    char calc_hash_hex[65];
    for (int i = 0; i < 32; ++i)
        sprintf(calc_hash_hex + i * 2, "%02x", calc_hash[i]);
    calc_hash_hex[64] = '\0';

    ESP_LOGI(TAG, "[OTA] Computed hash: %s", calc_hash_hex);
    ESP_LOGI(TAG, "[OTA] Expected hash: %s", expected_hash_hex);

    if (strcmp(calc_hash_hex, expected_hash_hex) != 0)
    {
        ESP_LOGE(TAG, "[OTA] Hash mismatch!");
        esp_ota_end(ota_handle);
        return false;
    }
    ota_monitor_end_stage("verify_hash");

    // Verify signature
    ota_monitor_start_stage();
    uint8_t signature[SIG_BUF_LEN];
    int sig_len = hexstr_to_bytes(signature_hex, signature, sizeof(signature));
    if (sig_len < 0)
    {
        ESP_LOGE(TAG, "[OTA] Signature hex->bytes conversion failed: %d", sig_len);
        esp_ota_end(ota_handle);
        return false;
    }

    // verify ECDSA over the 32-byte hash
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int ret = mbedtls_pk_parse_public_key(&pk, PUBLIC_KEY_PEM_P256, sizeof(PUBLIC_KEY_PEM_P256));
    if (ret != 0)
    {
        ESP_LOGE(TAG, "[OTA] Failed to parse public key: -0x%04X", -ret);
        esp_ota_end(ota_handle);
        return false;
    }

    ESP_LOGI(TAG, "[OTA] pk type: %d", mbedtls_pk_get_type(&pk));
    ESP_LOGI(TAG, "[OTA] Signature length: %d", sig_len);
    ESP_LOGI(TAG, "[OTA] Hash length: %d", (int)sizeof(calc_hash));
    // ESP_LOG_BUFFER_HEX(TAG, calc_hash, sizeof(calc_hash));
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, calc_hash, 0, signature, sig_len);
    if (ret != 0)
    {
        char err_buf[200];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "[OTA] Signature verification FAILED: -0x%04X (%d): %s", -ret, ret, err_buf);
        esp_ota_end(ota_handle);
        return false;
    }

    mbedtls_pk_free(&pk);
    ota_monitor_end_stage("verify_signature");
    ESP_LOGI(TAG, "[OTA] Hash and signature verified OK");

    // Finalize OTA
    ota_monitor_start_stage();
    if (esp_ota_end(ota_handle) != ESP_OK)
    {
        ESP_LOGE(TAG, "[OTA] esp_ota_end failed");
        return false;
    }

    if (esp_ota_set_boot_partition(update_partition) != ESP_OK)
    {
        ESP_LOGE(TAG, "[OTA] esp_ota_set_boot_partition failed");
        return false;
    }
    ota_monitor_end_stage("ota_finalize");

    ESP_LOGI(TAG, "[OTA] OTA committed. Rebooting...");

    // // Reset WDT before reboot
    // esp_task_wdt_reset();

    // // Cleanup files
    // ESP_LOGI(TAG, "[OTA] Cleaning up files...");
    // if (remove(bin_path) == 0)
    // {
    //     ESP_LOGI(TAG, "[OTA] Firmware file deleted");
    // }
    // else
    // {
    //     ESP_LOGW(TAG, "[OTA] Failed to delete firmware file");
    // }
    // esp_task_wdt_reset();
    // vTaskDelay(pdMS_TO_TICKS(100));

    // ESP_LOGI(TAG, "[OTA] Deleting manifest file...");
    // if (remove(MANIFEST_PATH) == 0)
    // {
    //     ESP_LOGI(TAG, "[OTA] Manifest file deleted");
    // }
    // else
    // {
    //     ESP_LOGW(TAG, "[OTA] Failed to delete manifest file");
    // }

    // Final WDT reset and reboot
    esp_task_wdt_reset();
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();

    return true;
}

/* ---------------- Main OTA function (no ZIP) ---------------- */
static bool perform_ota_update(void)
{
    // 1. Download manifest
    ESP_LOGI(TAG, "[OTA] Downloading manifest...");
    ota_monitor_start_stage();
    if (!download_file_to_spiffs(MANIFEST_URL, MANIFEST_PATH))
    {
        ESP_LOGE(TAG, "[OTA] Failed to download manifest");
        return false;
    }
    ota_monitor_end_stage("download_manifest");

    // 2. Parse manifest
    ota_monitor_start_stage();
    FILE *mf = fopen(MANIFEST_PATH, "rb");
    if (!mf)
    {
        ESP_LOGE(TAG, "[OTA] Failed to open manifest");
        return false;
    }

    fseek(mf, 0, SEEK_END);
    size_t manifest_size = ftell(mf);
    fseek(mf, 0, SEEK_SET);

    if (manifest_size == 0 || manifest_size > MAX_MANIFEST_SIZE)
    {
        ESP_LOGE(TAG, "[OTA] Invalid manifest size: %u", (unsigned)manifest_size);
        fclose(mf);
        return false;
    }

    char *manifest_str = malloc(manifest_size + 1);
    if (!manifest_str)
    {
        ESP_LOGE(TAG, "[OTA] malloc failed for manifest");
        fclose(mf);
        return false;
    }

    fread(manifest_str, 1, manifest_size, mf);
    manifest_str[manifest_size] = '\0';
    fclose(mf);

    ESP_LOGI(TAG, "[OTA] Manifest:\n%s", manifest_str);

    char expected_hash_hex[HASH_HEX_BUF];
    char signature_hex[SIG_BUF_LEN];
    char new_version[64];

    if (!parse_manifest(manifest_str, expected_hash_hex, sizeof(expected_hash_hex),
                        signature_hex, sizeof(signature_hex),
                        new_version, sizeof(new_version)))
    {
        ESP_LOGE(TAG, "[OTA] Failed to parse manifest");
        free(manifest_str);
        return false;
    }
    free(manifest_str);

    ESP_LOGI(TAG, "[OTA] New version: %s", new_version);
    ESP_LOGI(TAG, "[OTA] Current version: %s", FIRMWARE_VERSION);

    // 3. Compare versions
    int cmp = compare_firmware_versions(FIRMWARE_VERSION, new_version);
    if (cmp <= 0)
    {
        ESP_LOGI(TAG, "[OTA] No update needed (current >= new)");
        remove(MANIFEST_PATH);
        return false;
    }

    ESP_LOGI(TAG, "[OTA] Update available. Proceeding...");
    ota_monitor_end_stage("parse_manifest");

    // 4. Download firmware
    ESP_LOGI(TAG, "[OTA] Downloading firmware binary...");
    ota_monitor_start_stage();
    if (!download_file_to_spiffs(FIRMWARE_URL, FIRMWARE_PATH))
    {
        ESP_LOGE(TAG, "[OTA] Failed to download firmware");
        remove(MANIFEST_PATH);
        return false;
    }
    ota_monitor_end_stage("download_firmware");

    // 5. Flash firmware
    ESP_LOGI(TAG, "[OTA] Flashing firmware...");
    if (!flash_firmware_from_spiffs(FIRMWARE_PATH, expected_hash_hex, signature_hex))
    {
        ESP_LOGE(TAG, "[OTA] Failed to flash firmware");
        remove(MANIFEST_PATH);
        remove(FIRMWARE_PATH);
        return false;
    }

    return true;
}

/* ---------------- ota_task (simplified) ---------------- */
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
        esp_task_wdt_reset();

        if (!perform_ota_update())
        {
            ESP_LOGE(TAG, "[OTA] Update failed");
        }

        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    vTaskDelete(NULL);
}
/* ---------------- End of ota_updater.c ---------------- */
