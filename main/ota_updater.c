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
#include "monocypher-ed25519.h"
#include "cJSON.h"
#include "mbedtls/sha256.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "mqtt_app.h"
#include "ota_control.h"
#include "esp_crt_bundle.h"

#if FIRMWARE_TLS == 1
// https connections
    #define MANIFEST_URL "https://ota.sinaungoding.com:8443/api/v1/firmware/manifest.json"
    #define FIRMWARE_URL "https://ota.sinaungoding.com:8443/api/v1/firmware/firmware-otaq.bin"
#else
// http connections
    #define MANIFEST_URL "http://broker.sinaungoding.com:8000/api/v1/firmware/manifest.json"
    #define FIRMWARE_URL "http://broker.sinaungoding.com:8000/api/v1/firmware/firmware-otaq.bin"
#endif

#define TAG "OTA_SECURE"
#define MAX_MANIFEST_SIZE 4096
#define SIG_LEN 64

#define MANIFEST_PATH "/spiffs/manifest.json"
#define FIRMWARE_PATH "/spiffs/firmware-otaq.bin"

// ba89c973ffb9836d7c3c9f0b6bc869455cdb6db33aa299c297fd1726f567abd9 -> private key
static const uint8_t PUBLIC_KEY[32] = {0x0B, 0xC1, 0x2F, 0x3D, 0x71, 0x82, 0x04, 0x68, 0x6B, 0x66, 0x90, 0x42, 0xD9, 0x21, 0xC9, 0x1D, 0xB1, 0x2F, 0x83, 0x34, 0x0E, 0x80, 0xC4, 0x83, 0x78, 0x92, 0x82, 0x80, 0x51, 0xFA, 0xFC, 0xD8};

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
             "{\"stage\":\"%s\",\"elapsed_ms\":%llu,\"free_heap\":%u,\"min_free_heap\":%u,\"algorithm\":\"%s\",\"version\":\"%s\",\"timestamp\":\"%s\"}",
             stage_name, (unsigned long long)(elapsed_us / 1000),
             (unsigned int)free_heap, (unsigned int)min_free_heap, FIRMWARE_ALGORITHM, FIRMWARE_VERSION, timestamp);
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
                 "\"stack_free\":%u,\"algorithm\":\"%s\",\"version\":\"%s\",\"timestamp\":\"%s\"}",
                 stage_name, taskStatusArray[i].pcTaskName, cpu_percent,
                 (unsigned)stack_free_bytes, FIRMWARE_ALGORITHM, FIRMWARE_VERSION, timestamp);

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

static void remove_file_if_exists(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
    {
        // File exists
        if (remove(path) == 0)
        {
            ESP_LOGI(TAG, "File %s deleted successfully.", path);
        }
        else
        {
            ESP_LOGW(TAG, "Failed to delete %s.", path);
        }
    }
    else
    {
        ESP_LOGI(TAG, "File %s does not exist, no need to delete.", path);
    }
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
        
        // Clean up old files if SPIFFS usage is high
        if (used > (total / 2))  // If more than 50% used
        {
            ESP_LOGW(TAG, "SPIFFS usage high, cleaning up old files...");
            
            // List all files in SPIFFS
            DIR *dir = opendir("/spiffs");
            int file_count = 0;
            if (dir)
            {
                struct dirent *entry;
                ESP_LOGI(TAG, "Files in SPIFFS:");
                while ((entry = readdir(dir)) != NULL)
                {
                    char full_path[280];  // Increased size: 255 (max filename) + 8 ("/spiffs/") + margin
                    snprintf(full_path, sizeof(full_path), "/spiffs/%s", entry->d_name);
                    
                    struct stat st;
                    if (stat(full_path, &st) == 0)
                    {
                        ESP_LOGI(TAG, "  - %s (%d bytes)", entry->d_name, (int)st.st_size);
                        file_count++;
                        
                        // Delete all files to clean SPIFFS
                        if (remove(full_path) == 0)
                        {
                            ESP_LOGI(TAG, "    Deleted: %s", entry->d_name);
                        }
                    }
                }
                closedir(dir);
            }
            
            // Check usage after cleanup
            esp_spiffs_info(NULL, &total, &used);
            ESP_LOGI(TAG, "SPIFFS after cleanup: total: %d bytes, used: %d bytes, files found: %d", (int)total, (int)used, file_count);
            
            // If still high usage but no files found, format SPIFFS (orphaned blocks)
            if (used > (total / 2) && file_count == 0)
            {
                ESP_LOGW(TAG, "SPIFFS has orphaned blocks. Formatting...");
                esp_vfs_spiffs_unregister(NULL);
                esp_err_t fmt_err = esp_spiffs_format(NULL);
                if (fmt_err == ESP_OK)
                {
                    ESP_LOGI(TAG, "SPIFFS formatted successfully");
                    // Re-mount
                    esp_vfs_spiffs_conf_t conf = {
                        .base_path = "/spiffs",
                        .partition_label = NULL,
                        .max_files = 5,
                        .format_if_mount_failed = true
                    };
                    esp_vfs_spiffs_register(&conf);
                    esp_spiffs_info(NULL, &total, &used);
                    ESP_LOGI(TAG, "SPIFFS after format: total: %d bytes, used: %d bytes", (int)total, (int)used);
                }
                else
                {
                    ESP_LOGE(TAG, "SPIFFS format failed: %s", esp_err_to_name(fmt_err));
                }
            }
        }
    }
}

/* ---------------- Download single file to SPIFFS (generic) ---------------- */
static bool download_file_to_spiffs(const char *url, const char *dest_path)
{
    esp_http_client_config_t config = {
        .url = url,
    #if FIRMWARE_TLS == 1
        .crt_bundle_attach = esp_crt_bundle_attach,
        .skip_cert_common_name_check = false,
    #endif
        .timeout_ms = 30000
    };

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
    fflush(f);
    fsync(fileno(f));
    fclose(f);
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
static bool hexstr_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0)
        return false;
    if (out_len < hlen / 2)
        return false;
    for (size_t i = 0; i < hlen / 2; ++i)
    {
        unsigned int v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1)
            return false;
        out[i] = (uint8_t)v;
    }
    return true;
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
    uint8_t signature[SIG_LEN];
    if (!hexstr_to_bytes(signature_hex, signature, SIG_LEN))
    {
        ESP_LOGE(TAG, "[OTA] Signature hex->bytes failed");
        esp_ota_end(ota_handle);
        return false;
    }

    if (crypto_ed25519_check(signature, PUBLIC_KEY, calc_hash, 32) != 0)
    {
        ESP_LOGE(TAG, "[OTA] Signature verification FAILED");
        esp_ota_end(ota_handle);
        return false;
    }
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

    // Reset WDT before reboot
    esp_task_wdt_reset();

    // Cleanup files
    ESP_LOGI(TAG, "[OTA] Cleaning up files...");
    if (remove(bin_path) == 0)
    {
        ESP_LOGI(TAG, "[OTA] Firmware file deleted");
    }
    else
    {
        ESP_LOGW(TAG, "[OTA] Failed to delete firmware file");
    }
    esp_task_wdt_reset();
    vTaskDelay(pdMS_TO_TICKS(100));

    ESP_LOGI(TAG, "[OTA] Deleting manifest file...");
    if (remove(MANIFEST_PATH) == 0)
    {
        ESP_LOGI(TAG, "[OTA] Manifest file deleted");
    }
    else
    {
        ESP_LOGW(TAG, "[OTA] Failed to delete manifest file");
    }

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

    char expected_hash_hex[65];
    char signature_hex[129];
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

    // 4. Stream firmware directly to OTA partition (NO SPIFFS)
    ESP_LOGI(TAG, "[OTA] Streaming firmware to OTA partition...");
    ota_monitor_start_stage();
    
    esp_http_client_config_t http_config = {
        .url = FIRMWARE_URL,
    #if FIRMWARE_TLS == 1
        .crt_bundle_attach = esp_crt_bundle_attach,
        .skip_cert_common_name_check = false,
    #endif
        .timeout_ms = 60000,
        .buffer_size = 16384,
        .buffer_size_tx = 4096
    };

    esp_https_ota_config_t ota_config = {
        .http_config = &http_config,
    };

    esp_https_ota_handle_t https_ota_handle = NULL;
    esp_err_t err = esp_https_ota_begin(&ota_config, &https_ota_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "[OTA] esp_https_ota_begin failed: %s", esp_err_to_name(err));
        remove(MANIFEST_PATH);
        return false;
    }

    int image_size = esp_https_ota_get_image_size(https_ota_handle);
    ESP_LOGI(TAG, "[OTA] Firmware size: %d bytes", image_size);

    // Stream firmware with progress
    int last_percent = -1;
    int total_read = 0;

    while (1)
    {
        err = esp_https_ota_perform(https_ota_handle);
        if (err != ESP_ERR_HTTPS_OTA_IN_PROGRESS)
            break;

        total_read = esp_https_ota_get_image_len_read(https_ota_handle);
        int percent = (total_read * 100) / image_size;
        
        if (percent != last_percent && percent % 10 == 0)
        {
            ESP_LOGI(TAG, "[OTA] Progress: %d%% (%d/%d)", percent, total_read, image_size);
            last_percent = percent;
        }
        
        esp_task_wdt_reset();
    }

    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "[OTA] Firmware streaming failed: %s", esp_err_to_name(err));
        esp_https_ota_abort(https_ota_handle);
        remove(MANIFEST_PATH);
        return false;
    }

    ESP_LOGI(TAG, "[OTA] Download complete: %d bytes", total_read);
    ota_monitor_end_stage("stream_firmware");

    // 5. Verify hash by reading from partition
    ota_monitor_start_stage();
    ESP_LOGI(TAG, "[OTA] Verifying firmware hash...");
    
    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (!update_partition)
    {
        ESP_LOGE(TAG, "[OTA] Failed to get update partition");
        esp_https_ota_abort(https_ota_handle);
        remove(MANIFEST_PATH);
        return false;
    }

    // Calculate hash from partition
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);

    const int buf_size = 8192;
    uint8_t *buffer = malloc(buf_size);
    if (!buffer)
    {
        ESP_LOGE(TAG, "[OTA] malloc failed for verification");
        esp_https_ota_abort(https_ota_handle);
        remove(MANIFEST_PATH);
        return false;
    }

    size_t remaining = total_read;
    size_t offset = 0;

    while (remaining > 0)
    {
        size_t to_read = (remaining > buf_size) ? buf_size : remaining;
        err = esp_partition_read(update_partition, offset, buffer, to_read);
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "[OTA] Partition read failed: %s", esp_err_to_name(err));
            free(buffer);
            esp_https_ota_abort(https_ota_handle);
            remove(MANIFEST_PATH);
            return false;
        }

        mbedtls_sha256_update(&sha_ctx, buffer, to_read);
        offset += to_read;
        remaining -= to_read;
        esp_task_wdt_reset();
    }

    free(buffer);

    uint8_t calc_hash[32];
    mbedtls_sha256_finish(&sha_ctx, calc_hash);
    mbedtls_sha256_free(&sha_ctx);

    char calc_hash_hex[65];
    for (int i = 0; i < 32; ++i)
        sprintf(calc_hash_hex + i * 2, "%02x", calc_hash[i]);
    calc_hash_hex[64] = '\0';

    ESP_LOGI(TAG, "[OTA] Computed hash: %s", calc_hash_hex);
    ESP_LOGI(TAG, "[OTA] Expected hash: %s", expected_hash_hex);

    if (strcmp(calc_hash_hex, expected_hash_hex) != 0)
    {
        ESP_LOGE(TAG, "[OTA] Hash mismatch!");
        esp_https_ota_abort(https_ota_handle);
        remove(MANIFEST_PATH);
        return false;
    }
    ota_monitor_end_stage("verify_hash");

    // 6. Verify signature
    ota_monitor_start_stage();
    uint8_t signature[SIG_LEN];
    if (!hexstr_to_bytes(signature_hex, signature, SIG_LEN))
    {
        ESP_LOGE(TAG, "[OTA] Signature hex->bytes failed");
        esp_https_ota_abort(https_ota_handle);
        remove(MANIFEST_PATH);
        return false;
    }

    if (crypto_ed25519_check(signature, PUBLIC_KEY, calc_hash, 32) != 0)
    {
        ESP_LOGE(TAG, "[OTA] Signature verification FAILED");
        esp_https_ota_abort(https_ota_handle);
        remove(MANIFEST_PATH);
        return false;
    }
    ota_monitor_end_stage("verify_signature");

    ESP_LOGI(TAG, "[OTA] Hash and signature verified OK");

    // 7. Finalize OTA
    ota_monitor_start_stage();
    err = esp_https_ota_finish(https_ota_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "[OTA] esp_https_ota_finish failed: %s", esp_err_to_name(err));
        remove(MANIFEST_PATH);
        return false;
    }
    ota_monitor_end_stage("ota_finalize");

    ESP_LOGI(TAG, "[OTA] OTA committed. Rebooting...");
    
    // Cleanup
    esp_task_wdt_reset();
    remove(MANIFEST_PATH);
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();

    return true;
}

/* ---------------- ota_task (simplified) ---------------- */
void ota_task(void *pvParameter)
{
    esp_task_wdt_config_t wdt_config = {
        .timeout_ms = 30000, // 30 seconds
        .idle_core_mask = 0,
        .trigger_panic = true};
    esp_task_wdt_reconfigure(&wdt_config);
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