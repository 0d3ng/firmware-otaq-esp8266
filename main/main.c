#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "wifi_connect.h"
#include "mqtt_app.h"
#include "ota_updater.h"
#include "sensor_task.h"
#include "ntp.h"

static const char *TAG = "main_app";

void app_main(void)
{
    printf("Running firmware version: %s\n", FIRMWARE_VERSION);
    printf("Using firmware algorithm: %s\n", FIRMWARE_ALGORITHM);
    ESP_LOGI(TAG, "Starting system...");
    // NVS init
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    ESP_LOGI(TAG, "NVS initialized.");

    // WiFi
    ESP_LOGI(TAG, "Connecting to WiFi...");
    wifi_init_sta();

    // NTP
    ESP_LOGI(TAG, "Initializing NTP...");
    initialize_sntp();

    // MQTT
    ESP_LOGI(TAG, "Starting MQTT...");
    mqtt_app_start();

    // Sensor Task
    // ESP_LOGI(TAG, "Starting Sensor Task...");
    // xTaskCreate(sensor_task, "sensor_task", 4096, NULL, 5, NULL);

    // OTA Task
    ESP_LOGI(TAG, "Starting OTA Task...");
    xTaskCreate(ota_task, "ota_task", 16384, NULL, 5, NULL);

    ESP_LOGI(TAG, "System initialized. Waiting for MQTT OTA trigger...");

}