#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "mqtt_app.h"
#include <stdlib.h>
#include <time.h>
#include "ota_control.h"
#include "esp_timer.h"
#include "ina219.h"

#define ADC_CHANNEL ADC_CHANNEL_6 // GPIO34

#define SDA_GPIO 1
#define SCL_GPIO 2

static const char *TAG = "sensor_task";

static float energy_joule = 0.0f;
static uint64_t last_sample_time_ms = 0;
static uint64_t last_publish_time_ms = 0;

void sensor_task(void *pvParameter)
{
    // adc_oneshot_unit_handle_t adc_handle;
    // adc_cali_handle_t cali_handle;

    // battery_adc_init(&adc_handle, &cali_handle, ADC_CHANNEL);

    // EventGroupHandle_t eg = ota_control_get_event_group();
    // const EventBits_t PAUSE_BIT = (1 << 0);

    i2c_master_bus_handle_t bus;

    i2c_master_bus_config_t bus_cfg = {
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .i2c_port = I2C_NUM_0,
        .scl_io_num = SCL_GPIO,
        .sda_io_num = SDA_GPIO,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };

    ESP_ERROR_CHECK(i2c_new_master_bus(&bus_cfg, &bus));

    ina219_t ina;
    ina219_init(&ina, bus, INA219_I2C_ADDR, 0.1f); // shunt resistor 0.1Ω (default module)

    float current, volt, power;

    // while (1)
    // {
    //     // If OTA requested pause, wait until cleared
    //     if (eg)
    //     {
    //         EventBits_t bits = xEventGroupGetBits(eg);
    //         if (bits & PAUSE_BIT)
    //         {
    //             // paused: block until PAUSE_BIT is cleared
    //             ESP_LOGI(TAG, "Sensor task paused for OTA");
    //             while (xEventGroupGetBits(eg) & PAUSE_BIT)
    //             {
    //                 vTaskDelay(pdMS_TO_TICKS(100)); // Check every 100ms
    //             }
    //             ESP_LOGI(TAG, "Sensor task resumed after OTA");
    //         }
    //     }

    //     // time log
    //     time_t now;
    //     struct tm timeinfo;
    //     time(&now);
    //     localtime_r(&now, &timeinfo);
    //     // create timestamp ISO 8601
    //     char timestamp[64];
    //     snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02dT%02d:%02d:%02d", timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday, timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);

    //     TickType_t T0 = xTaskGetTickCount();
    //     // Second driver call
    //     int r = DHTget(&temperature, &humidity);
    //     TickType_t T1 = xTaskGetTickCount();
    //     float temperature_c = 0.0;
    //     float humidity_rh = 0.0;
    //     if (r < 0)
    //     {
    //         ESP_LOGE(TAG, "DHT22 read error: %d", r);
    //     }
    //     else
    //     {
    //         temperature_c = temperature / 10.0;
    //         humidity_rh = humidity / 10.0;
    //         // ESP_LOGI(TAG, "DHT22 read success: Temp=%.2f°C, Humi=%.2f%% (Time taken: %d ticks)", temperature_c, humidity_rh, (T1 - T0) * portTICK_PERIOD_MS);
    //     }

    //     // read battery voltage
    //     float voltage = battery_read_voltage(adc_handle, cali_handle, ADC_CHANNEL, 50);
    //     // ESP_LOGI(TAG, "Battery voltage: %.3f V", voltage);

    //     ina219_read_voltage(&ina, &volt);
    //     ina219_read_current(&ina, &current);
    //     ina219_read_power(&ina, &power);
    //     ESP_LOGI("POWER", "V=%.3f V  I=%.3f A  P=%.3f W", volt, current, power);

    //     // create JSON payload
    //     char payload[256];
    //     snprintf(payload, sizeof(payload), "{\"temperature\":%.2f,\"humidity\":%.2f,\"voltage\":%.3f,\"timestamp\":\"%s,\"volt\":%.3f,\"current:\":%.3f,\"power\":%.3f\"}", temperature_c, humidity_rh, voltage, timestamp, volt, current, power);
    //     // ESP_LOGI(TAG, "Payload: %s", payload);
    //     // publish via MQTT
    //     mqtt_publish("device/002/sensor", payload);

    //     ESP_LOGI(TAG, "[%s] Published Temp: %.2f°C | Humi: %.2f%% | Volt: %.3fV", timestamp, temperature_c, humidity_rh, voltage);

    //     vTaskDelay(pdMS_TO_TICKS(10000));
    // }

    while (1)
    {
        // read current, volt, power every 100ms
        ina219_read_voltage(&ina, &volt);
        ina219_read_current(&ina, &current);
        ina219_read_power(&ina, &power);

        // calculate energy on joule
        uint64_t now_ms = esp_timer_get_time() / 1000;
        float delta_t = (last_sample_time_ms > 0) ? (now_ms - last_sample_time_ms) / 1000.0f : 0.0f;
        last_sample_time_ms = now_ms;
        if (delta_t > 0.0f)
        {
            energy_joule += power * delta_t;
        }
        // ESP_LOGI("POWER", "V=%.3f V  I=%.3f A  P=%.3f W  E=%.3f J", volt, current, power, energy_joule);
        if (now_ms - last_publish_time_ms >= 2000)
        {
            time_t now;
            struct tm timeinfo;
            time(&now);
            localtime_r(&now, &timeinfo);
            // create timestamp ISO 8601
            char timestamp[64];
            snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02dT%02d:%02d:%02d", timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday, timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
            char payload[256];
            snprintf(payload, sizeof(payload), "{\"volt\":%.3f,\"current\":%.3f,\"power\":%.3f,\"energy_joule\":%.3f,\"algorithm\":\"%s\",\"timestamp\":\"%s\"}", volt, current, power, energy_joule, FIRMWARE_ALGORITHM, timestamp);
            mqtt_publish("device/002/power", payload);
            // ESP_LOGI(TAG, "Payload: %s", payload);
            last_publish_time_ms = now_ms;
            energy_joule = 0.0f; // reset after publish
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}