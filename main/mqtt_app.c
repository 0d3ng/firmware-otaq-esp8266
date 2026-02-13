#include "mqtt_app.h"
#include "esp_log.h"
#include "mqtt_client.h"
#include "ota_updater.h"
#include "esp_crt_bundle.h"
#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"

static const char *TAG = "mqtt_app";

static esp_mqtt_client_handle_t client;
static TimerHandle_t reconnect_timer = NULL;
static uint32_t reconnect_delay_ms = 2000;  // mulai dari 2 detik

#define RECONNECT_DELAY_MIN_MS   2000    // 2 detik
#define RECONNECT_DELAY_MAX_MS   60000   // max 60 detik

static void mqtt_reconnect_callback(TimerHandle_t xTimer)
{
    ESP_LOGI(TAG, "Attempting MQTT reconnect...");
    esp_mqtt_client_reconnect(client);
}

static void schedule_reconnect(void)
{
    if (reconnect_timer == NULL) {
        reconnect_timer = xTimerCreate("mqtt_reconn", pdMS_TO_TICKS(reconnect_delay_ms),
                                        pdFALSE, NULL, mqtt_reconnect_callback);
    } else {
        xTimerChangePeriod(reconnect_timer, pdMS_TO_TICKS(reconnect_delay_ms), 0);
    }

    ESP_LOGI(TAG, "MQTT reconnect scheduled in %lu ms", (unsigned long)reconnect_delay_ms);
    xTimerStart(reconnect_timer, 0);

    // exponential backoff: 2s -> 4s -> 8s -> 16s -> 32s -> 60s (max)
    reconnect_delay_ms *= 2;
    if (reconnect_delay_ms > RECONNECT_DELAY_MAX_MS) {
        reconnect_delay_ms = RECONNECT_DELAY_MAX_MS;
    }
}

static esp_err_t mqtt_event_handler_cb(esp_mqtt_event_handle_t event)
{
    switch (event->event_id)
    {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT connected");
        // reset backoff delay setelah berhasil connect
        reconnect_delay_ms = RECONNECT_DELAY_MIN_MS;
        if (reconnect_timer != NULL) {
            xTimerStop(reconnect_timer, 0);
        }
        esp_mqtt_client_subscribe(client, "device/002/ota/update", 1);
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "MQTT disconnected, will retry with backoff");
        schedule_reconnect();
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGI(TAG, "MQTT topic: %.*s, data: %.*s",
                 event->topic_len, event->topic,
                 event->data_len, event->data);
        if (strncmp(event->topic, "device/002/ota/update", event->topic_len) == 0 &&
            strncmp(event->data, "start", event->data_len) == 0)
        {
            ota_trigger();
        }
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGE(TAG, "MQTT error event");
        break;
    default:
        break;
    }
    return ESP_OK;
}

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    mqtt_event_handler_cb((esp_mqtt_event_handle_t)event_data);
}

void mqtt_app_start(void)
{
    esp_mqtt_client_config_t mqtt_cfg = {
        #if FIRMWARE_TLS == 1
        .broker.address.uri = "mqtts://ota.sinaungoding.com:8883", // ganti broker kamu
        .broker.verification.crt_bundle_attach = esp_crt_bundle_attach,
        .credentials.username = "uwais",
        .credentials.authentication.password = "uw415_4Lqarn1",
        #else
        .broker.address.uri = "mqtt://broker.sinaungoding.com:1884", // ganti broker kamu
        .credentials.username = "noureen",
        .credentials.authentication.password = "1234",
        #endif
    };

    client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, client);
    esp_mqtt_client_start(client);
    ESP_LOGI(TAG, "MQTT client started");
}

void mqtt_publish(const char *topic, const char *payload)
{
    if (client)
    {
        esp_mqtt_client_publish(client, topic, payload, 0, 1, 0);
    }
}