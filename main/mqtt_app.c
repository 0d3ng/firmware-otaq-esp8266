#include "mqtt_app.h"
#include "esp_log.h"
#include "mqtt_client.h"
#include "ota_updater.h"
#include "certs/fullchain.h"

static const char *TAG = "mqtt_app";

static esp_mqtt_client_handle_t client;

static esp_err_t mqtt_event_handler_cb(esp_mqtt_event_handle_t event)
{
    switch (event->event_id)
    {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT connected");
        esp_mqtt_client_subscribe(client, "device/002/ota/update", 1);
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "MQTT disconnected");
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
        .broker.address.uri = "mqtts://ota.sinaungoding.com:8883", // ganti broker kamu
        // .broker.address.uri = "mqtt://broker.sinaungoding.com", // ganti broker kamu
        // .broker.address.uri = "mqtt://140.238.199.159", // ganti broker kamu
        .credentials.username = "uwais",
        .credentials.authentication.password = "uw415_4Lqarn1",
        .broker.verification.certificate = fullchain_pem,
        .broker.verification.certificate_len = fullchain_pem_len,
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