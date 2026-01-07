idf_component_register(SRCS "ntp.c" "main.c" "ota_updater.c" "ota_control.c" "sensor_task.c" "wifi_connect.c" "mqtt_app.c" "ina219.c"
                       REQUIRES spi_flash nvs_flash monocypher mqtt esp_http_client esp_wifi esp_https_ota app_update lwip spiffs cjson esp_adc mbedtls
                       INCLUDE_DIRS "." "certs")

target_include_directories(${COMPONENT_TARGET} PRIVATE
    "$ENV{IDF_PATH}/components/spiffs/include"
    "$ENV{IDF_PATH}/components/lwip/include"
    "$ENV{IDF_PATH}/components/esp_driver_i2c/include"
)