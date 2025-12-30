#include "ina219.h"
#include "esp_log.h"

static const char *TAG = "INA219";

static esp_err_t ina219_write(ina219_t *ina, uint8_t reg, uint16_t value)
{
    uint8_t data[3] = {reg, value >> 8, value & 0xFF};
    return i2c_master_transmit(ina->dev_handle, data, sizeof(data), -1);
}

static esp_err_t ina219_read(ina219_t *ina, uint8_t reg, uint16_t *value)
{
    uint8_t data[2];

    esp_err_t ret = i2c_master_transmit_receive(ina->dev_handle, &reg, 1, data, 2, -1);
    if (ret != ESP_OK)
    {
        ESP_LOGE(TAG, "I2C read failed: %d", ret);
        return ret;
    }

    *value = ((uint16_t)data[0] << 8) | data[1];
    return ESP_OK;
}

esp_err_t ina219_init(ina219_t *ina, i2c_master_bus_handle_t bus, uint8_t addr, float shunt_resistor)
{
    ina->shunt_resistor = shunt_resistor;
    ina->current_lsb = 0.00005f; // 100uA per bit (default)
    ina->power_lsb = ina->current_lsb * 20;

    // 1. Register device on bus
    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = addr,
        .scl_speed_hz = 100000,
    };

    ESP_ERROR_CHECK(i2c_master_bus_add_device(bus, &dev_cfg, &ina->dev_handle));

    ESP_LOGI(TAG, "Device added: addr=0x%02X", addr);

    // 2. Config register (default)
    uint16_t config = 0x399F;
    ESP_ERROR_CHECK(ina219_write(ina, INA219_REG_CONFIG, config));

    // 3. Calibration (important for accurate readings)
    uint16_t calibration = (uint16_t)(0.04096 / (ina->current_lsb * shunt_resistor));
    ESP_ERROR_CHECK(ina219_write(ina, INA219_REG_CALIB, calibration));

    ESP_LOGI(TAG, "INA219 initialized (shunt=%.4f ohm)", shunt_resistor);
    return ESP_OK;
}

esp_err_t ina219_read_voltage(ina219_t *ina, float *voltage_v)
{
    uint16_t raw;
    ESP_ERROR_CHECK(ina219_read(ina, INA219_REG_BUS_V, &raw));

    raw >>= 3;                 // lower 3 bits not used
    *voltage_v = raw * 0.004f; // 4 mV per bit

    return ESP_OK;
}

esp_err_t ina219_read_current(ina219_t *ina, float *current_a)
{
    uint16_t raw;
    ESP_ERROR_CHECK(ina219_read(ina, INA219_REG_CURRENT, &raw));

    *current_a = (int16_t)raw * ina->current_lsb;
    return ESP_OK;
}

esp_err_t ina219_read_power(ina219_t *ina, float *power_w)
{
    uint16_t raw;
    ESP_ERROR_CHECK(ina219_read(ina, INA219_REG_POWER, &raw));

    *power_w = raw * ina->power_lsb;
    return ESP_OK;
}