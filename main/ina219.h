#pragma once

#include "driver/i2c_master.h"
#include "esp_err.h"

#define INA219_I2C_ADDR 0x40

#define INA219_REG_CONFIG 0x00
#define INA219_REG_SHUNT_V 0x01
#define INA219_REG_BUS_V 0x02
#define INA219_REG_POWER 0x03
#define INA219_REG_CURRENT 0x04
#define INA219_REG_CALIB 0x05

typedef struct
{
    i2c_master_dev_handle_t dev_handle;
    float current_lsb;    // A/bit
    float power_lsb;      // W/bit
    float shunt_resistor; // ohm
} ina219_t;

esp_err_t ina219_init(ina219_t *ina, i2c_master_bus_handle_t bus, uint8_t addr, float shunt_resistor);
esp_err_t ina219_read_voltage(ina219_t *ina, float *voltage_v);
esp_err_t ina219_read_current(ina219_t *ina, float *current_a);
esp_err_t ina219_read_power(ina219_t *ina, float *power_w);