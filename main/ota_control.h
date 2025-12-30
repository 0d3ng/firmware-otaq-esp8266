#ifndef OTA_CONTROL_H
#define OTA_CONTROL_H

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

void ota_control_init(void);
void ota_pause_sensors(void);
void ota_resume_sensors(void);
EventGroupHandle_t ota_control_get_event_group(void);

#endif // OTA_CONTROL_H
