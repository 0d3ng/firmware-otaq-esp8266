#include "ota_control.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

static EventGroupHandle_t ota_event_group = NULL;
#define OTA_SENSOR_PAUSE_BIT (1 << 0)

void ota_control_init(void)
{
    if (!ota_event_group)
        ota_event_group = xEventGroupCreate();
}

void ota_pause_sensors(void)
{
    if (!ota_event_group)
        ota_control_init();
    xEventGroupSetBits(ota_event_group, OTA_SENSOR_PAUSE_BIT);
}

void ota_resume_sensors(void)
{
    if (!ota_event_group)
        return;
    xEventGroupClearBits(ota_event_group, OTA_SENSOR_PAUSE_BIT);
}

EventGroupHandle_t ota_control_get_event_group(void)
{
    if (!ota_event_group)
        ota_control_init();
    return ota_event_group;
}
