#pragma once

#include <stdbool.h>

void ota_trigger();
bool ota_triggered(void);
void ota_task(void *pvParameter);