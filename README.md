# firmware-otaq-s3

This firmware is developed for the ESP32-S3 using ESP-IDF. The project includes several main features such as WiFi connectivity, MQTT, INA219 sensor reading, NTP time synchronization, and Over-The-Air (OTA) updates.

## Main Features
- **WiFi Connection**: Connects the device to a WiFi network.
- **MQTT**: Sends and receives data using the MQTT protocol.
- **INA219 Sensor**: Reads current and voltage using the INA219 sensor.
- **NTP**: Synchronizes time using the Network Time Protocol.
- **OTA Update**: Supports remote firmware updates.

## Directory Structure
- `main/` : Contains main source code (C) and headers.
- `components/` : Additional components such as `cjson`, `dht`, etc.
- `build/` : Compilation results and output files.
- `certs/` : Certificates used for secure connections.
- `CMakeLists.txt` : CMake build configuration.
- `sdkconfig` : ESP-IDF project configuration.
- `partitions.csv` : Flash partition table.

## Requirements
- ESP32-S3
- ESP-IDF (recommended version 5.5.1)
- Python 3.x
- ESP32 Toolchain

## Build & Flash Instructions
1. **Set ESP-IDF environment**
   ```sh
   $ export IDF_PATH="/path/to/esp-idf"
   $ . $IDF_PATH/export.sh
   ```
2. **Build firmware**
   ```sh
   $ idf.py build
   ```
3. **Flash to device**
   ```sh
   $ idf.py -p [PORT] flash
   ```
4. **Monitor serial output**
   ```sh
   $ idf.py -p [PORT] monitor
   ```

## Configuration
- Edit the `sdkconfig` file to set build parameters.
- Edit the `partitions.csv` file if you want to change the flash partitioning.

## License
This project uses the MIT license. Feel free to modify and use as needed.

---

**Notes:**
- Ensure all submodules and dependencies are installed.
- For OTA updates, make sure the partition table and certificates are correct.
