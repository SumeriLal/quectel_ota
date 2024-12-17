import app_fota
from misc import Power

def run_app_ota():
    fota = app_fota.new()

    # List of files to download
    download_list = [
        {
            'url': 'https://raw.githubusercontent.com/SumeriLal/quectel_ota/main/main.py',
            'file_name': '/usr/main.py'
        },
        {
            'url': 'https://raw.githubusercontent.com/SumeriLal/quectel_ota/main/modbus_RTU.py',
            'file_name': '/usr/modbus_RTU.py'
        },
        {
            'url': 'https://raw.githubusercontent.com/SumeriLal/quectel_ota/main/app_ota.py',
            'file_name': '/usr/app_ota.py'
        },
        {
            'url': 'https://raw.githubusercontent.com/SumeriLal/quectel_ota/main/ota_handler.py',
            'file_name': '/usr/ota_handler.py'
        },
        {
            'url': 'https://raw.githubusercontent.com/SumeriLal/quectel_ota/main/device_credentials.py',
            'file_name': '/usr/device_credentials.py'
        }
    ]

    print("Starting the OTA process...")
    try:
        # Download the application files in bulk
        print("Downloading application files...")
        x = fota.bulk_download(download_list)
        print("----------------->", x)
        print("Download completed successfully. Sumeri Lal")

        # Set the update flag for FOTA
        print("Setting update flag...")
        fota.set_update_flag()

        # Restart the device to apply updates
        print("Restarting the device to apply updates...")
        Power.powerRestart()

    except Exception as e:
        # Handle any errors during the OTA process
        print("Error during OTA process:", e)
        print("OTA update failed. Please check logs and retry.")


run_app_ota()