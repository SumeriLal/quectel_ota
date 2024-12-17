import app_fota
from misc import Power
def run_app_ota():
    fota = app_fota.new()
    download_list = [{'url': 'https://raw.githubusercontent.com/SumeriLal/quectel_ota/main/main.py', 'file_name': '/usr/main.py'}, {'url': 'https://raw.githubusercontent.com/SumeriLal/quectel_ota/main/modbus_RTU.py', 'file_name': '/usr/modbus_RTU.py'},
                     {'url': 'https://raw.githubusercontent.com/SumeriLal/quectel_ota/main/app_ota.py', 'file_name': '/usr/app_ota.py'}, {'url': 'https://raw.githubusercontent.com/SumeriLal/quectel_ota/main/ota_handler.py', 'file_name': '/usr/ota_handler.py'},
                     {'url': 'https://raw.githubusercontent.com/SumeriLal/quectel_ota/main/device_credentials.py', 'file_name': '/usr/device_credentials.py'}]
    print("Downloading application file.")
    fota.bulk_download(download_list)
    fota.set_update_flag()
    print("Updating and restarting in just few seconds...")
    Power.powerRestart()
