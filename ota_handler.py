# import app_fota
# from misc import Power
#
# fota = app_fota.new()
# download_list = [{'url': 'https://raw.githubusercontent.com/SumeriLal/quectel_ota/main/main.py', 'file_name': '/usr/main.py'}, {'url': 'https://raw.githubusercontent.com/SumeriLal/quectel_ota/main/modbus_RTU.py', 'file_name': '/usr/modbus_RTU.py'}]
# fota.bulk_download(download_list)
# fota.set_update_flag()
# Power.powerRestart()


# OTA Upgrade. The module will restart automatically after the upgrade package is downloaded.

import fota
import utime
import log

# Sets the log output level
log.basicConfig(level=log.INFO)
fota_log = log.getLogger("Fota")

def result(args):
    print('download status:',args[0],'download process:',args[1])

def run():
    fota_obj = fota()  # Creates a FOTA object
    fota_log.info("httpDownload...")
    # Methods of DFOTA upgrades
    res = fota_obj.httpDownload(url1="https://raw.githubusercontent.com/SumeriLal/quectel_ota/refs/heads/main/output_EC200U_ota.pack",callback=result)
    # Methods of mini FOTA
    #res = fota_obj.httpDownload(url1="http://www.example.com/fota1.bin",url2="http://www.example.com/fota2.bin")
    if res != 0:
        fota_log.error("httpDownload error")
        return
    fota_log.info("wait httpDownload update...")
    utime.sleep(2)
