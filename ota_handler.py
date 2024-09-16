import app_fota
from misc import Power

fota = app_fota.new()
download_list = [{'url': 'https://drive.usercontent.google.com/download?id=11u7w4DiPXpUwg5-zl-gamYY2gW_tNY1M&export=download&authuser=0', 'file_name': '/usr/main.py'}, {'url': 'https://drive.usercontent.google.com/download?id=1_fuJVsIkOObVuKwo6G-K6PIs8HzCFVRG&export=download&authuser=0', 'file_name': '/usr/modbus_RTU.py'}]
fota.bulk_download(download_list)
fota.set_update_flag()
Power.powerRestart()
