import utime
import ql_fs
import modem
file_name = "/usr/config/setup_credentials.json"

def setup_device_credentials():
    if ql_fs.path_exists(file_name):
        try:
            data = ql_fs.read_json(file_name)
            return data
        except Exception as e:
            print("Error in reading the json file: {}".format(e))
    else:
        current_time = utime.localtime()
        # Extract the year, month, and day
        year = current_time[0]
        month = current_time[1]
        day = current_time[2]
        today = ("{}{}{}".format(day,month, year))
        formatted_date = today
        imei_number = modem.getDevImei()
        last_six_digits = imei_number[-6:]  # Slicing to get the last 6 characters
        username = "NLDT" + "_" + formatted_date + "_" + last_six_digits
        password = "newleaf" + "_" + last_six_digits
        initial_data = {
            "device_id": username,
            "password": password,
            "author": "This device and firmware were developed by Sumeri Lal on the behalf of New Leaf Dynamic Technology Pvt Ltd.",
            "copyright": "All rights reserved ©2024."
        }
        ql_fs.touch(file_name, initial_data)
        print("Setup credentials has been generated successfully.")

