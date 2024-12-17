import app_fota
from misc import Power
import request

class PrivateRepoFOTA:
    def __init__(self, token):
        self.token = token

    def download_file(self, url, file_name):
        headers = {
            "Authorization": self.token,
            "Accept": "application/vnd.github.v3.raw"
        }
        response = request.get(url, headers=headers)
        if response.status_code == 200:
            with open(file_name, 'wb') as file:
                file.write(response.content)
            print("Downloaded {} successfully." .format(file_name))
        else:
            print("Failed to download ")
            response.raise_for_status()

    def bulk_download(self, download_list):
        for item in download_list:
            self.download_file(item['url'], item['file_name'])


# Replace with your GitHub personal access token
GITHUB_TOKEN = "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"

# Instantiate the custom FOTA class
fota = PrivateRepoFOTA(GITHUB_TOKEN)

# Define the list of files to download (raw URLs from the private repo)
download_list = [
    {
        'url': 'https://raw.githubusercontent.com/SumeriLal/quectel_ota/main/main.py',
        'file_name': '/usr/main.py'
    },
    {
        'url': 'https://raw.githubusercontent.com/SumeriLal/quectel_ota/main/modbus_RTU.py',
        'file_name': '/usr/modbus_RTU.py'
    }
]

# Perform the download
fota.bulk_download(download_list)

# Set update flag and restart
app_fota.new().set_update_flag()
Power.powerRestart()
