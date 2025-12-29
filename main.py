from umqtt import MQTTClient
import utime
import log
import checkNet
import ujson
import ql_fs
import _thread
import modem
import sim
from usr.app_ota import run_app_ota
from usr.device_credentials import setup_device_credentials
from usr.modbus_setting_update_oncycle_count import get_modbus_data
from machine import WDT
from misc import Power

file_name = "/usr/config/current_cycle_count.json"

PROJECT_NAME = "New Leaf IoT 2.0"
PROJECT_VERSION = "1.0.0"

checknet = checkNet.CheckNetwork(PROJECT_NAME, PROJECT_VERSION)
# Set the log output level.
log.basicConfig(level=log.INFO)
mqtt_log = log.getLogger("MQTT")
device_log = log.getLogger("GC400")

state = 0
data_dev = setup_device_credentials()
device_id = data_dev['device_id']
server = "iot.greenchill365.com"
port = 1883
user = device_id
password = data_dev['password']

print("Client ID: {}, Username: {}, Password: {}" .format(device_id, device_id, password))

# Configure topics
TOPIC_PUB = "v1/devices/me/telemetry"
TOPIC_SUB = "v1/devices/me/rpc/request/+"
TOPIC_SUB_ATTRIB = "v1/devices/me/attributes"

# Initialize watchdog timer and GPIO state
wdt = WDT(120)
gpio_state = {1: False, 2: False, 3: False}

def get_gpio_status():
    return ujson.dumps(gpio_state)

def set_gpio_status(pin, status):
    print('State set by server ---->', pin, status)
    if pin==1 and status == True:
        print("Updating the OTA Firmware")
    gpio_state[pin] = status
    if pin==2 and status == True:
        print("Updating the OTA Application")
        run_app_ota()
    gpio_state[pin] = status
    if pin==3 and status == True:
        print("Updating the Restarting the CPU in few seconds")
        Power.powerRestart()
    gpio_state[pin] = status

def on_connect(client):
    mqtt_log.info("Connected to MQTT broker")
    imei_number = modem.getDevImei()
    sim_no = sim.getPhoneNumber()
    count_data = ql_fs.read_json(file_name)
    start_log = {"started_at": "started", "machine_id": count_data['machine_id'], "sim_no": sim_no, 'imei_number': imei_number}
    log_data = ujson.dumps(start_log)
    client.subscribe(TOPIC_SUB)
    client.publish(TOPIC_SUB_ATTRIB, get_gpio_status(), 1)
    mqtt_log.info("Subscribed to topic: {}".format(TOPIC_SUB))
    client.publish(TOPIC_PUB, log_data)

def on_message(topic, msg):
    global state
    mqtt_log.info("Message received. Topic={}, Msg={}".format(topic.decode(), msg.decode()))
    state = 1
    try:
        # Decode the received message
        message = ujson.loads(msg.decode())
        if "method" in message:
            method = message["method"]
            # Handle "getGpioStatus" method
            if method == "getGpioStatus":
                response = get_gpio_status()  # Get GPIO status as JSON
                client.publish(topic.replace(b'request', b'response'), response)
                mqtt_log.info("Sent GPIO status response")

            # Handle "setGpioStatus" method
            elif method == "setGpioStatus":
                params = message.get("params", {})
                pin = params.get("pin")
                enabled = params.get("enabled")
                if pin is not None and enabled is not None:
                    set_gpio_status(pin, enabled)
                    response = get_gpio_status()
                    client.publish(topic.replace(b'request', b'response'), response)
                    mqtt_log.info("Updated GPIO state and sent response")
    except Exception as e:
        mqtt_log.error("Error processing received message: {}".format(e))

# Thread for continuously publishing data
def publish_data():
    try:
        while True:
            try:
                # Read Modbus data and publish it
                data = get_modbus_data()
                json_string = ujson.dumps(data)
                client.publish(TOPIC_PUB, json_string)
                mqtt_log.info("Published topic: {} with data: {}".format(TOPIC_PUB, json_string))

                # Delay between publishing messages
                utime.sleep(30)
                wdt.feed()  # Feed the watchdog timer
            except Exception as e:
                mqtt_log.error("Error in getting Modbus data: {}".format(e))
    except Exception as e:
        mqtt_log.error("Error in publishing data: {}".format(e))

# Thread for subscribing to messages and handling them
def subscribe_messages():
    try:
        while True:
            client.check_msg()  # Non-blocking call to check for messages
            wdt.feed()  # Feed the watchdog timer
            utime.sleep(0.1)  # Small delay to prevent 100% CPU usage
    except Exception as e:
        mqtt_log.error("Error in subscription loop: {}".format(e))


if __name__ == '__main__':
    # Wait for network connection
    checknet.poweron_print_once()
    stagecode, subcode = checknet.wait_network_connected(30)
    if stagecode == 3 and subcode == 1:
        print(data_dev["author"], data_dev["copyright"])
        mqtt_log.info('【Look Out】 Network Ready, connection successful!')
        # Create MQTT client instance
        client = MQTTClient(client_id=device_id, server=server, port=port, user=user, password=password)
        # client = MQTTClient(client_id=device_id, server=server, port=port)

        # Set the callback functions
        client.set_callback(on_message)
        try:
            client.connect(clean_session=False)
            on_connect(client)  # Call on_connect after connecting
        except Exception as e:
            mqtt_log.error("Failed to connect to MQTT broker: {}".format(e))

        wdt.feed()  # Feed the watchdog timer
        try:
            # Start the publish data thread
            _thread.start_new_thread(publish_data, ())
            wdt.feed()
            # Start the subscribe messages thread
            _thread.start_new_thread(subscribe_messages, ())
            wdt.feed()
            while True:
                utime.sleep(5)  # Keep the main thread alive
        except Exception as e:
            mqtt_log.error("An unexpected error occurred: {}".format(e))
        finally:
            # Disconnect on exit
            client.disconnect()
            mqtt_log.info("Disconnected from broker")

    elif stagecode == 1 and subcode == 0:
        device_log.warning('【Look Out】 No Sim Card Inserted\r\n')
    elif stagecode == 1 and subcode == 2:
        device_log.warning('【Look Out】 The Sim Card is Locked\r\n')
    elif stagecode == 2 and subcode == 0:
        device_log.warning('【Look Out】 Timeout: Not Netted\r\n')
    else:
        device_log.warning('【Look Out】 Network Not Available\r\n')
