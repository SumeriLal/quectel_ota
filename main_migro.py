from umqtt import MQTTClient
import utime
import log
import checkNet
from machine import WDT
from usr.modbus_RTU import get_modbus_data

PROJECT_NAME = "GC2_MQTT"
PROJECT_VERSION = "v1.0"

# Define your IoT Cloud device credentials
device_id = "umqtt_client"
server = "44.192.63.111"
port = 1883
# device_id = "umqtt_client"
# server = "1de9a47071694905ab0e47e401e2c236.s1.eu.hivemq.cloud"
# port = 8883
# user = "admindev"
# password = "Admindev1"


# Configure topic to store data in Data Buckets
TOPIC_PUB = "/greenchill/365/data/GC4001/"

checknet = checkNet.CheckNetwork(PROJECT_NAME, PROJECT_VERSION)

# Set the log output level.
log.basicConfig(level=log.INFO)
mqtt_log = log.getLogger("MQTT")
device_log = log.getLogger("Device GC2")

wdt = WDT(30)
DebugFlag = True
state = 0


def sub_cb(topic, msg):
    global state
    mqtt_log.info("Subscribe Recv: Topic={},Msg={}".format(topic.decode(), msg.decode()))
    state = 1


if __name__ == '__main__':
    checknet.poweron_print_once()
    stagecode, subcode = checknet.wait_network_connected(30)
    if stagecode == 3 and subcode == 1:
        mqtt_log.info('【Look Out】 Network Ready, connection successful!')
        # Create an MQTT example.
        # c = MQTTClient(client_id=device_id, server=server, port=port, user=user, password=password, ssl=True)
        c = MQTTClient(client_id=device_id, server=server, port=port)
        # Set the callback function of receiving messages.
        c.set_callback(sub_cb)
        # Connect to the MQTT server.
        c.connect()
        wdt.feed()
        try:
            while True:
                for i in range(0, 50):
                    try:
                        a = str(i)
                        data = get_modbus_data()
                        # data = {
                        #     "current": "1",
                        #     "batteryPercentage": "80",
                        #     "dimmingPercentage": "50"
                        # }
                        json_string = ujson.dumps(data)
                        c.subscribe(b"/public/light_status/ state")
                        # Publish a message periodically.
                        c.publish(TOPIC_PUB, json_string, retain=False, qos=1)
                        # mqtt_log.info('Published Message: {}'.format(json_string))
                        mqtt_log.info("Publish topic: /greenchill/365/data/GC4001/")
                        wdt.feed()
                        # Delay between publishing messages (adjust as needed).
                        utime.sleep(2)
                    except Exception as e:
                        mqtt_log.error("An error occurred from MQTT: {}".format(e))
        except Exception as e:
            mqtt_log.error("An error occurred: {}".format(e))
            wdt.feed()
        finally:
            # Ensure the client disconnects on exit.
            c.disconnect()
            mqtt_log.info("Disconnected from broker.hivemq.com")

    elif stagecode == 1 and subcode == 0:
        device_log.warning('【Look Out】 No Sim Card Inserted\r\n')
    elif stagecode == 1 and subcode == 2:
        device_log.warning('【Look Out】 The Sim Card is Locked\r\n')
    elif stagecode == 2 and subcode == 0:
        device_log.warning('【Look Out】 Timeout: Not Netted\r\n')
    else:
        device_log.warning('【Look Out】 Network Not Available\r\n')
