from umqtt import MQTTClient
import utime
import log
import checkNet
import ujson
from usr.modbus_RTU import get_modbus_data

PROJECT_NAME = "GC2_MQTT"
PROJECT_VERSION = "1.0.0"

checknet = checkNet.CheckNetwork(PROJECT_NAME, PROJECT_VERSION)

# Set the log output level.
log.basicConfig(level=log.INFO)
mqtt_log = log.getLogger("MQTT")


state = 0

def sub_cb(topic, msg):
    global state
    mqtt_log.info("Subscribe Recv: Topic={},Msg={}".format(topic.decode(), msg.decode()))
    state = 1


if __name__ == '__main__':
    stagecode, subcode = checknet.wait_network_connected(30)
    if stagecode == 3 and subcode == 1:
        mqtt_log.info('Network connection successful!')

        # Create an MQTT example.
        c = MQTTClient("umqtt_client", "mqtt.eclipseprojects.io", 1883)
        # Set the callback function of receiving messages.
        c.set_callback(sub_cb)
        # Connect to the MQTT server.
        c.connect()
        try:
            while True:
                for i in range(0, 50):
                    try:
                        a = str(i)
                        data = get_modbus_data()
                        json_string = ujson.dumps(data)
                        c.subscribe(b"/public/light_status/ state")
                        # Publish a message periodically.
                        c.publish(b"/greenchill/365/data/GC4001/", json_string, retain=False, qos=1)
                        # mqtt_log.info('Published Message: {}'.format(json_string))
                        mqtt_log.info("Publish topic: /greenichill/365/data/GC4001/")

                        # Delay between publishing messages (adjust as needed).
                        utime.sleep(2)
                    except Exception as e:
                        mqtt_log.error("An error occurred from MQTT: {}".format(e))
        except Exception as e:
            mqtt_log.error("An error occurred: {}".format(e))

        finally:
            # Ensure the client disconnects on exit.
            c.disconnect()
            mqtt_log.info("Disconnected from broker.hivemq.com")
    else:
        mqtt_log.info('Network connection failed! stagecode = {}, subcode = {}'.format(stagecode, subcode))