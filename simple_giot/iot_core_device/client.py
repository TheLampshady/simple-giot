from datetime import datetime as dt, timedelta
import json
import logging
import os
import ssl
from sys import getsizeof
import time

import jwt
import paho.mqtt.client as mqtt

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

IoTConnectionException = mqtt.socket.gaierror

DEFAULT_REGION = "us-central1"
CLIENT_ID_PATH = 'projects/%s/locations/%s/registries/%s/devices/%s'

ALGORITHM = "RS256"
PRIVATE_CERT = 'rsa_private.pem'
CA_CERTS = "roots.pem"

MQTT_BRIDGE_HOSTNAME = 'mqtt.googleapis.com'
MQTT_BRIDGE_PORT = 8883

DEFAULT_RETRY = (60 * 24) - 5  # ~24 hours refresh
DEFAULT_KEEP_ALIVE = 30

MAX_MESSAGE_SIZE = 262144


class IoTPayloadError(Exception):
    def __init__(self, message, size_ratio):
        self.message = message
        self.size_ratio = size_ratio


# noinspection PyMethodOverriding
class MQTTClient(mqtt.Client):
    size_limit = MAX_MESSAGE_SIZE

    def __init__(self,
                 device_id, registry_id, project_id, cloud_region=DEFAULT_REGION,
                 algorithm=ALGORITHM, private_cert=PRIVATE_CERT, ca_cert=CA_CERTS,
                 bridge_hostname=MQTT_BRIDGE_HOSTNAME, bridge_port=MQTT_BRIDGE_PORT,
                 retry_time=DEFAULT_RETRY, keepalive=DEFAULT_KEEP_ALIVE, validate_size=True
                 ):
        # IoT Core setup
        self.project_id = project_id
        self.algorithm = algorithm
        self.private_cert = private_cert
        self.ca_cert = ca_cert

        self.bridge_hostname = bridge_hostname
        self.bridge_port = bridge_port
        self.retry_time = retry_time
        self.keepalive = keepalive
        self.validate_size = validate_size

        self.start_dt = dt.utcnow()
        self.expire_time = self.start_dt
        self._is_ssl_set = False
        self.connected = False
        self._log_disconnect = True

        # Device Settings
        self.command_message = ""
        self.command_dt = self.start_dt

        self.config_message = dict()
        self.config_dt = self.start_dt

        self._iot_config = dict(
            device_id=device_id,
            registry_id=registry_id,
            cloud_region=cloud_region,
            project_id=project_id,
            retry_time=retry_time,
            keepalive=keepalive
        )

        client_id = CLIENT_ID_PATH % (self.project_id, cloud_region, registry_id, device_id)

        # Command Topic - Subscribed to
        # devices/{device-id}/commands
        # devices/{device-id}/commands/{subfolder}
        self.event_topic = '/devices/{}/events'.format(device_id)
        self.state_topic = '/devices/{}/state'.format(device_id)

        self.config_topic = '/devices/{}/config'.format(device_id)
        self.command_topic = '/devices/{}/commands/#'.format(device_id)

        logger.info(
            "IoT Core Connection: \n"
            "\tProject '%s' \n"
            "\tRegistry '%s' \n"
            "\tDevice '%s'" %
            (self.project_id, registry_id, device_id)
        )

        # Create the MQTT client and connects to Cloud IoT.
        super().__init__(client_id=client_id)
        self.start()

    @classmethod
    def from_config(cls, file_name="iot_config.json", *args, **kwargs):
        """
        Loads configurations from a JSON file.
        :param file_name: name of config JSON file.
        :return:
        """
        if not os.path.isfile(file_name):
            return None

        with open(file_name) as f:
            config = json.loads(f.read())

        config.update(kwargs)
        return cls(**config)

    @property
    def expire_left(self):
        if self.expire_time > dt.utcnow():
            return (self.expire_time - dt.utcnow()).seconds
        return (dt.utcnow() - self.expire_time).seconds * -1

    def _authenticate(self):
        """
        Authenticates with JWT. Private and CA cert files required.
        """
        password = self._create_jwt(self.project_id, self.private_cert, self.algorithm)
        self.username_pw_set(username='unused', password=password)
        if not self._is_ssl_set:
            self.tls_set(ca_certs=self.ca_cert, tls_version=ssl.PROTOCOL_TLSv1_2)
            self._is_ssl_set = True

    def _create_jwt(self, project_id, private_key_file, algorithm):
        """Create a JWT (https://jwt.io) to establish an MQTT connection."""
        self.expire_time = dt.utcnow() + timedelta(minutes=self.retry_time)
        token = {
            'iat': dt.utcnow(),
            'exp': self.expire_time,
            'aud': project_id
        }
        with open(private_key_file, 'r') as f:
            private_key = f.read()
        logger.debug('Creating JWT using {} from private key file {}'.format(
            algorithm, private_key_file))
        return jwt.encode(token, private_key, algorithm=algorithm)

    def start(self):
        """ Creates the initial connection, starts IoT loop and registers to pubsub. """
        try:
            self._authenticate()
            self.connect(self.bridge_hostname, self.bridge_port, keepalive=self.keepalive)
        except IoTConnectionException as ie:
            logger.warning("Connection Failed. Will retry in a few seconds.")
            logger.warning(ie)
            return False

        self.loop_start()

        # Wait up to 5 seconds for the device to connect.
        self._wait_for_connection()
        return True

    def check_reconnect(self):
        """ Checks expired credentials and refreshes """
        if self.expire_time < dt.utcnow() + timedelta(minutes=1):
            if not self.connected:
                self.close()
                self.start()
                return
            logger.debug("Token Expiring | Now Reconnecting.")
            self._authenticate()

    def close(self):
        """Closes connection to host"""
        self.disconnect()
        self.connected = False
        self.loop_stop()

    @staticmethod
    def error_str(rc):
        """Convert a Paho error to a human readable string."""
        return '{}: {}'.format(rc, mqtt.error_string(rc))

    @staticmethod
    def connack_str(rc):
        """Convert a Paho error to a human readable string."""
        return '{}: {}'.format(rc, mqtt.connack_string(rc))

    @property
    def _device_state(self):
        """ Returns a mapping of device and service state"""
        state = dict(
            upttime=self.uptime
        )
        state.update(self._iot_config)
        return state

    def _wait_for_connection(self, timeout=5):
        """Wait for the device to become connected."""
        total_time = 0
        while not self.connected and total_time < timeout:
            time.sleep(1)
            total_time += 1

        if not self.connected:
            raise RuntimeError('Could not connect to MQTT bridge.')

    @property
    def uptime(self):
        """ Human-readable date difference since last connection. """
        diff = dt.utcnow() - self.start_dt
        secs = diff.seconds % 60
        all_min = int(diff.seconds // 60)
        mins = all_min % 60
        hours = int(all_min // 60)
        return "Days:{} | {:02d}:{:02d}:{:02d}".format(diff.days, hours, mins, secs)

    def on_connect(self, unused_client, unused_userdata, unused_flags, rc):
        """Callback for when a device connects."""
        if not rc:
            logger.debug('Connected')
            self.connected = True
            self.subscribe([(self.config_topic, 1), (self.command_topic, 0)])
        else:
            logger.error('Connection Error: ' + self.connack_str(rc))

    def on_disconnect(self, unused_client, unused_userdata, rc):
        """Callback for when a device disconnects."""
        if not rc:
            logger.debug('Disconnected')
            self._log_disconnect = True
        elif self._log_disconnect:
            logger.error('Disconnection Error: ' + self.error_str(rc))
            self._log_disconnect = False
        self.connected = False
        self.start_dt = dt.utcnow()
        if rc == 4:
            self._authenticate()

    def on_publish(self, unused_client, unused_userdata, unused_mid):
        """Callback when the device receives a PUBACK from the MQTT bridge."""
        logger.debug('Published message acked.')

    def on_subscribe(self, unused_client, unused_userdata, unused_mid,
                     granted_qos):
        """Callback when the device receives a SUBACK from the MQTT bridge."""
        logger.debug('Subscribed: ' + granted_qos)
        if granted_qos[0] == 128:
            logger.warning('Subscription failed.')

    def on_message(self, unused_client, unused_userdata, message):
        """
        Callback when the device receives a message on a subscription.
        :param unused_client:
        :param unused_userdata:
        :param message:  MQTT message with metadata and serialized payload
        :return:
        """
        payload = message.payload.decode('utf-8')
        is_config = message.topic.split('/')[-1].endswith("config")

        logger.debug('Received message:')
        logger.debug('    Topic: %s' % message.topic)
        logger.debug('    Type: %s' % ("Config" if is_config else "Command"))
        logger.debug('    QoS: %s' % str(message.qos))
        logger.debug('    Payload: %s' % payload)

        # The device will receive its latest config when it subscribes to the
        # config topic. If there is no configuration for the device, the device
        # will receive a config with an empty payload.
        if not payload:
            return

        if is_config:
            return self.process_config(payload)

        return self.process_command(payload)

    def process_config(self, payload):
        """ Processes a config message. """
        self.config_dt = dt.utcnow()
        try:
            self.config_message = json.loads(payload)
            logger.info('Payload: %s' % payload)
        except (TypeError, Exception):
            logger.debug("Payload not in JSON format")
        return

    def process_command(self, data):
        """ Processes a command message. """
        self.command_dt = dt.utcnow()
        self.command_message = data

    def send_state(self):
        """ Sends the state of the device to the cloud service. """
        payload = json.dumps(self._device_state)
        return self.publish(self.state_topic, payload, qos=1)

    def send_payload(self, data):
        """
        Sends a dict to IoT Core
        :type data: dict Payload for IoT Core
        """
        if not self.connected:
            logger.warning("Device Not Connected for Payload: Reconnecting")
            self.start()
        payload = json.dumps(data) if isinstance(data, (dict, list)) else data
        if self.validate_size and getsizeof(payload) >= self.size_limit:
            msg = "Payload Larger than '%d': %d" % (self.size_limit, getsizeof(payload))
            logger.warning(msg)
            raise IoTPayloadError(msg, getsizeof(payload) / self.size_limit)
        logger.debug('Publishing Payload')
        return self.publish(self.event_topic, payload, qos=1)


if __name__ == "__main__":
    client = MQTTClient.from_config()
    client.send_state()
    expire_time = dt.utcnow() + timedelta(minutes=5)
    cmd_last = None
    cfg_last = None
    while True:

        if client.command_dt != cmd_last:
            print(client.command_message)
            cmd_last = client.command_dt
            if client.command_message.lower() == "status":
                client.send_state()
            else:
                client.send_payload({"test": "test"})

        if client.config_dt != cfg_last:
            print(client.config_message)
            cfg_last = client.config_dt
