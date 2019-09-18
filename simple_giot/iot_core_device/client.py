from datetime import datetime as dt, timedelta
import json
import logging
import os
import ssl
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

DEFAULT_RETRY = 60


# noinspection PyMethodOverriding
class Client(mqtt.Client):
    def __init__(self,
                 device_id, registry_id, project_id, cloud_region=DEFAULT_REGION,
                 algorithm=ALGORITHM, private_cert=PRIVATE_CERT, ca_cert=CA_CERTS,
                 bridge_hostname=MQTT_BRIDGE_HOSTNAME, bridge_port=MQTT_BRIDGE_PORT,
                 retry_time=DEFAULT_RETRY, *args, **kwargs
                 ):
        """

        These parameters are unique to GCP for device identification
        :param device_id: the unique name of the device
        :param registry_id: the registry create in Google IoT Core
        :param project_id: The GCP project
        :param cloud_region: The gcp cloud region used by the registry

        Authentication parameters for connection over MQTT
        :param algorithm: The algorithm associated with the private cert (Ex: RS256)
        :param private_cert: The certificate file used to identify the device to the service
        :param ca_cert: Google's CA root certificate file.
            To connect the device you must have downloaded Google's CA root certificates,
            and a copy of your private key file. See cloud.google.com/iot for instructions
            on how to do this. Run this script with the corresponding algorithm flag.

        Connection parameters
        :param bridge_hostname: the hostname. Google services use: mqtt.googleapis.com
        :param bridge_port: the port to connect to the service. MQTT default is 8883
        :param retry_time: Amount of time credentials expire and need to refresh

        :param args:
        :param kwargs:
        """

        # Device Settings
        self.command_message = ""
        self.command_dt = None

        self.config_message = dict()
        self.config_dt = None

        self._state = dict()

        # IoT Core setup
        self.device_id = device_id
        self.registry_id = registry_id
        self.project_id = project_id
        self.cloud_region = cloud_region

        self.algorithm = algorithm
        self.private_cert = private_cert
        self.ca_cert = ca_cert

        self.bridge_hostname = bridge_hostname
        self.bridge_port = bridge_port

        self.retry_time = retry_time
        self.expire_time = dt.utcnow()
        self._is_ssl_set = False

        self.connected = False

        client_id = CLIENT_ID_PATH % (self.project_id, self.cloud_region, self.registry_id, self.device_id)

        # Command Topic - Subscribed to
        # devices/{device-id}/commands
        # devices/{device-id}/commands/{subfolder}
        self.event_topic = '/devices/{}/events'.format(device_id)
        self.state_topic = '/devices/{}/state'.format(device_id)

        self.config_topic = '/devices/{}/config'.format(device_id)
        self.command_topic = '/devices/{}/commands/#'.format(device_id)

        # Create the MQTT client and connect to Cloud IoT.
        super().__init__(client_id=client_id, *args, **kwargs)

        logger.info(
            "IoT Core Connection: \n"
            "\tProject '%s' \n"
            "\tRegistry '%s' \n"
            "\tDevice '%s'" %
            (self.project_id, self.registry_id, self.device_id)
        )

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
            self.connect(MQTT_BRIDGE_HOSTNAME, MQTT_BRIDGE_PORT)
        except IoTConnectionException as ie:
            logger.warning("Connection Failed. Will retry in a few seconds.")
            logger.warning(ie)
            return False

        self.loop_start()

        # Wait up to 5 seconds for the device to connect.
        self._wait_for_connection(5)

        self.subscribe(self.config_topic, qos=1)
        self.subscribe(self.command_topic, qos=1)

        return True

    def check_reconnect(self):
        """ Checks expired credentials and refreshes """
        if self.expire_time < dt.utcnow() + timedelta(minutes=1):
            logger.info("Token Expiring | Now Reconnecting.")
            self.loop_stop()
            self.start()

    def close(self):
        """Closes connection to host"""
        self.disconnect()
        self.loop_stop()
        logger.info('Finished loop successfully. Goodbye!')

    @staticmethod
    def error_str(rc):
        """Convert a Paho error to a human readable string."""
        return '{}: {}'.format(rc, mqtt.error_string(rc))

    @property
    def state(self):
        """ Returns a mapping of device state"""
        return self._state

    def _wait_for_connection(self, timeout):
        """Wait for the device to become connected."""
        total_time = 0
        while not self.connected and total_time < timeout:
            time.sleep(1)
            total_time += 1

        if not self.connected:
            raise RuntimeError('Could not connect to MQTT bridge.')

    def on_connect(self, unused_client, unused_userdata, unused_flags, rc):
        """Callback for when a device connects."""
        if not rc:
            logger.debug('Connected')
            self.connected = True
        else:
            logger.error('Connection Result: ' + self.error_str(rc))

    def on_disconnect(self, unused_client, unused_userdata, rc):
        """Callback for when a device disconnects."""
        logger.info('Disconnected:' + self.error_str(rc))
        self.connected = False

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
        logger.info('     Payload: %s' % payload)

        # The device will receive its latest config when it subscribes to the
        # config topic. If there is no configuration for the device, the device
        # will receive a config with an empty payload.
        if not payload:
            return

        if is_config:
            self.config_dt = dt.utcnow()
            return self.process_config(payload)

        self.command_dt = dt.utcnow()
        return self.process_command(payload)

    def process_config(self, payload):
        """ Processes a config message. """
        try:
            self.config_message = json.loads(payload)
        except (TypeError, Exception):
            logger.debug("Payload not in JSON format")
            return

    def process_command(self, data):
        """ Processes a command message. """
        self.command_message = data

    def send_state(self):
        """ Sends the state of the device to the cloud service. """
        payload = json.dumps(self.state)
        return self.publish(self.state_topic, payload, qos=1)

    def send_payload(self, payload):
        """
        Sends a dict to IoT Core
        :type payload: dict Payload for IoT Core
        """
        if not self.connected:
            self.start()
        if isinstance(payload, str):
            payload = json.dumps(payload)
        logger.info('Publishing Payload: %s' % payload)
        return self.publish(self.event_topic, payload, qos=1)
