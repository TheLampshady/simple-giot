#!/usr/bin/env python

import logging
from datetime import datetime as dt, timedelta

logging.basicConfig(level=logging.DEBUG)

from simple_giot.iot_core_device import MQTTClient

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
