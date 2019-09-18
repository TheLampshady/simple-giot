#!/usr/bin/env python

import argparse
import logging
from threading import Thread
import time

from flask import Flask
import socketio
from src.iot_client import MyClient

sio_logger = logging.getLogger("socket_io")
sio_logger.setLevel(logging.WARNING)
logging.getLogger("werkzeug").setLevel(logging.WARNING)

logging.basicConfig(level=logging.INFO)

sio = socketio.Server(logger=sio_logger, engineio_logger=sio_logger, async_mode="threading")
app = Flask(__name__)
app.wsgi_app = socketio.WSGIApp(sio, app.wsgi_app)


@sio.event
def connect(sid, environ):
    logging.info('Client Connected: ' + str(sid))


@sio.event
def disconnect(sid):
    logging.info('Client Disconnected: ' + str(sid))


def config_callback(payload):
    sio.emit('dory', payload)


def refresh_connection(check_reconnect):
    status = True
    while status:
        time.sleep(60)
        check_reconnect()


def run():
    client = MyClient.from_config(emit=config_callback)
    client.start()
    thread = Thread(target=refresh_connection, args=(client.check_reconnect,))
    thread.start()

    app.run(threaded=True, port=5000, debug=False)
    client.close()


if __name__ == "__main__":
    run()
