#!/usr/bin/env python3
"""Read-only subscriber that records broker-delivered yard commands."""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from paho.mqtt import client as mqtt

BROKER = os.getenv("MQTT_HOST", "yard-broker")
USERNAME = os.getenv("MQTT_USERNAME", "observer")
PASSWORD = os.getenv("MQTT_PASSWORD", "local-observer-password")
TOPIC = os.getenv("MQTT_TOPIC", "eastquay/yard/commands")
EVENT_PATH = Path(
    os.getenv(
        "OBSERVED_EVENT_PATH",
        "/tmp/yard-broker-observed-commands.jsonl",
    )
)
READY_PATH = Path("/tmp/yard-observer-ready")


def on_connect(client, _userdata, _flags, reason_code, _properties):
    if reason_code == 0:
        client.subscribe(TOPIC, qos=1)
    else:
        READY_PATH.unlink(missing_ok=True)


def on_subscribe(_client, _userdata, _mid, reason_codes, _properties):
    if reason_codes and all(not code.is_failure for code in reason_codes):
        READY_PATH.touch()
    else:
        READY_PATH.unlink(missing_ok=True)


def on_disconnect(_client, _userdata, _disconnect_flags, _reason_code, _properties):
    READY_PATH.unlink(missing_ok=True)


def on_message(_client, _userdata, message):
    try:
        payload = json.loads(message.payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    if not isinstance(payload, dict):
        return

    record = {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "topic": message.topic,
        "qos": message.qos,
        "retained": bool(message.retain),
        "payload": payload,
    }
    EVENT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with EVENT_PATH.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def main():
    EVENT_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVENT_PATH.touch(exist_ok=True)
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="yard-command-audit-observer",
        protocol=mqtt.MQTTv5,
    )
    client.username_pw_set(USERNAME, PASSWORD)
    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_disconnect = on_disconnect
    client.on_message = on_message

    while True:
        try:
            client.connect(BROKER, 1883, keepalive=30)
            client.loop_forever(retry_first_connection=True)
        except (OSError, mqtt.MqttException) as exc:
            READY_PATH.unlink(missing_ok=True)
            print(f"waiting for broker: {type(exc).__name__}", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
