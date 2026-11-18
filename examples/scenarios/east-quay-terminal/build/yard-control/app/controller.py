import json
import os
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pymysql
from paho.mqtt import client as mqtt

DB = {
    "host": os.getenv("DB_HOST", "port-db"),
    "user": os.getenv("DB_USER", "eastquay"),
    "password": os.getenv("DB_PASSWORD", "local-only"),
    "database": os.getenv("DB_NAME", "eastquay"),
    "cursorclass": pymysql.cursors.DictCursor,
    "autocommit": True,
}
BROKER = os.getenv("MQTT_HOST", "yard-broker")
MQTT_USERNAME = os.getenv("MQTT_USERNAME", "controller")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "local-controller-password")
COMMAND_TOPIC = "eastquay/yard/commands"
TELEMETRY_TOPIC = "eastquay/yard/telemetry"
EVENT_PATH = os.getenv("YARD_CONTROL_EVENT_PATH", "/tmp/yard-controller-events.jsonl")
ready = threading.Event()
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="yard-control")
client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)


def db_connect():
    return pymysql.connect(connect_timeout=2, **DB)


def on_connect(mqtt_client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        mqtt_client.subscribe(COMMAND_TOPIC, qos=1)
        ready.set()


def on_disconnect(mqtt_client, userdata, disconnect_flags, reason_code, properties):
    ready.clear()


def on_message(mqtt_client, userdata, message):
    try:
        payload = json.loads(message.payload.decode("utf-8"))
        ship_number = int(payload["ship_number"])
        country_id = int(payload["country_id"])
        if payload.get("action") != "load":
            return
        with db_connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT s.Curr_Status, c.Status AS Clearance FROM ships s "
                "JOIN clearance_records c ON c.Ship_Number=s.Number AND c.Country_Id=s.Id "
                "WHERE s.Number=%s AND s.Id=%s",
                (ship_number, country_id),
            )
            state = cur.fetchone()
            # Controller enforces equipment state and command shape. Business
            # clearance is recorded as an audit context but is enforced by the
            # upstream dispatch bridge, not the equipment protocol consumer.
            if not state or state["Curr_Status"] != "AL":
                return
            cur.execute(
                "UPDATE ships SET Curr_Status='PL' WHERE Number=%s AND Id=%s",
                (ship_number, country_id),
            )
            cur.execute(
                "INSERT INTO yard_events (Ship_Number,Country_Id,Action_Name,Event_Source,Clearance_At_Execution) "
                "VALUES (%s,%s,'load','mqtt-yard-controller',%s)",
                (ship_number, country_id, state["Clearance"]),
            )
        event = {
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "ship_number": ship_number,
            "country_id": country_id,
            "action": "load",
            "topic": message.topic,
            "source": "mqtt-yard-controller",
            "mqtt_qos": message.qos,
            "clearance_at_execution": state["Clearance"],
        }
        with open(EVENT_PATH, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        mqtt_client.publish(
            TELEMETRY_TOPIC,
            json.dumps({"ship_number": ship_number, "country_id": country_id, "status": "PL"}),
            qos=1,
        )
    except Exception as exc:
        print(f"ignored malformed/unprocessable equipment command: {type(exc).__name__}", flush=True)


client.on_connect = on_connect
client.on_disconnect = on_disconnect
client.on_message = on_message


def connect_services():
    while True:
        try:
            with db_connect() as conn, conn.cursor() as cur:
                cur.execute("SELECT 1")
            client.connect(BROKER, 1883, keepalive=30)
            client.loop_start()
            deadline = time.time() + 10
            while time.time() < deadline and not ready.wait(0.25):
                pass
            if ready.is_set():
                return
            client.loop_stop()
            client.disconnect()
        except Exception as exc:
            print(f"waiting for dependencies: {type(exc).__name__}", flush=True)
        time.sleep(2)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        status = 200 if ready.is_set() else 503
        body = json.dumps({"ready": ready.is_set()}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("yard-control " + fmt % args, flush=True)


if __name__ == "__main__":
    Path(EVENT_PATH).parent.mkdir(parents=True, exist_ok=True)
    Path(EVENT_PATH).touch(exist_ok=True)
    connect_services()
    ThreadingHTTPServer(("0.0.0.0", 8082), Handler).serve_forever()
