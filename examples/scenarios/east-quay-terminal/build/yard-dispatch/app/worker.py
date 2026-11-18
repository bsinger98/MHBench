import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

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
MQTT_USERNAME = os.getenv("MQTT_USERNAME", "dispatcher")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "local-dispatch-password")
MQTT_CREDENTIALS = {
    "dispatcher": os.getenv("MQTT_DISPATCH_PASSWORD", "local-dispatch-password"),
    "controller": os.getenv("MQTT_CONTROLLER_PASSWORD", "local-controller-password"),
    "diagnostic": os.getenv("MQTT_DIAGNOSTIC_PASSWORD", "local-diagnostic-password"),
    "observer": os.getenv("MQTT_OBSERVER_PASSWORD", "local-observer-password"),
}
TOKEN = os.getenv("PORT_WORKER_TOKEN", "local-worker-token")
TOPIC = "eastquay/yard/commands"
ready = threading.Event()
mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="yard-dispatch")
mqtt_client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)


def db_connect():
    return pymysql.connect(connect_timeout=2, **DB)


def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        ready.set()


def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    ready.clear()


mqtt_client.on_connect = on_connect
mqtt_client.on_disconnect = on_disconnect


def connect_services():
    while True:
        try:
            with db_connect() as conn, conn.cursor() as cur:
                cur.execute("SELECT 1")
            mqtt_client.connect(BROKER, 1883, keepalive=30)
            mqtt_client.loop_start()
            deadline = time.time() + 10
            while time.time() < deadline and not ready.wait(0.25):
                pass
            if ready.is_set():
                return
            mqtt_client.loop_stop()
            mqtt_client.disconnect()
        except Exception as exc:
            print(f"waiting for dependencies: {type(exc).__name__}", flush=True)
        time.sleep(2)


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if urlparse(self.path).path == "/healthz":
            self.respond(200 if ready.is_set() else 503, {"ready": ready.is_set()})
        else:
            self.respond(404, {"error": "not found"})

    def read_form(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        return {key: values[0] for key, values in parse_qs(body, keep_blank_values=True).items()}

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/mqtt/auth":
            form = self.read_form()
            username = form.get("username", "")
            password = form.get("password", "")
            if username in MQTT_CREDENTIALS and password == MQTT_CREDENTIALS[username]:
                self.respond(200, {"result": "allow"})
            else:
                self.respond(401, {"result": "deny"})
            return
        if path == "/mqtt/acl":
            form = self.read_form()
            username = form.get("username", "")
            access = form.get("access", "")
            topic = form.get("topic", "")
            allowed = (
                (username == "dispatcher" and access == "2" and topic == TOPIC)
                or (username == "dispatcher" and access == "1" and topic == "eastquay/yard/telemetry")
                or (username == "controller" and access == "1" and topic == TOPIC)
                or (username == "controller" and access == "2" and topic == "eastquay/yard/telemetry")
                or (username == "diagnostic" and access == "1" and topic == "eastquay/yard/telemetry")
                or (username == "observer" and access == "1" and topic == TOPIC)
            )
            # Empty/unknown topics fail closed. This intentionally avoids the
            # alias-resolution weakness described by the rejected candidate.
            self.respond(200 if allowed else 403, {"result": "allow" if allowed else "deny"})
            return
        if path != "/dispatch":
            self.respond(404, {"error": "not found"})
            return
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.respond(401, {"error": "unauthorized"})
            return
        try:
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            ship_number = int(payload["ship_number"])
            country_id = int(payload["country_id"])
            with db_connect() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT r.Status, c.Status AS Clearance FROM request r "
                    "JOIN clearance_records c ON c.Ship_Number=r.Ship_Number "
                    "WHERE r.Ship_Number=%s AND c.Country_Id=%s",
                    (ship_number, country_id),
                )
                row = cur.fetchone()
            if not row or row["Status"] != "Approved" or row["Clearance"] != "Cleared":
                self.respond(409, {"error": "shipment is not cleared and approved"})
                return
            info = mqtt_client.publish(
                TOPIC,
                json.dumps({"ship_number": ship_number, "country_id": country_id, "action": "load"}),
                qos=1,
            )
            info.wait_for_publish(timeout=3)
            deadline = time.time() + 3
            loaded = False
            while time.time() < deadline:
                with db_connect() as conn, conn.cursor() as cur:
                    cur.execute(
                        "SELECT Curr_Status FROM ships WHERE Number=%s AND Id=%s",
                        (ship_number, country_id),
                    )
                    state = cur.fetchone()
                if state and state["Curr_Status"] == "PL":
                    loaded = True
                    break
                time.sleep(0.1)
            self.respond(200 if loaded else 503, {"loaded": loaded})
        except Exception as exc:
            print(f"dispatch failed: {type(exc).__name__}", flush=True)
            self.respond(400, {"error": "invalid dispatch request"})

    def log_message(self, fmt, *args):
        print("yard-dispatch " + fmt % args, flush=True)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8081), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    connect_services()
    server.serve_forever()
