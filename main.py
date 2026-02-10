import os
import json
import threading
import ssl
import logging
import time
import requests
from dotenv import load_dotenv
from colorama import Fore, Style, init
import paho.mqtt.client as mqtt
from flask import Flask, request, jsonify

init(autoreset=True)
load_dotenv()

MQTT_BROKER = os.getenv("MQTT_BROKER")
MQTT_PORT = int(os.getenv("MQTT_PORT", "8883"))
MQTT_USERNAME = os.getenv("MQTT_USERNAME")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
MQTT_SECRET = os.getenv("MQTT_SECRET")
DEV_MODE = os.getenv("DEV_MODE", "false").lower() == "true"

if not MQTT_SECRET:
    raise ValueError("MQTT_SECRET is required")

BASE_TOPICS = ["scan/qr", "scan/rfid", "config"]
TOPICS = [f"dev/{t}" for t in BASE_TOPICS] if DEV_MODE else BASE_TOPICS

client_status = {}

class ColoredFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.MAGENTA,
    }

    def format(self, record):
        color = self.LEVEL_COLORS.get(record.levelno, "")
        record.msg = f"{color}{record.msg}{Style.RESET_ALL}"
        return super().format(record)

handler = logging.StreamHandler()
formatter = ColoredFormatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(formatter)

logger = logging.getLogger("mqtt_webhook")
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

client = mqtt.Client()


def async_post(url, payload):
    def worker():
        try:
            response = requests.post(url, json=payload, timeout=5)
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Webhook error: {e}")

    threading.Thread(target=worker, daemon=True).start()


def handle_status_message(msg):
    client_id = msg.topic.split("/")[-1]

    try:
        status_data = json.loads(msg.payload.decode())
    except Exception:
        logger.warning("❌ Invalid status JSON payload")
        return

    new_status = status_data.get("status", "unknown")
    old_status = client_status.get(client_id, {}).get("status")

    client_status[client_id] = {"status": new_status, "last_seen": time.time()}
    logger.info(f"📡 Client {client_id} is now {new_status}")

    if new_status != old_status:
        async_post(
            WEBHOOK_URL,
            {
                "topic": msg.topic,
                "client_id": client_id,
                "status": new_status,
                "secret_key": MQTT_SECRET,
            }
        )


def handle_config_message(msg):
    try:
        config_data = json.loads(msg.payload.decode())
    except Exception:
        logger.warning("❌ Invalid config JSON payload")
        return

    action = config_data.get("action", "unknown")

    if action == "READ":

        payload = {
            **config_data,
            "topic": f"{"dev/" if DEV_MODE else ""}config",
            "secret_key": MQTT_SECRET,
        }

        def send_webhook():
            try:
                response = requests.post(WEBHOOK_URL, json=payload, timeout=5)
                response.raise_for_status()

                client.publish("config", response.text)
                logger.info(f"✅ Webhook  cofnig sent for topic: {msg.topic}")

            except Exception as e:
                logger.error(f"Webhook error: {e}")

        threading.Thread(target=send_webhook, daemon=True).start()


def handle_secure_payload_message(msg):
    try:
        payload = json.loads(msg.payload.decode())
    except Exception:
        logger.warning("❌ Invalid JSON payload")
        return

    if payload.get("secret_key") != MQTT_SECRET:
        logger.warning(f"❌ Invalid secret key from topic: {msg.topic}")
        return

    payload.pop("secret_key", None)
    payload["topic"] = msg.topic

    def send_webhook():
        try:
            response = requests.post(WEBHOOK_URL, json=payload, timeout=5)
            response.raise_for_status()

            client.publish(f"{msg.topic}/response", response.text)
            logger.info(f"✅ Webhook response sent for topic: {msg.topic}")

        except Exception as e:
            logger.error(f"Webhook error: {e}")

    threading.Thread(target=send_webhook, daemon=True).start()


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info("Connected to MQTT broker")

        for topic in TOPICS:
            client.subscribe(topic)
            logger.info(f"Subscribed to: {topic}")

        client.subscribe("status/#")
        logger.info("Subscribed to: status/#")

    else:
        logger.error(f"MQTT connection failed with code {rc}")


def on_message(client, userdata, msg):
    topic = msg.topic

    if topic.startswith("status/"):
        handle_status_message(msg)
        return

    if topic.startswith("config") or topic.startswith("dev/config"):
        handle_config_message(msg)
        return

    handle_secure_payload_message(msg)


client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
client.tls_set(cert_reqs=ssl.CERT_NONE)
client.tls_insecure_set(True)
client.on_connect = on_connect
client.on_message = on_message


def start_mqtt_worker():
    try:
        client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
        client.loop_forever()
    except Exception as e:
        logger.error(f"MQTT worker failed: {e}")


app = Flask(__name__)


@app.route("/")
def root():
    return jsonify({"status": "ok", "message": "MQTT worker is running", "version_code": "1.1"})


@app.route("/config", methods=['POST'])
def write_config():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Missing config"}), 400

    data_to_publish = {
        **data,
        "action": "WRITE",
        "secret_key": MQTT_SECRET,
    }

    topic = f"{'dev/' if DEV_MODE else ''}config"
    client.publish(topic, json.dumps(data_to_publish))

    return jsonify({"message": "Config is published!"})


def start_mqtt_thread():
    threading.Thread(target=start_mqtt_worker, daemon=True).start()


if __name__ == "__main__":
    logger.info("🚀 Starting MQTT worker + web server...")
    start_mqtt_thread()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
