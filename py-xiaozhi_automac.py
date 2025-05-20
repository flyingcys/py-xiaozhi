# pip3 install pynput==1.7.7 cryptography==44.0.0 paho-mqtt==2.1.0 opuslib==3.0.1
#!/usr/bin/python
# -*- coding: UTF-8 -*-
import json
import time
import requests
import paho.mqtt.client as mqtt
import threading
import pyaudio
import opuslib
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import logging
from pynput import keyboard as pynput_keyboard
import uuid

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 全局变量
OTA_VERSION_URL = 'https://api.tenclass.net/xiaozhi/ota/'
MAC_ADDR = None
mqtt_info = {}
aes_opus_info = {
    "type": "hello",
    "version": 3,
    "transport": "udp",
    "udp": {
        "server": "120.24.160.13",
        "port": 8884,
        "encryption": "aes-128-ctr",
        "key": "263094c3aa28cb42f3965a1020cb21a7",
        "nonce": "01000000ccba9720b4bc268100000000"
    },
    "audio_params": {
        "format": "opus",
        "sample_rate": 24000,
        "channels": 1,
        "frame_duration": 60
    },
    "session_id": "b23ebfe9"
}
iot_msg = {
    "session_id": "635aa42d",
    "type": "iot",
    "descriptors": [
        {
            "name": "Speaker",
            "description": "当前 AI 机器人的扬声器",
            "properties": {
                "volume": {
                    "description": "当前音量值",
                    "type": "number"
                }
            },
            "methods": {
                "SetVolume": {
                    "description": "设置音量",
                    "parameters": {
                        "volume": {
                            "description": "0到100之间的整数",
                            "type": "number"
                        }
                    }
                }
            }
        },
        {
            "name": "Lamp",
            "description": "一个测试用的灯",
            "properties": {
                "power": {
                    "description": "灯是否打开",
                    "type": "boolean"
                }
            },
            "methods": {
                "TurnOn": {
                    "description": "打开灯",
                    "parameters": {}
                },
                "TurnOff": {
                    "description": "关闭灯",
                    "parameters": {}
                }
            }
        }
    ]
}
iot_status_msg = {
    "session_id": "635aa42d",
    "type": "iot",
    "states": [
        {"name": "Speaker", "state": {"volume": 50}},
        {"name": "Lamp", "state": {"power": False}}
    ]
}
local_sequence = 0
listen_state = None
tts_state = None
key_state = None
audio = None
udp_socket = None
conn_state = False
recv_audio_thread = None
send_audio_thread = None
mqttc = None

# 获取MAC地址
def get_mac_address():
    mac_int = uuid.getnode()
    mac_hex = "{:012x}".format(mac_int)
    mac_address = ":".join([mac_hex[i:i+2] for i in range(0, 12, 2)]).lower()
    return mac_address

# 初始化MAC地址
MAC_ADDR = get_mac_address()
logging.info(f"你的设备MAC地址为: {MAC_ADDR}")

# AES加密
def aes_ctr_encrypt(key, nonce, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

# AES解密
def aes_ctr_decrypt(key, nonce, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# 发送音频数据
def send_audio():
    global aes_opus_info, udp_socket, local_sequence, listen_state, audio
    key = aes_opus_info['udp']['key']
    nonce = aes_opus_info['udp']['nonce']
    server_ip = aes_opus_info['udp']['server']
    server_port = aes_opus_info['udp']['port']
    encoder = opuslib.Encoder(16000, 1, opuslib.APPLICATION_AUDIO)
    mic = audio.open(format=pyaudio.paInt16, channels=1, rate=16000, input=True, frames_per_buffer=960)

    logging.info(f"UDP connected to {server_ip}:{server_port}")
    try:
        while True:
            if listen_state == "stop":
                time.sleep(0.1)
                continue
            data = mic.read(960)
            encoded_data = encoder.encode(data, 960)
            local_sequence += 1
            new_nonce = nonce[0:4] + format(len(encoded_data), '04x') + nonce[8:24] + format(local_sequence, '08x')
            encrypt_encoded_data = aes_ctr_encrypt(bytes.fromhex(key), bytes.fromhex(new_nonce), bytes(encoded_data))
            data = bytes.fromhex(new_nonce) + encrypt_encoded_data
            udp_socket.sendto(data, (server_ip, server_port))
    except Exception as e:
        logging.error(f"Error in send_audio: {e}")
    finally:
        logging.info("UDP connection closed in send_audio")
        local_sequence = 0
        mic.stop_stream()
        mic.close()

# 接收音频数据
def recv_audio():
    global aes_opus_info, udp_socket, audio
    key = aes_opus_info['udp']['key']
    nonce = aes_opus_info['udp']['nonce']
    sample_rate = aes_opus_info['audio_params']['sample_rate']
    frame_duration = aes_opus_info['audio_params']['frame_duration']
    frame_num = int(frame_duration / (1000 / sample_rate))
    decoder = opuslib.Decoder(sample_rate, 1)
    spk = audio.open(format=pyaudio.paInt16, channels=1, rate=sample_rate, output=True, frames_per_buffer=frame_num)

    logging.info(f"UDP connected to {aes_opus_info['udp']['server']}:{aes_opus_info['udp']['port']}")
    try:
        while True:
            data, server = udp_socket.recvfrom(4096)
            encrypt_encoded_data = data
            split_encrypt_encoded_data_nonce = encrypt_encoded_data[:16]
            split_encrypt_encoded_data = encrypt_encoded_data[16:]
            decrypt_data = aes_ctr_decrypt(bytes.fromhex(key), split_encrypt_encoded_data_nonce, split_encrypt_encoded_data)
            spk.write(decoder.decode(decrypt_data, frame_num))
    except Exception as e:
        logging.error(f"Error in recv_audio: {e}")
    finally:
        logging.info("UDP connection closed in recv_audio")
        spk.stop_stream()
        spk.close()

# MQTT消息回调
def on_message(client, userdata, message):
    global aes_opus_info, udp_socket, tts_state, recv_audio_thread, send_audio_thread, conn_state
    msg = json.loads(message.payload)
    logging.info(f"Received message: {msg}")

    if msg['type'] == 'hello':
        aes_opus_info = msg
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.connect((msg['udp']['server'], msg['udp']['port']))
        iot_msg['session_id'] = msg['session_id']
        push_mqtt_msg(iot_msg)
        iot_status_msg['session_id'] = msg['session_id']
        push_mqtt_msg(iot_status_msg)

        if not recv_audio_thread or not recv_audio_thread.is_alive():
            recv_audio_thread = threading.Thread(target=recv_audio)
            recv_audio_thread.start()

        if not send_audio_thread or not send_audio_thread.is_alive():
            send_audio_thread = threading.Thread(target=send_audio)
            send_audio_thread.start()

    if msg['type'] == 'tts':
        tts_state = msg['state']

    if msg['type'] == 'goodbye':
        logging.info("Received goodbye message, resetting connection state")
        aes_opus_info['session_id'] = None  # 重置 session_id
        conn_state = False  # 标记需要重新建立连接

        # 关闭 UDP 连接
        if udp_socket:
            udp_socket.close()
            udp_socket = None

        # 停止音频线程
        if recv_audio_thread and recv_audio_thread.is_alive():
            recv_audio_thread.join(timeout=1)
            recv_audio_thread = None

        if send_audio_thread and send_audio_thread.is_alive():
            send_audio_thread.join(timeout=1)
            send_audio_thread = None

        logging.info("UDP connection and threads closed after goodbye message")

# MQTT连接回调
def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        logging.info("MQTT connected successfully")
        subscribe_topic = mqtt_info['subscribe_topic'].split("/")[0] + '/p2p/GID_test@@@' + MAC_ADDR.replace(':', '_')
        logging.info(f"Subscribed to topic: {subscribe_topic}")
        client.subscribe(subscribe_topic)
    else:
        logging.error(f"MQTT connection failed with code {rc}")

# MQTT断开回调
def on_disconnect(client, userdata, rc, properties=None):
    logging.info("MQTT disconnected")
    if rc != 0:
        logging.error(f"Unexpected MQTT disconnection. Will auto-reconnect")

# 推送MQTT消息
def push_mqtt_msg(message):
    global mqttc
    mqttc.publish(mqtt_info['publish_topic'], json.dumps(message))

# 获取OTA版本信息
def get_ota_version():
    global mqtt_info
    header = {
        'Device-Id': MAC_ADDR,
        'Content-Type': 'application/json'
    }
    post_data = {
        "flash_size": 16777216,
        "minimum_free_heap_size": 8318916,
        "mac_address": MAC_ADDR,
        "chip_model_name": "esp32s3",
        "chip_info": {
            "model": 9,
            "cores": 2,
            "revision": 2,
            "features": 18
        },
        "application": {
            "name": "xiaozhi",
            "version": "0.9.9",
            "compile_time": "Jan 22 2025T20:40:23Z",
            "idf_version": "v5.3.2-dirty",
            "elf_sha256": "22986216df095587c42f8aeb06b239781c68ad8df80321e260556da7fcf5f522"
        },
        "partition_table": [
            {"label": "nvs", "type": 1, "subtype": 2, "address": 36864, "size": 16384},
            {"label": "otadata", "type": 1, "subtype": 0, "address": 53248, "size": 8192},
            {"label": "phy_init", "type": 1, "subtype": 1, "address": 61440, "size": 4096},
            {"label": "model", "type": 1, "subtype": 130, "address": 65536, "size": 983040},
            {"label": "storage", "type": 1, "subtype": 130, "address": 1048576, "size": 1048576},
            {"label": "factory", "type": 0, "subtype": 0, "address": 2097152, "size": 4194304},
            {"label": "ota_0", "type": 0, "subtype": 16, "address": 6291456, "size": 4194304},
            {"label": "ota_1", "type": 0, "subtype": 17, "address": 10485760, "size": 4194304}
        ],
        "ota": {"label": "factory"},
        "board": {
            "type": "bread-compact-wifi",
            "ssid": "mzy",
            "rssi": -58,
            "channel": 6,
            "ip": "192.168.124.38",
            "mac": "cc:ba:97:20:b4:bc"
        }
    }

    try:
        response = requests.post(OTA_VERSION_URL, headers=header, data=json.dumps(post_data))
        logging.info(f"OTA version response: {response.text}")
        mqtt_info = response.json()['mqtt']
    except Exception as e:
        logging.error(f"Error in get_ota_version: {e}")

# 键盘监听回调
def on_press(key):
    if key == pynput_keyboard.Key.space:
        on_space_key_press()

def on_release(key):
    if key == pynput_keyboard.Key.space:
        on_space_key_release()
    if key == pynput_keyboard.Key.esc:
        return False

# 空格键按下
def on_space_key_press():
    global key_state, udp_socket, aes_opus_info, listen_state, conn_state
    if key_state == "press":
        return
    key_state = "press"

    # 如果连接已断开或 session_id 为空，自动重新建立连接
    if not conn_state or not aes_opus_info.get('session_id'):
        conn_state = True
        hello_msg = {
            "type": "hello",
            "version": 3,
            "transport": "udp",
            "audio_params": {
                "format": "opus",
                "sample_rate": 16000,
                "channels": 1,
                "frame_duration": 60
            }
        }
        push_mqtt_msg(hello_msg)
        logging.info(f"Sent hello message to re-establish connection: {hello_msg}")

    if tts_state == "start" or tts_state == "entence_start":
        push_mqtt_msg({"type": "abort"})
        logging.info("Sent abort message")

    if aes_opus_info.get('session_id'):
        msg = {
            "session_id": aes_opus_info['session_id'],
            "type": "listen",
            "state": "start",
            "mode": "manual"
        }
        logging.info(f"Sent start listen message: {msg}")
        push_mqtt_msg(msg)

# 空格键释放
def on_space_key_release():
    global key_state, aes_opus_info
    key_state = "release"
    if aes_opus_info.get('session_id'):
        msg = {
            "session_id": aes_opus_info['session_id'],
            "type": "listen",
            "state": "stop"
        }
        logging.info(f"Sent stop listen message: {msg}")
        push_mqtt_msg(msg)

# 主函数
def run():
    global mqtt_info, mqttc, audio
    get_ota_version()
    audio = pyaudio.PyAudio()

    # 启动键盘监听
    listener = pynput_keyboard.Listener(on_press=on_press, on_release=on_release)
    listener.start()

    # 初始化MQTT客户端
    mqttc = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id=mqtt_info['client_id'])
    mqttc.username_pw_set(username=mqtt_info['username'], password=mqtt_info['password'])
    mqttc.tls_set(ca_certs=None, certfile=None, keyfile=None, cert_reqs=mqtt.ssl.CERT_REQUIRED,
                  tls_version=mqtt.ssl.PROTOCOL_TLS, ciphers=None)
    mqttc.on_connect = on_connect
    mqttc.on_disconnect = on_disconnect
    mqttc.on_message = on_message
    mqttc.connect(host=mqtt_info['endpoint'], port=8883)
    mqttc.loop_forever()

if __name__ == "__main__":
    run()