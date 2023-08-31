#!/usr/bin/env python3
import sys
import time
from scapy.all import Raw ,IP, send, ICMP
from datetime import datetime

def generate_timestamp():
    current_time = datetime.now()
    timestamp = int(current_time.timestamp())
    hex_timestamp = format(timestamp, 'x').zfill(16)
    hex_timestamp_little_endian = ''.join(reversed([hex_timestamp[i:i+2] for i in range(0, len(hex_timestamp), 2)]))
    return bytes.fromhex(hex_timestamp_little_endian)

def create_icmp_packet(dest_ip, identifier, sequence_number, data):
    payload = data + bytes.fromhex("00040000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637").decode("utf-8")
    timestamp_bytes = generate_timestamp()
    icmp_packet = IP(dst=dest_ip) / ICMP(id=identifier, seq=sequence_number) / Raw(timestamp_bytes) / payload
    return icmp_packet

def send_icmp(data):
    dest_ip = "8.8.8.8"
    identifier = 0x001c
    sequence_number = 1

    for char in data:
        icmp_packet = create_icmp_packet(dest_ip, identifier, sequence_number, char)
        send(icmp_packet)
        sequence_number += 1
        time.sleep(0.1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: {} <string_to_send>".format(sys.argv[0]))
        sys.exit(1)
    input_string = sys.argv[1]
    send_icmp(input_string)
