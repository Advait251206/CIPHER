from scapy.all import IP, TCP, Ether
from app.network.live_sensor.flow_tracker import FlowTracker
from app.network.live_sensor.config import SensorConfig

pkt = Ether()/IP(src='192.168.29.29', dst='192.168.29.29')/TCP(sport=1234, dport=5174)/b"username=AdvaitTest' --"
tracker = FlowTracker(SensorConfig())
tracker.process_packet(pkt)
