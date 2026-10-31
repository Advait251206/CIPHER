"""WAF signature accuracy: ordinary traffic must pass, common attacks must be caught."""

import pytest

from app.network.live_sensor.waf_engine import WAFEngine
from app.network.live_sensor.config import load_sensor_config_from_env

HEADERS = (
    "POST /login HTTP/1.1\r\nHost: 192.168.1.10:5174\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    "Referer: http://192.168.1.10:5174/#signup\r\nCookie: theme=dark; session=abc123\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
)

BENIGN = [
    HEADERS + "username=priya&password=Summer2026%23&full_name=Priya+Deshmukh&email=p%40x.com",
    '{"body":"Thanks, see you Monday.\\n-- \\nAdvait"}',
    '{"url":"https://example.com/docs#section-2"}',
    '{"note":"# Weekly update"}',
    '{"msg":"Please update the address and set the delivery time"}',
    '{"msg":"Please select one option from the list"}',
    "full_name=O%27Brien&email=ob%40example.com",
    '{"q":"(see above) and the price is 5"}',
    "comment=Use+--verbose+for+more+output",
    "GET /static/app.js?v=3 HTTP/1.1\r\nHost: x\r\n\r\n",
]

ATTACKS = [
    ("username=admin%27+OR+%27a%27%3D%27a&password=x", "SQL_INJECTION"),
    ("username=admin' OR 'a'='a&password=x", "SQL_INJECTION"),
    ("username=admin'--&password=x", "SQL_INJECTION"),
    ("username=x' OR 1=1 #&password=x", "SQL_INJECTION"),
    ("q=1 UNION SELECT password FROM users", "SQL_INJECTION"),
    ("q=1 UNION/**/ALL/**/SELECT password FROM users", "SQL_INJECTION"),
    ("full_name=x'); DROP TABLE users;--", "SQL_INJECTION"),
    ("id=1 AND 1=1", "SQL_INJECTION"),
    ("id=1' AND SLEEP(5)--", "SQL_INJECTION"),
    ("q=%2555NION%2520SELECT%2520password", "SQL_INJECTION"),
    ("full_name=<script>alert(1)</script >", "XSS"),
    ("full_name=<img src=x onerror=alert(1)>", "XSS"),
    ("full_name=<svg/onload=alert(1)>", "XSS"),
    ("url=javascript:alert(1)", "XSS"),
    ("full_name=<iframe src=data:text/html;base64,PHNjcmlwdD4=>", "XSS"),
    ("GET /download?file=../../../etc/passwd HTTP/1.1", "DIRECTORY_TRAVERSAL"),
    ("GET /download?file=..%2f..%2fwin.ini HTTP/1.1", "DIRECTORY_TRAVERSAL"),
]


@pytest.fixture
def waf():
    return WAFEngine(default_mode="detect")


@pytest.mark.parametrize("payload", BENIGN)
def test_benign_traffic_is_not_flagged(waf, payload):
    assert waf.inspect_payload(payload)[0] is None, payload


@pytest.mark.parametrize("payload,expected", ATTACKS)
def test_attacks_are_detected(waf, payload, expected):
    assert waf.inspect_payload(payload)[0] == expected, payload


def test_waf_does_not_inspect_cipher_api_port_by_default(monkeypatch):
    monkeypatch.delenv("CIPHER_WAF_PORTS", raising=False)
    cfg = load_sensor_config_from_env()
    assert 8000 not in cfg.waf_ports
    assert 5174 in cfg.waf_ports


def test_sensor_tracks_all_ports_by_default(monkeypatch):
    from scapy.all import IP, TCP
    from app.network.live_sensor.flow_tracker import FlowTracker
    monkeypatch.delenv("CIPHER_MONITORED_PORTS", raising=False)
    tracker = FlowTracker(load_sensor_config_from_env())
    for port in range(1, 101):
        pkt = IP(src="203.0.113.66", dst="192.168.1.10") / TCP(sport=40000, dport=port, flags="S")
        pkt.time = 1.0
        tracker.process_packet(pkt)
    assert tracker.active_flow_count == 100
