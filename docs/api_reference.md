# CIPHER — Complete REST API Reference

The **CIPHER** backend provides a clean, local-first REST API built with FastAPI. All endpoints are hosted locally by default on `http://127.0.0.1:8000`.

---

## 1. System & Health Endpoints

### `GET /api/health`
- **Description**: Verifies the status of the API server, database connectivity, and pre-warmed ML model artifacts.
- **Response**:
```json
{
  "status": "ok",
  "service": "CIPHER-IDPS",
  "version": "1.1.0",
  "database": true,
  "models": {
    "phishing": true,
    "network": true
  },
  "timestamp": "2026-09-15T03:00:00Z"
}
```

### `GET /api/system/status`
- **Description**: Comprehensive system diagnostics for the SOC dashboard, reporting memory, uptime, database size, and model versions.
- **Response**:
```json
{
  "system": "CIPHER Local Security Platform",
  "status": "HEALTHY",
  "timestamp": "2026-09-15T03:00:00Z",
  "subsystems": {
    "database": { "status": "CONNECTED", "events_logged": 150 },
    "phishing_engine": { "status": "READY", "version": "phiusiil-rf-v1" },
    "network_engine": { "status": "READY", "version": "cicids2017-dual-rf-v1" },
    "prevention_engine": { "mode": "detect_only" }
  }
}
```

---

## 2. Security Events Endpoints

### `GET /api/events`
- **Description**: Retrieves paginated audit security events with multi-criteria filtering.
- **Query Parameters**:
  - `limit` (int, default=50)
  - `offset` (int, default=0)
  - `severity` (string: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  - `event_type` (string: `PHISHING`, `NETWORK`)
  - `attack_type` (string)
  - `source_ip` (string)
- **Response**:
```json
{
  "total": 12,
  "limit": 50,
  "offset": 0,
  "events": [
    {
      "event_id": "1c12b70b-7515-4b22-ab8a-504841fb3741",
      "timestamp": "2026-09-14T21:41:48Z",
      "event_type": "NETWORK",
      "attack_type": "PORT_SCAN",
      "classification": "PORT_SCAN",
      "risk_score": 80,
      "severity": "CRITICAL",
      "source_ip": "203.0.113.88",
      "destination_ip": "10.0.0.1",
      "detection_method": "HYBRID",
      "action": "MONITORED_ONLY"
    }
  ]
}
```

### `GET /api/events/{event_id}`
- **Description**: Retrieves full metadata, feature dictionary, triggered rules, and explanation for a single event.

### `GET /api/stats`
- **Description**: Returns overall system event statistics, severity counts, and attack distribution.

---

## 3. Incident Management & Correlation Endpoints

### `GET /api/incidents`
- **Description**: Lists correlated multi-stage security incident chains.
- **Query Parameters**:
  - `limit` (int, default=50)
  - `offset` (int, default=0)
  - `status` (string: `ACTIVE`, `RESOLVED`, `INVESTIGATING`)
  - `severity` (string)
  - `source_ip` (string)

### `GET /api/incidents/{incident_id}`
- **Description**: Fetches detailed incident record including event count, correlation score, escalation flag, and summary.

### `GET /api/incidents/{incident_id}/events`
- **Description**: Returns chronological list of all security events linked to the specified incident chain.

### `POST /api/incidents/{incident_id}/resolve`
- **Description**: Resolves both the in-memory active tracking chain and updates the SQLite database record.

### `GET /api/correlation/stats`
- **Description**: Returns correlation metrics: active chains, resolved incidents, multi-stage escalation counts, and average correlation score.

### `POST /api/correlation/process`
- **Description**: Manually ingest an event into the correlation engine.

---

## 4. Network Intrusion Detection Endpoints

### `GET /api/network/health`
- **Description**: Checks Network IDS status, Dual RF model availability, and active prevention mode.

### `POST /api/network/analyze`
- **Description**: Evaluates an incoming network flow record through the unified detection pipeline.
- **Request Body**:
```json
{
  "source_ip": "192.168.1.105",
  "destination_ip": "10.0.0.1",
  "source_port": 49152,
  "destination_port": 80,
  "protocol": "TCP",
  "features": {
    "Destination Port": 80,
    "Flow Duration": 150000,
    "Total Fwd Packets": 10,
    "Total Backward Packets": 12,
    "Fwd Packet Length Mean": 120.0,
    "Bwd Packet Length Mean": 350.0,
    "Fwd Packets/s": 66.7,
    "Flow Bytes/s": 3133.3
  }
}
```
- **Response**: `NetworkDetectionResponse` containing `threat_score`, `severity`, `attack_type`, `ml_prediction`, `ml_confidence`, `recommended_action`, and `applied_action`.

### `GET /api/network/stats`
- **Description**: Aggregates network flow statistics, attack categories, and prevention decisions.

### `GET /api/network/model`
- **Description**: Inspects Dual Random Forest architecture, feature names, and top feature importances.

### `GET /api/network/interfaces`
- **Description**: Lists available physical and loopback network interfaces detected via Scapy / Npcap.

### `GET /api/network/sensor/status`
- **Description**: Telemetry on packet capture: packet count, active flow count, dropped packets, and uptime.

### `POST /api/network/sensor/start`
- **Description**: Starts the live packet capture sniffer on a specified interface with optional BPF filter.

### `POST /api/network/sensor/stop`
- **Description**: Stops the live packet capture sniffer and flushes in-memory flows.

### `GET /api/network/blocklist`
- **Description**: Returns all currently active IP containment entries with remaining TTL.

### `DELETE /api/network/blocklist/{ip}`
- **Description**: Manually unblocks an IP from the prevention blocklist.

---

## 5. Phishing URL Detection Endpoints

### `POST /api/phishing/analyze`
- **Description**: Inspects a URL through the 15-feature static extraction pipeline, Random Forest classifier, and lexical heuristics.
- **Request Body**:
```json
{
  "url": "http://192.168.1.1/login.php?user=admin&token=secure"
}
```
- **Response**:
```json
{
  "url": "http://192.168.1.1/login.php?user=admin&token=secure",
  "risk_score": 88,
  "severity": "CRITICAL",
  "classification": "LIKELY_PHISHING",
  "ml_prediction": "PHISHING",
  "ml_probability": 0.942,
  "heuristic_score": 75,
  "reasons": [
    "URL utilizes raw IPv4 address in domain hostname",
    "Contains sensitive authentication keywords ('login', 'admin', 'token')"
  ],
  "recommendation": "DANGER: High probability of phishing attack. Do not enter credentials."
}
```

---

## 6. Deterministic Rules Endpoints

### `GET /api/rules`
- **Description**: Lists all 14 registered deterministic heuristic and signature rules.

### `GET /api/rules/{rule_id}`
- **Description**: Fetches individual rule metadata, category, weight, and enabled status.

### `POST /api/rules/{rule_id}/enable`
- **Description**: Enables an active heuristic or signature rule.

### `POST /api/rules/{rule_id}/disable`
- **Description**: Disables a heuristic or signature rule.

### `POST /api/rules/evaluate`
- **Description**: Sandboxed evaluation of raw event metadata against all registered rules.

---

## 7. Threat Intelligence & IOC Endpoints

### `GET /api/threat-intel/iocs`
- **Description**: Paginated listing of IOCs with type and severity filtering.
- **Query Parameters**: `limit`, `offset`, `ioc_type`, `severity`, `enabled_only`.

### `POST /api/threat-intel/iocs`
- **Description**: Adds a new threat indicator (`IP`, `DOMAIN`, `URL`, `HASH`).
- **Request Body**:
```json
{
  "ioc_type": "IP",
  "indicator": "203.0.113.88",
  "severity": "HIGH",
  "confidence": 0.90,
  "category": "SCANNER",
  "description": "Known aggressive scanner IP",
  "tags": ["reconnaissance", "threat_actor"]
}
```

### `GET /api/threat-intel/iocs/{ioc_id}`
- **Description**: Retrieves single IOC record.

### `DELETE /api/threat-intel/iocs/{ioc_id}`
- **Description**: Deletes an IOC from the local SQLite store.

### `POST /api/threat-intel/iocs/{ioc_id}/enable`
- **Description**: Enables an IOC for active matching.

### `POST /api/threat-intel/iocs/{ioc_id}/disable`
- **Description**: Disables an IOC (prevents match elevation without deleting the record).

### `GET /api/threat-intel/check`
- **Description**: Instant lookup checking if an indicator matches an active IOC.

### `POST /api/threat-intel/import/json`
- **Description**: Bulk imports an array of up to 1,000 IOC records via JSON.

### `POST /api/threat-intel/import/csv`
- **Description**: Bulk imports a CSV file of up to 1,000 IOC records via multipart form.

### `GET /api/threat-intel/export/json`
- **Description**: Exports the local IOC store as a downloadable JSON file.

### `GET /api/threat-intel/stats`
- **Description**: Returns total IOC count, active count, type breakdown, and severity breakdown.
