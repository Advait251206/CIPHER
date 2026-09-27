"""
CIPHER Local Database Storage
Privacy-preserving SQLite database interface for security incident & analysis event logging.
Supports unified event stream (Phishing, Network IDS, Heuristics) and persistent IPS blocklisting.
Zero external transmission; all records remain on local disk.
"""

import os
import sqlite3
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

logger = logging.getLogger("cipher.database")


class Database:
    """Thread-safe SQLite connection and event repository."""

    def __init__(self, db_path: Optional[str] = None):
        backend_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        if db_path is None:
            raw_path = os.getenv("DATABASE_PATH", "cipher.db")
            db_path = os.path.join(backend_root, raw_path) if not os.path.isabs(raw_path) else raw_path
        elif not os.path.isabs(db_path):
            db_path = os.path.join(backend_root, db_path)

        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes and non-destructively migrates tables and indexes."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                # 1. Base Security Events Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS security_events (
                        event_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        classification TEXT NOT NULL,
                        risk_score INTEGER NOT NULL,
                        confidence REAL NOT NULL,
                        severity TEXT NOT NULL,
                        ml_score REAL NOT NULL,
                        heuristic_score INTEGER NOT NULL,
                        domain TEXT NOT NULL,
                        reasons TEXT NOT NULL,
                        recommendation TEXT NOT NULL,
                        model_version TEXT NOT NULL,
                        source TEXT NOT NULL
                    )
                """)

                # 2. Schema Migration: Non-destructive addition of Network IDPS fields
                cursor.execute("PRAGMA table_info(security_events)")
                existing_cols = {row["name"] for row in cursor.fetchall()}

                new_columns = {
                    "event_type": "TEXT DEFAULT 'PHISHING'",
                    "attack_type": "TEXT",
                    "source_ip": "TEXT",
                    "destination_ip": "TEXT",
                    "source_port": "INTEGER",
                    "destination_port": "INTEGER",
                    "protocol": "TEXT",
                    "detection_method": "TEXT DEFAULT 'ML'",
                    "action": "TEXT DEFAULT 'ALERT'",
                    "status": "TEXT DEFAULT 'NEW'",
                    "metadata": "TEXT"
                }

                for col_name, col_def in new_columns.items():
                    if col_name not in existing_cols:
                        cursor.execute(f"ALTER TABLE security_events ADD COLUMN {col_name} {col_def}")
                        logger.info(f"Added column '{col_name}' to security_events table")

                # Indexes on security_events
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_classification ON security_events(classification)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_attack_type ON security_events(attack_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON security_events(source_ip)")

                # 3. Persistent IP Blocklist Table for IPS
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ip_blocklist (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT UNIQUE NOT NULL,
                        reason TEXT NOT NULL,
                        attack_type TEXT NOT NULL,
                        threat_score INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT,
                        source_event_id TEXT,
                        status TEXT NOT NULL DEFAULT 'ACTIVE'
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocklist_ip ON ip_blocklist(ip)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocklist_status ON ip_blocklist(status)")

                # 4. Incidents Table for Correlation Layer
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS incidents (
                        incident_id TEXT PRIMARY KEY,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'OPEN',
                        source_ip TEXT,
                        destination_ip TEXT,
                        event_count INTEGER NOT NULL DEFAULT 1,
                        attack_categories TEXT NOT NULL,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        correlation_score INTEGER NOT NULL,
                        severity TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        escalation_detected BOOLEAN NOT NULL DEFAULT 0,
                        summary TEXT NOT NULL,
                        recommended_action TEXT,
                        applied_action TEXT,
                        metadata TEXT
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents(source_ip)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)")

                # 5. Incident Events Junction Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS incident_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        incident_id TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        UNIQUE(incident_id, event_id),
                        FOREIGN KEY(incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
                        FOREIGN KEY(event_id) REFERENCES security_events(event_id) ON DELETE CASCADE
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON incident_events(incident_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_events_event ON incident_events(event_id)")
                # 6. Threat Intelligence IOC Table (Phase 8)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS threat_intel_iocs (
                        ioc_id TEXT PRIMARY KEY,
                        ioc_type TEXT NOT NULL,
                        indicator TEXT NOT NULL,
                        indicator_normalized TEXT NOT NULL,
                        source TEXT NOT NULL DEFAULT 'LOCAL_ADMIN',
                        confidence REAL NOT NULL DEFAULT 0.85,
                        severity TEXT NOT NULL DEFAULT 'HIGH',
                        category TEXT NOT NULL DEFAULT 'MALICIOUS_IP',
                        description TEXT,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        expires_at TEXT,
                        enabled INTEGER NOT NULL DEFAULT 1,
                        tags TEXT NOT NULL DEFAULT '[]',
                        created_at TEXT NOT NULL,
                        UNIQUE(ioc_type, indicator_normalized)
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_normalized ON threat_intel_iocs(indicator_normalized)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type ON threat_intel_iocs(ioc_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_enabled ON threat_intel_iocs(enabled)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_expires_at ON threat_intel_iocs(expires_at)")

                conn.commit()
                logger.info(f"Initialized & migrated SQLite event database at: {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    def save_event(self, event_data: Dict[str, Any]) -> str:
        """Saves a privacy-safe security event record (Phishing or Network)."""
        query = """
            INSERT INTO security_events (
                event_id, timestamp, classification, risk_score, confidence,
                severity, ml_score, heuristic_score, domain, reasons,
                recommendation, model_version, source,
                event_type, attack_type, source_ip, destination_ip,
                source_port, destination_port, protocol, detection_method,
                action, status, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        reasons_json = json.dumps(event_data.get("reasons", []))
        metadata_val = event_data.get("metadata")
        metadata_json = json.dumps(metadata_val) if isinstance(metadata_val, dict) else (metadata_val or "{}")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (
                event_data["event_id"],
                event_data.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
                event_data.get("classification", "UNKNOWN"),
                event_data["risk_score"],
                event_data["confidence"],
                event_data["severity"],
                event_data.get("ml_score", 0.0),
                event_data.get("heuristic_score", 0),
                event_data.get("domain", event_data.get("source_ip", "unknown")),
                reasons_json,
                event_data.get("recommendation", ""),
                event_data.get("model_version", "phiusiil-rf-v1"),
                event_data.get("source", "api"),
                event_data.get("event_type", "PHISHING"),
                event_data.get("attack_type"),
                event_data.get("source_ip"),
                event_data.get("destination_ip"),
                event_data.get("source_port"),
                event_data.get("destination_port"),
                event_data.get("protocol"),
                event_data.get("detection_method", "ML"),
                event_data.get("action", "ALERT"),
                event_data.get("status", "NEW"),
                metadata_json
            ))
            conn.commit()
        return event_data["event_id"]

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single security event by ID."""
        query = "SELECT * FROM security_events WHERE event_id = ?"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (event_id,))
            row = cursor.fetchone()
            if row:
                d = dict(row)
                d["reasons"] = json.loads(d["reasons"]) if d["reasons"] else []
                if d.get("metadata"):
                    try:
                        d["metadata"] = json.loads(d["metadata"])
                    except Exception:
                        d["metadata"] = {}
                return d
        return None

    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        event_type: Optional[str] = None,
        attack_type: Optional[str] = None,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None,
        status: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Lists security events with optional filtering across event streams."""
        query = "SELECT * FROM security_events WHERE 1=1"
        params: List[Any] = []

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type.upper())
        if attack_type:
            query += " AND attack_type = ?"
            params.append(attack_type.upper())
        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        if source_ip:
            query += " AND (source_ip = ? OR domain = ?)"
            params.extend([source_ip, source_ip])
        if status:
            query += " AND status = ?"
            params.append(status.upper())
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            results = []
            for r in rows:
                d = dict(r)
                d["reasons"] = json.loads(d["reasons"]) if d["reasons"] else []
                if d.get("metadata"):
                    try:
                        d["metadata"] = json.loads(d["metadata"])
                    except Exception:
                        d["metadata"] = {}
                results.append(d)
            return results

    def get_stats(self) -> Dict[str, Any]:
        """Calculates aggregated phishing scanning statistics (backward compatible)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM security_events WHERE event_type = 'PHISHING' OR event_type IS NULL")
            total_scans = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM security_events WHERE (event_type = 'PHISHING' OR event_type IS NULL) AND classification = 'LIKELY_PHISHING'")
            phishing_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM security_events WHERE (event_type = 'PHISHING' OR event_type IS NULL) AND classification = 'SUSPICIOUS'")
            suspicious_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM security_events WHERE (event_type = 'PHISHING' OR event_type IS NULL) AND classification = 'LEGITIMATE'")
            legitimate_count = cursor.fetchone()[0]

            cursor.execute("SELECT AVG(risk_score) FROM security_events WHERE event_type = 'PHISHING' OR event_type IS NULL")
            avg_risk = cursor.fetchone()[0] or 0.0

            return {
                "total_scans": total_scans,
                "phishing_detected": phishing_count,
                "suspicious_detected": suspicious_count,
                "legitimate_verified": legitimate_count,
                "average_risk_score": round(avg_risk, 1)
            }

    def get_network_stats(self) -> Dict[str, Any]:
        """Calculates aggregated Network IDS flow statistics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM security_events WHERE event_type = 'NETWORK'")
            total_flows = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM security_events WHERE event_type = 'NETWORK' AND attack_type != 'BENIGN'")
            total_attacks = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM security_events WHERE event_type = 'NETWORK' AND attack_type = 'BENIGN'")
            benign_flows = cursor.fetchone()[0]

            # Attacks by Category
            cursor.execute("""
                SELECT attack_type, COUNT(*) as cnt
                FROM security_events
                WHERE event_type = 'NETWORK' AND attack_type != 'BENIGN'
                GROUP BY attack_type
                ORDER BY cnt DESC
            """)
            attacks_by_type = {row["attack_type"]: row["cnt"] for row in cursor.fetchall()}

            # Severity Breakdown
            cursor.execute("""
                SELECT severity, COUNT(*) as cnt
                FROM security_events
                WHERE event_type = 'NETWORK'
                GROUP BY severity
            """)
            severity_counts = {row["severity"]: row["cnt"] for row in cursor.fetchall()}

            # Top Source IPs
            cursor.execute("""
                SELECT source_ip, COUNT(*) as cnt
                FROM security_events
                WHERE event_type = 'NETWORK' AND source_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY cnt DESC
                LIMIT 5
            """)
            top_sources = [{row["source_ip"]: row["cnt"]} for row in cursor.fetchall()]

            # Top Destination Ports
            cursor.execute("""
                SELECT destination_port, COUNT(*) as cnt
                FROM security_events
                WHERE event_type = 'NETWORK' AND destination_port IS NOT NULL
                GROUP BY destination_port
                ORDER BY cnt DESC
                LIMIT 5
            """)
            top_ports = [{str(row["destination_port"]): row["cnt"]} for row in cursor.fetchall()]

            # Recent Detections
            cursor.execute("""
                SELECT event_id, timestamp, attack_type, severity, risk_score, source_ip, destination_port
                FROM security_events
                WHERE event_type = 'NETWORK'
                ORDER BY timestamp DESC
                LIMIT 5
            """)
            recent = [dict(r) for r in cursor.fetchall()]

            return {
                "total_network_flows": total_flows,
                "total_attacks_detected": total_attacks,
                "benign_flows": benign_flows,
                "attacks_by_type": attacks_by_type,
                "severity_distribution": {
                    "LOW": severity_counts.get("LOW", 0),
                    "MEDIUM": severity_counts.get("MEDIUM", 0),
                    "HIGH": severity_counts.get("HIGH", 0),
                    "CRITICAL": severity_counts.get("CRITICAL", 0)
                },
                "top_source_ips": top_sources,
                "top_destination_ports": top_ports,
                "recent_detections": recent
            }

    # =========================================================================
    # IPS Persistent Blocklist Methods
    # =========================================================================

    def save_blocked_ip(
        self,
        ip: str,
        reason: str,
        attack_type: str,
        threat_score: int,
        expires_at: Optional[str] = None,
        source_event_id: Optional[str] = None
    ) -> int:
        """Adds or updates an IP entry in the persistent blocklist."""
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        query = """
            INSERT INTO ip_blocklist (ip, reason, attack_type, threat_score, created_at, expires_at, source_event_id, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
            ON CONFLICT(ip) DO UPDATE SET
                reason = excluded.reason,
                attack_type = excluded.attack_type,
                threat_score = excluded.threat_score,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at,
                source_event_id = excluded.source_event_id,
                status = 'ACTIVE'
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (ip, reason, attack_type, threat_score, now_iso, expires_at, source_event_id))
            conn.commit()
            return cursor.lastrowid

    def is_ip_blocked(self, ip: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Checks if an IP is currently actively blocked and not expired."""
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        query = "SELECT * FROM ip_blocklist WHERE ip = ? AND status = 'ACTIVE'"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (ip,))
            row = cursor.fetchone()
            if not row:
                return False, None

            record = dict(row)
            expires_at = record.get("expires_at")
            if expires_at and expires_at < now_iso:
                # Expired -> mark inactive
                cursor.execute("UPDATE ip_blocklist SET status = 'EXPIRED' WHERE id = ?", (record["id"],))
                conn.commit()
                return False, None

            return True, record

    def remove_blocked_ip(self, ip: str) -> bool:
        """Manually unblocks an IP."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE ip_blocklist SET status = 'REMOVED' WHERE ip = ? AND status = 'ACTIVE'", (ip,))
            conn.commit()
            return cursor.rowcount > 0

    def list_blocked_ips(self, status: str = "ACTIVE") -> List[Dict[str, Any]]:
        """Lists blocked IPs matching status."""
        query = "SELECT * FROM ip_blocklist WHERE status = ? ORDER BY created_at DESC"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (status,))
            return [dict(r) for r in cursor.fetchall()]

    def cleanup_expired_blocks(self) -> int:
        """Marks any expired blocks as EXPIRED."""
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        query = "UPDATE ip_blocklist SET status = 'EXPIRED' WHERE status = 'ACTIVE' AND expires_at IS NOT NULL AND expires_at < ?"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (now_iso,))
            conn.commit()
            return cursor.rowcount

    # =========================================================================
    # Incident Correlation Repositories (Phase 6)
    # =========================================================================

    def save_incident(self, incident_data: Dict[str, Any], event_ids: Optional[List[str]] = None) -> str:
        """Saves a new correlated security incident record and links its events."""
        query = """
            INSERT INTO incidents (
                incident_id, created_at, updated_at, status, source_ip, destination_ip,
                event_count, attack_categories, first_seen, last_seen, correlation_score,
                severity, confidence, escalation_detected, summary, recommended_action,
                applied_action, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        cats = incident_data.get("attack_categories", [])
        cats_json = json.dumps(cats) if isinstance(cats, list) else str(cats)
        meta = incident_data.get("metadata", {})
        meta_json = json.dumps(meta) if isinstance(meta, dict) else str(meta or "{}")

        incident_id = incident_data["incident_id"]

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (
                incident_id,
                incident_data.get("created_at", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
                incident_data.get("updated_at", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
                incident_data.get("status", "OPEN"),
                incident_data.get("source_ip"),
                incident_data.get("destination_ip"),
                incident_data.get("event_count", 1),
                cats_json,
                incident_data.get("first_seen", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
                incident_data.get("last_seen", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
                int(incident_data.get("correlation_score", 0)),
                incident_data.get("severity", "LOW"),
                float(incident_data.get("confidence", 0.0)),
                1 if incident_data.get("escalation_detected", False) else 0,
                incident_data.get("summary", ""),
                incident_data.get("recommended_action"),
                incident_data.get("applied_action"),
                meta_json
            ))

            if event_ids:
                for eid in event_ids:
                    cursor.execute(
                        "INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?, ?)",
                        (incident_id, eid)
                    )

            conn.commit()
        return incident_id

    def update_incident(
        self,
        incident_id: str,
        updates: Dict[str, Any],
        new_event_ids: Optional[List[str]] = None
    ) -> bool:
        """Updates an existing incident record and attaches newly correlated events."""
        set_clauses = []
        params = []

        allowed_fields = [
            "updated_at", "status", "event_count", "attack_categories",
            "last_seen", "correlation_score", "severity", "confidence",
            "escalation_detected", "summary", "recommended_action",
            "applied_action", "metadata"
        ]

        for field in allowed_fields:
            if field in updates:
                val = updates[field]
                if field == "attack_categories" and isinstance(val, list):
                    val = json.dumps(val)
                elif field == "metadata" and isinstance(val, dict):
                    val = json.dumps(val)
                elif field == "escalation_detected":
                    val = 1 if val else 0
                set_clauses.append(f"{field} = ?")
                params.append(val)

        if not set_clauses and not new_event_ids:
            return False

        with self._get_connection() as conn:
            cursor = conn.cursor()
            if set_clauses:
                params.append(incident_id)
                query = f"UPDATE incidents SET {', '.join(set_clauses)} WHERE incident_id = ?"
                cursor.execute(query, tuple(params))

            if new_event_ids:
                for eid in new_event_ids:
                    cursor.execute(
                        "INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?, ?)",
                        (incident_id, eid)
                    )

            conn.commit()
            return True

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single incident by ID including its associated event IDs."""
        query = "SELECT * FROM incidents WHERE incident_id = ?"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (incident_id,))
            row = cursor.fetchone()
            if not row:
                return None
            res = dict(row)

            try:
                res["attack_categories"] = json.loads(res.get("attack_categories") or "[]")
            except Exception:
                res["attack_categories"] = []

            try:
                res["metadata"] = json.loads(res.get("metadata") or "{}")
            except Exception:
                res["metadata"] = {}

            res["escalation_detected"] = bool(res.get("escalation_detected", False))

            cursor.execute("SELECT event_id FROM incident_events WHERE incident_id = ?", (incident_id,))
            res["event_ids"] = [r["event_id"] for r in cursor.fetchall()]

            return res

    def delete_incidents(self, incident_ids: List[str]) -> bool:
        """Deletes multiple incidents and their associated records."""
        if not incident_ids:
            return False
            
        placeholders = ",".join("?" * len(incident_ids))
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"DELETE FROM incident_events WHERE incident_id IN ({placeholders})", incident_ids)
            cursor.execute(f"DELETE FROM incidents WHERE incident_id IN ({placeholders})", incident_ids)
            conn.commit()
            return True

            return res

    def list_incidents(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Lists incidents with optional filtering."""
        conditions = []
        params = []

        if status:
            conditions.append("status = ?")
            params.append(status.upper())
        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())
        if source_ip:
            conditions.append("source_ip = ?")
            params.append(source_ip)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT * FROM incidents {where_clause} ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["attack_categories"] = json.loads(item.get("attack_categories") or "[]")
                except Exception:
                    item["attack_categories"] = []
                try:
                    item["metadata"] = json.loads(item.get("metadata") or "{}")
                except Exception:
                    item["metadata"] = {}
                item["escalation_detected"] = bool(item.get("escalation_detected", False))

                cursor.execute("SELECT event_id FROM incident_events WHERE incident_id = ?", (item["incident_id"],))
                item["event_ids"] = [e["event_id"] for e in cursor.fetchall()]
                results.append(item)

            return results

    def get_incident_events(self, incident_id: str) -> List[Dict[str, Any]]:
        """Retrieves complete security event objects associated with an incident."""
        query = """
            SELECT se.* FROM security_events se
            JOIN incident_events ie ON se.event_id = ie.event_id
            WHERE ie.incident_id = ?
            ORDER BY se.timestamp ASC
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (incident_id,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                ev = dict(r)
                try:
                    ev["reasons"] = json.loads(ev.get("reasons") or "[]")
                except Exception:
                    ev["reasons"] = []
                try:
                    ev["metadata"] = json.loads(ev.get("metadata") or "{}")
                except Exception:
                    ev["metadata"] = {}
                results.append(ev)
            return results

    def get_correlation_stats(self) -> Dict[str, Any]:
        """Calculates aggregate correlation statistics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as total FROM incidents")
            total = cursor.fetchone()["total"]

            cursor.execute("SELECT COUNT(*) as open_cnt FROM incidents WHERE status = 'OPEN'")
            open_cnt = cursor.fetchone()["open_cnt"]

            cursor.execute("SELECT COUNT(*) as resolved_cnt FROM incidents WHERE status = 'RESOLVED'")
            resolved_cnt = cursor.fetchone()["resolved_cnt"]

            cursor.execute("SELECT COUNT(*) as esc_cnt FROM incidents WHERE escalation_detected = 1")
            esc_cnt = cursor.fetchone()["esc_cnt"]

            cursor.execute("SELECT AVG(correlation_score) as avg_score FROM incidents")
            avg_score_row = cursor.fetchone()
            avg_score = round(float(avg_score_row["avg_score"]), 2) if avg_score_row and avg_score_row["avg_score"] is not None else 0.0

            cursor.execute("""
                SELECT source_ip, COUNT(*) as inc_count, MAX(correlation_score) as max_score
                FROM incidents
                WHERE source_ip IS NOT NULL AND source_ip != ''
                GROUP BY source_ip
                ORDER BY inc_count DESC
                LIMIT 5
            """)
            top_sources = [dict(r) for r in cursor.fetchall()]

            cursor.execute("""
                SELECT severity, COUNT(*) as cnt
                FROM incidents
                GROUP BY severity
            """)
            by_severity = {r["severity"]: r["cnt"] for r in cursor.fetchall()}

            return {
                "total_incidents": total,
                "open_incidents": open_cnt,
                "resolved_incidents": resolved_cnt,
                "escalations_detected": esc_cnt,
                "average_correlation_score": avg_score,
                "incidents_by_severity": by_severity,
                "top_attacking_sources": top_sources
            }


    def delete_event(self, event_id: str) -> bool:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM security_events WHERE event_id = ?', (event_id,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f'Database error deleting event {event_id}: {e}')
            return False
