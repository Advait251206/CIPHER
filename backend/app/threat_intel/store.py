"""
CIPHER Local IOC Store
Thread-safe SQLite repository for Indicators of Compromise with indexed lookups,
bounded LRU caching, expiration filtering, and deterministic duplicate handling.
"""

import json
import uuid
import logging
import threading
import ipaddress
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any, Union

from app.database.database import Database
from app.threat_intel.models import IOCItem, IOCCreateRequest
from app.threat_intel.config import IOC_CACHE_MAX_ENTRIES, IOC_MAX_BULK_IMPORT

logger = logging.getLogger("cipher.threat_intel.store")


def normalize_indicator(ioc_type: str, indicator: str) -> str:
    """Safely normalizes an indicator string for deterministic matching."""
    t = (ioc_type or "").strip().upper()
    s = (indicator or "").strip()

    if t == "IP":
        try:
            return str(ipaddress.ip_address(s))
        except ValueError:
            return s.lower()

    elif t == "DOMAIN":
        clean = s.lower().rstrip(".")
        # Strip scheme if present
        if "://" in clean:
            try:
                clean = urllib.parse.urlparse(clean).netloc or clean
            except Exception:
                pass
        # Strip port if present
        if ":" in clean:
            clean = clean.split(":")[0]
        return clean.strip("/")

    elif t == "URL":
        try:
            parsed = urllib.parse.urlparse(s)
            scheme = (parsed.scheme or "http").lower()
            netloc = (parsed.netloc or "").lower()
            path = parsed.path or "/"
            if len(path) > 1 and path.endswith("/"):
                path = path[:-1]
            query = f"?{parsed.query}" if parsed.query else ""
            return f"{scheme}://{netloc}{path}{query}"
        except Exception:
            return s.lower()

    elif t == "HASH":
        return s.lower()

    return s.lower()


class IOCStore:
    """Thread-safe SQLite store and in-memory cache for IOC records."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()
        self._lock = threading.RLock()
        # Bounded cache: (ioc_type, indicator_normalized) -> (timestamp, Optional[IOCItem])
        self._cache: Dict[Tuple[str, str], Optional[IOCItem]] = {}
        logger.info("Initialized CIPHER Threat Intelligence IOC Store.")

    def _row_to_item(self, row: Any) -> IOCItem:
        d = dict(row)
        tags_raw = d.get("tags")
        if isinstance(tags_raw, str):
            try:
                d["tags"] = json.loads(tags_raw)
            except Exception:
                d["tags"] = []
        elif not isinstance(tags_raw, list):
            d["tags"] = []
        d["enabled"] = bool(d.get("enabled", 1))
        return IOCItem(**d)

    def is_expired(self, expires_at: Optional[str]) -> bool:
        """Checks if an ISO-formatted expiration timestamp has passed."""
        if not expires_at:
            return False
        try:
            # Handle ISO string with or without timezone
            clean_ts = expires_at.replace("Z", "+00:00")
            exp_dt = datetime.fromisoformat(clean_ts)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) > exp_dt
        except Exception:
            return False

    def add_ioc(self, req: Union[IOCCreateRequest, Dict[str, Any]], ioc_id: Optional[str] = None) -> IOCItem:
        """
        Inserts a new validated IOC record.
        Deterministic duplicate handling: rejects duplicate (ioc_type, indicator_normalized).
        """
        if isinstance(req, dict):
            req = IOCCreateRequest(**req)

        norm_ind = normalize_indicator(req.ioc_type, req.indicator)
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        new_id = ioc_id or f"IOC-{uuid.uuid4().hex[:12].upper()}"

        with self._lock:
            with self.db._get_connection() as conn:
                cursor = conn.cursor()
                # Check for duplicate
                cursor.execute(
                    "SELECT ioc_id FROM threat_intel_iocs WHERE ioc_type = ? AND indicator_normalized = ?",
                    (req.ioc_type, norm_ind)
                )
                existing = cursor.fetchone()
                if existing:
                    raise ValueError(
                        f"Duplicate IOC: Indicator '{req.indicator}' of type '{req.ioc_type}' "
                        f"already registered with ID '{existing['ioc_id']}'."
                    )

                query = """
                    INSERT INTO threat_intel_iocs (
                        ioc_id, ioc_type, indicator, indicator_normalized,
                        source, confidence, severity, category, description,
                        first_seen, last_seen, expires_at, enabled, tags, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                cursor.execute(query, (
                    new_id,
                    req.ioc_type,
                    req.indicator,
                    norm_ind,
                    req.source,
                    req.confidence,
                    req.severity,
                    req.category or "THREAT_IOC",
                    req.description,
                    now_iso,
                    now_iso,
                    req.expires_at,
                    1 if req.enabled else 0,
                    json.dumps(req.tags or []),
                    now_iso
                ))
                conn.commit()

            item = IOCItem(
                ioc_id=new_id,
                ioc_type=req.ioc_type,
                indicator=req.indicator,
                indicator_normalized=norm_ind,
                source=req.source,
                confidence=req.confidence,
                severity=req.severity,
                category=req.category or "THREAT_IOC",
                description=req.description,
                first_seen=now_iso,
                last_seen=now_iso,
                expires_at=req.expires_at,
                enabled=req.enabled,
                tags=req.tags or [],
                created_at=now_iso
            )
            self._update_cache(req.ioc_type, norm_ind, item)
            return item

    def get_ioc(self, ioc_id: str) -> Optional[IOCItem]:
        """Retrieves a single IOC by ID."""
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM threat_intel_iocs WHERE ioc_id = ?", (ioc_id,))
            row = cursor.fetchone()
            if row:
                return self._row_to_item(row)
        return None

    def get_ioc_by_indicator(
        self,
        indicator: str,
        ioc_type: Optional[str] = None,
        active_only: bool = True
    ) -> Optional[IOCItem]:
        """
        Looks up an IOC by indicator value.
        If active_only is True (default), ignores disabled and expired IOCs.
        """
        types_to_try = [ioc_type.upper()] if ioc_type else ["IP", "DOMAIN", "URL", "HASH"]

        with self._lock:
            for t in types_to_try:
                norm_ind = normalize_indicator(t, indicator)
                cache_key = (t, norm_ind)
                if cache_key in self._cache:
                    cached_item = self._cache[cache_key]
                    if cached_item is None:
                        continue
                    if active_only:
                        if not cached_item.enabled or self.is_expired(cached_item.expires_at):
                            continue
                    return cached_item

                with self.db._get_connection() as conn:
                    cursor = conn.cursor()
                    query = "SELECT * FROM threat_intel_iocs WHERE ioc_type = ? AND indicator_normalized = ?"
                    cursor.execute(query, (t, norm_ind))
                    row = cursor.fetchone()
                    if row:
                        item = self._row_to_item(row)
                        self._update_cache(t, norm_ind, item)
                        if active_only:
                            if not item.enabled or self.is_expired(item.expires_at):
                                return None
                        return item
                    else:
                        self._update_cache(t, norm_ind, None)

        return None

    def delete_ioc(self, ioc_id: str) -> bool:
        """Removes an IOC from the store."""
        with self._lock:
            item = self.get_ioc(ioc_id)
            with self.db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM threat_intel_iocs WHERE ioc_id = ?", (ioc_id,))
                conn.commit()
                deleted = cursor.rowcount > 0

            if deleted and item:
                cache_key = (item.ioc_type, item.indicator_normalized)
                self._cache.pop(cache_key, None)
            return deleted

    def set_ioc_enabled(self, ioc_id: str, enabled: bool) -> bool:
        """Enables or disables an IOC record."""
        with self._lock:
            with self.db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE threat_intel_iocs SET enabled = ? WHERE ioc_id = ?",
                    (1 if enabled else 0, ioc_id)
                )
                conn.commit()
                updated = cursor.rowcount > 0

            if updated:
                item = self.get_ioc(ioc_id)
                if item:
                    cache_key = (item.ioc_type, item.indicator_normalized)
                    self._cache[cache_key] = item
            return updated

    def list_iocs(
        self,
        ioc_type: Optional[str] = None,
        severity: Optional[str] = None,
        enabled_only: bool = False,
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[IOCItem], int]:
        """Lists IOCs with optional filtering and pagination."""
        query = "SELECT * FROM threat_intel_iocs WHERE 1=1"
        count_query = "SELECT COUNT(*) as cnt FROM threat_intel_iocs WHERE 1=1"
        params: List[Any] = []

        if ioc_type:
            query += " AND ioc_type = ?"
            count_query += " AND ioc_type = ?"
            params.append(ioc_type.upper())
        if severity:
            query += " AND severity = ?"
            count_query += " AND severity = ?"
            params.append(severity.upper())
        if enabled_only:
            query += " AND enabled = 1"
            count_query += " AND enabled = 1"

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        exec_params = list(params) + [limit, offset]

        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(count_query, params)
            total = cursor.fetchone()["cnt"]

            cursor.execute(query, exec_params)
            rows = cursor.fetchall()
            items = [self._row_to_item(r) for r in rows]

        return items, total

    def bulk_add(self, iocs: List[IOCCreateRequest]) -> Tuple[int, int, List[Dict[str, Any]]]:
        """
        Bulk adds up to IOC_MAX_BULK_IMPORT IOCs deterministically.
        Returns (imported_count, rejected_count, error_list).
        """
        if len(iocs) > IOC_MAX_BULK_IMPORT:
            raise ValueError(f"Bulk import exceeds maximum allowed limit of {IOC_MAX_BULK_IMPORT} indicators.")

        imported = 0
        rejected = 0
        errors: List[Dict[str, Any]] = []

        for idx, req in enumerate(iocs):
            try:
                self.add_ioc(req)
                imported += 1
            except Exception as e:
                rejected += 1
                errors.append({
                    "index": idx,
                    "indicator": getattr(req, "indicator", str(req)),
                    "error": str(e)
                })

        return imported, rejected, errors

    def _update_cache(self, ioc_type: str, norm_indicator: str, item: Optional[IOCItem]):
        """Maintains bounded cache size."""
        cache_key = (ioc_type, norm_indicator)
        if len(self._cache) >= IOC_CACHE_MAX_ENTRIES:
            # Evict first key (FIFO)
            first_k = next(iter(self._cache))
            del self._cache[first_k]
        self._cache[cache_key] = item
