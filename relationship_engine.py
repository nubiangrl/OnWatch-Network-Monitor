"""
On Watch Network Monitor
Phase 27A - Relationship Engine Foundation

This module provides the authoritative relationship store and manager used by
discovery, topology, dependency, root-cause, provisioning, and API layers.

Phase 27A is intentionally backward-compatible. Existing legacy relationship
structures may continue to exist while this engine becomes the source of truth.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import os
import threading
from typing import Any, Dict, Iterable, List, Optional, Tuple


ENGINE_VERSION = "27C.1"
DEFAULT_STORE_KEY = "relationship_store"
DEFAULT_DEVICE_INDEX_KEY = "device_relationship_index"
DEFAULT_METADATA_KEY = "relationship_engine"


def utc_now_string() -> str:
    """Return a stable UTC timestamp suitable for JSON persistence."""
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def clean_text(value: Any) -> str:
    """Normalize arbitrary values into safe, stripped text."""
    if value is None:
        return ""
    return str(value).strip()


def clamp_confidence(value: Any, default: int = 0) -> int:
    """Convert confidence to an integer in the inclusive range 0-100."""
    try:
        confidence = int(float(value))
    except (TypeError, ValueError):
        confidence = default
    return max(0, min(100, confidence))


def normalize_bool(value: Any, default: bool = False) -> bool:
    """Normalize common bool-like values."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = clean_text(value).lower()
    if normalized in {"true", "yes", "1", "on", "enabled", "up", "active"}:
        return True
    if normalized in {"false", "no", "0", "off", "disabled", "down", "inactive"}:
        return False
    return default


class RelationshipState(str, Enum):
    LIVE = "LIVE"
    CACHED = "CACHED"
    MANUAL = "MANUAL"
    CONFIGURED = "CONFIGURED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    DISABLED = "DISABLED"
    MAINTENANCE = "MAINTENANCE"


class RelationshipType(str, Enum):
    PHYSICAL = "PHYSICAL"
    LOGICAL = "LOGICAL"
    VIRTUAL = "VIRTUAL"
    MANUAL = "MANUAL"
    VPN = "VPN"
    WIRELESS = "WIRELESS"
    DEPENDENCY = "DEPENDENCY"
    SERVICE = "SERVICE"
    CONTAINER = "CONTAINER"


DEFAULT_SOURCE_PRIORITIES: Dict[str, int] = {
    "CDP": 100,
    "LLDP": 95,
    "SNMP": 90,
    "MANUAL": 80,
    "PROVISIONING": 80,
    "CONFIGURED": 60,
    "ROLE_PATH": 50,
    "CACHED": 40,
    "UNKNOWN": 0,
}


def parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    text = clean_text(value)
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            return datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def normalize_evidence_record(
    value: Any,
    *,
    parent: Any = "",
    child: Any = "",
    relationship_type: Any = RelationshipType.PHYSICAL.value,
    source: Any = "UNKNOWN",
    confidence: Any = 0,
    observed_at: Any = "",
    details: Any = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if isinstance(value, dict):
        record = deepcopy(value)
    else:
        record = {"source": value}

    record_source = normalize_source(record.get("source", source))
    record_confidence = clamp_confidence(record.get("confidence", confidence))
    observed_value = clean_text(record.get("observed_at", record.get("recorded_at", observed_at))) or utc_now_string()
    recorded_value = clean_text(record.get("recorded_at", observed_value)) or observed_value
    details_value = clean_text(record.get("details", record.get("summary", details)))

    record_id = clean_text(record.get("id"))
    if not record_id:
        payload = "|".join(
            [
                clean_text(parent),
                clean_text(child),
                normalize_type(relationship_type),
                record_source,
                observed_value,
                details_value,
            ]
        )
        record_id = f"ev-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:12]}"

    metadata_payload = record.get("metadata")
    if isinstance(metadata_payload, dict):
        record_metadata = deepcopy(metadata_payload)
    else:
        record_metadata = {}
    if isinstance(metadata, dict):
        record_metadata.update(deepcopy(metadata))

    return {
        "id": record_id,
        "source": record_source,
        "confidence": record_confidence,
        "observed_at": observed_value,
        "recorded_at": recorded_value,
        "details": details_value,
        "parent": clean_text(record.get("parent", parent)),
        "child": clean_text(record.get("child", child)),
        "parent_interface": clean_text(record.get("parent_interface", record.get("from_interface", ""))),
        "child_interface": clean_text(record.get("child_interface", record.get("to_interface", ""))),
        "relationship_type": normalize_type(record.get("relationship_type", relationship_type)),
        "metadata": record_metadata,
    }


def normalize_evidence_records(
    value: Any,
    *,
    parent: Any = "",
    child: Any = "",
    relationship_type: Any = RelationshipType.PHYSICAL.value,
    source: Any = "UNKNOWN",
    confidence: Any = 0,
    observed_at: Any = "",
    details: Any = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    if value is None:
        return []

    if isinstance(value, dict):
        candidates: List[Any] = [value]
    elif isinstance(value, (list, tuple, set)):
        candidates = list(value)
    elif isinstance(value, str):
        candidates = [value]
    else:
        candidates = [value]

    normalized: List[Dict[str, Any]] = []
    for candidate in candidates:
        if isinstance(candidate, dict):
            record = normalize_evidence_record(
                candidate,
                parent=parent,
                child=child,
                relationship_type=relationship_type,
                source=source,
                confidence=confidence,
                observed_at=observed_at,
                details=details,
                metadata=metadata,
            )
        else:
            record = normalize_evidence_record(
                candidate,
                parent=parent,
                child=child,
                relationship_type=relationship_type,
                source=source,
                confidence=confidence,
                observed_at=observed_at,
                details=details,
                metadata=metadata,
            )
        if record.get("source") != "UNKNOWN" or record.get("details") or record.get("id"):
            normalized.append(record)
    return normalized


def normalize_history(value: Any) -> List[Dict[str, Any]]:
    if not value:
        return []
    if isinstance(value, list):
        candidates = value
    elif isinstance(value, tuple):
        candidates = list(value)
    elif isinstance(value, dict):
        candidates = [value]
    else:
        return []

    result: List[Dict[str, Any]] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        entry = deepcopy(candidate)
        entry.setdefault("timestamp", utc_now_string())
        entry.setdefault("event", "updated")
        entry.setdefault("details", "")
        result.append(entry)
    return result


def normalize_state(value: Any) -> str:
    raw = clean_text(value).upper().replace("-", "_").replace(" ", "_")
    aliases = {
        "ACTIVE": RelationshipState.LIVE.value,
        "VERIFIED": RelationshipState.LIVE.value,
        "DISCOVERED": RelationshipState.LIVE.value,
        "STALE": RelationshipState.CACHED.value,
        "FALLBACK": RelationshipState.CACHED.value,
        "STATIC": RelationshipState.CONFIGURED.value,
    }
    raw = aliases.get(raw, raw)
    valid = {state.value for state in RelationshipState}
    return raw if raw in valid else RelationshipState.UNKNOWN.value


def normalize_type(value: Any) -> str:
    raw = clean_text(value).upper().replace("-", "_").replace(" ", "_")
    aliases = {
        "INFRASTRUCTURE": RelationshipType.PHYSICAL.value,
        "LINK": RelationshipType.PHYSICAL.value,
        "VM": RelationshipType.VIRTUAL.value,
        "HOST": RelationshipType.VIRTUAL.value,
        "APPLICATION": RelationshipType.SERVICE.value,
    }
    raw = aliases.get(raw, raw)
    valid = {relationship_type.value for relationship_type in RelationshipType}
    return raw if raw in valid else RelationshipType.PHYSICAL.value


def normalize_source(value: Any) -> str:
    source = clean_text(value).upper().replace("-", "_").replace(" ", "_")
    return source or "UNKNOWN"


def normalize_evidence_sources(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        candidates = [item for item in value.replace(";", ",").split(",")]
    elif isinstance(value, (list, tuple, set)):
        candidates = list(value)
    else:
        candidates = [value]

    result: List[str] = []
    for candidate in candidates:
        source = normalize_source(candidate)
        if source and source not in result and source != "UNKNOWN":
            result.append(source)
    return result


def relationship_identity_key(
    parent: Any,
    child: Any,
    relationship_type: Any = RelationshipType.PHYSICAL.value,
    parent_interface: Any = "",
    child_interface: Any = "",
) -> Tuple[str, str, str, str, str]:
    return (
        clean_text(parent),
        clean_text(child),
        normalize_type(relationship_type),
        clean_text(parent_interface),
        clean_text(child_interface),
    )


def stable_relationship_id(
    parent: Any,
    child: Any,
    relationship_type: Any = RelationshipType.PHYSICAL.value,
    parent_interface: Any = "",
    child_interface: Any = "",
) -> str:
    """Generate a stable relationship ID from immutable relationship identity."""
    identity = "|".join(
        relationship_identity_key(
            parent,
            child,
            relationship_type,
            parent_interface,
            child_interface,
        )
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return f"rel-{digest}"


@dataclass
class Relationship:
    id: str
    parent: str
    child: str
    parent_interface: str = ""
    child_interface: str = ""
    relationship_type: str = RelationshipType.PHYSICAL.value
    relationship_state: str = RelationshipState.UNKNOWN.value
    confidence: int = 0
    currently_verified: bool = False
    active: bool = True
    evidence_sources: List[str] = field(default_factory=list)
    evidence_records: List[Dict[str, Any]] = field(default_factory=list)
    evidence_id: str = ""
    source: str = "UNKNOWN"
    priority: int = 0
    created_at: str = field(default_factory=utc_now_string)
    updated_at: str = field(default_factory=utc_now_string)
    last_verified_at: str = ""
    last_seen_at: str = ""
    state_details: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    history: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(
        cls,
        raw: Dict[str, Any],
        relationship_id: Optional[str] = None,
    ) -> "Relationship":
        if not isinstance(raw, dict):
            raise TypeError("Relationship data must be a dictionary.")

        parent = clean_text(raw.get("parent", raw.get("from", "")))
        child = clean_text(raw.get("child", raw.get("to", "")))
        parent_interface = clean_text(
            raw.get(
                "parent_interface",
                raw.get("from_interface", raw.get("local_interface", "")),
            )
        )
        child_interface = clean_text(
            raw.get(
                "child_interface",
                raw.get("to_interface", raw.get("remote_interface", "")),
            )
        )
        relationship_type = normalize_type(
            raw.get("relationship_type", raw.get("type", "PHYSICAL"))
        )

        rid = clean_text(
            relationship_id
            or raw.get("id")
            or raw.get("relationship_id")
            or stable_relationship_id(
                parent,
                child,
                relationship_type,
                parent_interface,
                child_interface,
            )
        )

        source = normalize_source(
            raw.get(
                "source",
                raw.get("selection_source", raw.get("discovery_source", "UNKNOWN")),
            )
        )

        evidence_sources = normalize_evidence_sources(
            raw.get("evidence_sources", raw.get("evidence", []))
        )
        if source != "UNKNOWN" and source not in evidence_sources:
            evidence_sources.append(source)

        active = normalize_bool(raw.get("active", True), default=True)
        confidence = clamp_confidence(raw.get("confidence", 0))

        evidence_records = normalize_evidence_records(
            raw.get(
                "evidence_records",
                raw.get("evidence_history", raw.get("evidence", [])),
            ),
            parent=parent,
            child=child,
            relationship_type=relationship_type,
            source=source,
            confidence=confidence,
            observed_at=raw.get("last_verified_at") or raw.get("last_seen_at") or raw.get("updated_at") or utc_now_string(),
            details=clean_text(raw.get("state_details", raw.get("relationship_state_details", ""))),
            metadata=deepcopy(raw.get("metadata", {})) if isinstance(raw.get("metadata", {}), dict) else {},
        )
        if not evidence_records and evidence_sources:
            evidence_records = [
                normalize_evidence_record(
                    {
                        "source": evidence_source,
                        "confidence": confidence,
                        "observed_at": raw.get("last_verified_at") or raw.get("last_seen_at") or raw.get("updated_at") or utc_now_string(),
                        "details": clean_text(raw.get("state_details", raw.get("relationship_state_details", ""))),
                    },
                    parent=parent,
                    child=child,
                    relationship_type=relationship_type,
                    source=evidence_source,
                    confidence=confidence,
                    observed_at=raw.get("last_verified_at") or raw.get("last_seen_at") or raw.get("updated_at") or utc_now_string(),
                    details=clean_text(raw.get("state_details", raw.get("relationship_state_details", ""))),
                    metadata=deepcopy(raw.get("metadata", {})) if isinstance(raw.get("metadata", {}), dict) else {},
                )
                for evidence_source in evidence_sources
            ]

        state = normalize_state(
            raw.get("relationship_state", raw.get("state", "UNKNOWN"))
        )

        currently_verified = normalize_bool(
            raw.get(
                "currently_verified",
                raw.get("verified", raw.get("active", state == "LIVE")),
            )
        )

        priority = raw.get("priority")
        if priority is None:
            priority = DEFAULT_SOURCE_PRIORITIES.get(source, confidence)
        try:
            priority = int(priority)
        except (TypeError, ValueError):
            priority = DEFAULT_SOURCE_PRIORITIES.get(source, confidence)

        metadata = deepcopy(raw.get("metadata", {}))
        if not isinstance(metadata, dict):
            metadata = {"legacy_metadata": metadata}

        known_keys = {
            "id",
            "relationship_id",
            "parent",
            "child",
            "from",
            "to",
            "parent_interface",
            "child_interface",
            "from_interface",
            "to_interface",
            "local_interface",
            "remote_interface",
            "relationship_type",
            "type",
            "relationship_state",
            "state",
            "confidence",
            "currently_verified",
            "verified",
            "active",
            "evidence_sources",
            "evidence",
            "evidence_id",
            "source",
            "selection_source",
            "discovery_source",
            "priority",
            "created_at",
            "updated_at",
            "last_verified_at",
            "last_seen_at",
            "relationship_state_details",
            "state_details",
            "metadata",
        }
        for key, value in raw.items():
            if key not in known_keys and key not in metadata:
                metadata[key] = deepcopy(value)

        created_at = clean_text(raw.get("created_at")) or utc_now_string()
        updated_at = clean_text(raw.get("updated_at")) or created_at
        last_verified_at = clean_text(raw.get("last_verified_at"))
        last_seen_at = clean_text(raw.get("last_seen_at"))
        state_details = clean_text(
            raw.get(
                "relationship_state_details",
                raw.get("state_details", ""),
            )
        )
        history = normalize_history(
            raw.get("history", raw.get("change_history", raw.get("relationship_history", [])))
        )

        return cls(
            id=rid,
            parent=parent,
            child=child,
            parent_interface=parent_interface,
            child_interface=child_interface,
            relationship_type=relationship_type,
            relationship_state=state,
            confidence=confidence,
            currently_verified=currently_verified,
            active=active,
            evidence_sources=evidence_sources,
            evidence_records=evidence_records,
            evidence_id=clean_text(raw.get("evidence_id")),
            source=source,
            priority=priority,
            created_at=created_at,
            updated_at=updated_at,
            last_verified_at=last_verified_at,
            last_seen_at=last_seen_at,
            state_details=state_details,
            metadata=metadata,
            history=history,
        )

    def validate(self) -> None:
        if not self.id:
            raise ValueError("Relationship id is required.")
        if not self.parent:
            raise ValueError("Relationship parent is required.")
        if not self.child:
            raise ValueError("Relationship child is required.")
        if self.parent == self.child:
            raise ValueError("Relationship parent and child cannot be identical.")

    def touch(self) -> None:
        self.updated_at = utc_now_string()

    def identity_key(self) -> Tuple[str, str, str, str, str]:
        return relationship_identity_key(
            self.parent,
            self.child,
            self.relationship_type,
            self.parent_interface,
            self.child_interface,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "parent": self.parent,
            "child": self.child,
            "parent_interface": self.parent_interface,
            "child_interface": self.child_interface,
            "relationship_type": self.relationship_type,
            "relationship_state": self.relationship_state,
            "relationship_state_details": self.state_details,
            "confidence": self.confidence,
            "currently_verified": self.currently_verified,
            "active": self.active,
            "evidence_sources": list(self.evidence_sources),
            "evidence_records": [deepcopy(item) for item in self.evidence_records],
            "evidence_id": self.evidence_id,
            "source": self.source,
            "priority": self.priority,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_verified_at": self.last_verified_at,
            "last_seen_at": self.last_seen_at,
            "metadata": deepcopy(self.metadata),
            "history": [deepcopy(item) for item in self.history],
        }


class RelationshipStore:
    """Thread-safe in-memory relationship store with config persistence."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: Optional[str] = None,
        store_key: str = DEFAULT_STORE_KEY,
        device_index_key: str = DEFAULT_DEVICE_INDEX_KEY,
        metadata_key: str = DEFAULT_METADATA_KEY,
        autosave: bool = False,
    ) -> None:
        self.config = config if isinstance(config, dict) else {}
        self.config_path = config_path
        self.store_key = store_key
        self.device_index_key = device_index_key
        self.metadata_key = metadata_key
        self.autosave = bool(autosave)
        self._lock = threading.RLock()
        self._relationships: Dict[str, Relationship] = {}
        self._identity_index: Dict[Tuple[str, str, str, str, str], str] = {}
        self._device_index: Dict[str, List[str]] = {}
        self.load_from_config()

    def _ensure_config_structure(self) -> None:
        self.config.setdefault(self.store_key, {})
        self.config.setdefault(self.device_index_key, {})
        metadata = self.config.setdefault(self.metadata_key, {})
        metadata.setdefault("phase", "27A")
        metadata.setdefault("engine_version", ENGINE_VERSION)
        metadata.setdefault("created_at", utc_now_string())
        metadata.setdefault("updated_at", utc_now_string())
        metadata.setdefault("relationship_count", 0)
        metadata.setdefault("migration_complete", False)

    def load_from_config(self) -> None:
        with self._lock:
            self._ensure_config_structure()
            self._relationships.clear()
            self._identity_index.clear()
            self._device_index.clear()

            raw_store = self.config.get(self.store_key, {})
            if isinstance(raw_store, list):
                raw_store = {
                    clean_text(item.get("id")) or f"legacy-{index}": item
                    for index, item in enumerate(raw_store)
                    if isinstance(item, dict)
                }
            if not isinstance(raw_store, dict):
                raw_store = {}

            for relationship_id, raw in raw_store.items():
                if not isinstance(raw, dict):
                    continue
                try:
                    relationship = Relationship.from_dict(raw, relationship_id)
                    relationship.validate()
                except (TypeError, ValueError):
                    continue
                self._relationships[relationship.id] = relationship

            self._rebuild_indexes()
            self.sync_to_config(save=False)

    def _rebuild_indexes(self) -> None:
        self._identity_index.clear()
        self._device_index.clear()

        for relationship_id, relationship in self._relationships.items():
            self._identity_index[relationship.identity_key()] = relationship_id
            for device_name in (relationship.parent, relationship.child):
                self._device_index.setdefault(device_name, [])
                if relationship_id not in self._device_index[device_name]:
                    self._device_index[device_name].append(relationship_id)

        for relationship_ids in self._device_index.values():
            relationship_ids.sort()

    def sync_to_config(self, save: Optional[bool] = None) -> None:
        with self._lock:
            self._ensure_config_structure()
            self.config[self.store_key] = {
                relationship_id: relationship.to_dict()
                for relationship_id, relationship in sorted(
                    self._relationships.items(),
                    key=lambda item: item[0],
                )
            }
            self.config[self.device_index_key] = deepcopy(self._device_index)
            metadata = self.config[self.metadata_key]
            metadata["phase"] = "27A"
            metadata["engine_version"] = ENGINE_VERSION
            metadata["updated_at"] = utc_now_string()
            metadata["relationship_count"] = len(self._relationships)

            should_save = self.autosave if save is None else bool(save)
            if should_save:
                self.save_config_file()

    def save_config_file(self) -> None:
        if not self.config_path:
            return

        config_path = os.path.abspath(self.config_path)
        directory = os.path.dirname(config_path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        temporary_path = f"{config_path}.tmp"
        with open(temporary_path, "w", encoding="utf-8") as handle:
            json.dump(self.config, handle, indent=2, sort_keys=False)
            handle.write("\n")
        os.replace(temporary_path, config_path)

    def get(self, relationship_id: str) -> Optional[Relationship]:
        with self._lock:
            relationship = self._relationships.get(clean_text(relationship_id))
            return deepcopy(relationship) if relationship else None

    def get_mutable(self, relationship_id: str) -> Optional[Relationship]:
        """Internal manager access. Callers must hold the store lock."""
        return self._relationships.get(clean_text(relationship_id))

    def all(self) -> List[Relationship]:
        with self._lock:
            return [deepcopy(item) for item in self._relationships.values()]

    def count(self) -> int:
        with self._lock:
            return len(self._relationships)

    def find_by_identity(
        self,
        parent: Any,
        child: Any,
        relationship_type: Any = RelationshipType.PHYSICAL.value,
        parent_interface: Any = "",
        child_interface: Any = "",
    ) -> Optional[Relationship]:
        identity = relationship_identity_key(
            parent,
            child,
            relationship_type,
            parent_interface,
            child_interface,
        )
        with self._lock:
            relationship_id = self._identity_index.get(identity)
            relationship = self._relationships.get(relationship_id or "")
            return deepcopy(relationship) if relationship else None

    def relationship_ids_for_device(self, device_name: Any) -> List[str]:
        with self._lock:
            return list(self._device_index.get(clean_text(device_name), []))

    def relationships_for_device(self, device_name: Any) -> List[Relationship]:
        with self._lock:
            ids = self._device_index.get(clean_text(device_name), [])
            return [
                deepcopy(self._relationships[relationship_id])
                for relationship_id in ids
                if relationship_id in self._relationships
            ]

    def upsert(self, relationship: Relationship, save: Optional[bool] = None) -> Relationship:
        relationship.validate()
        with self._lock:
            existing = self._relationships.get(relationship.id)
            if existing and not relationship.created_at:
                relationship.created_at = existing.created_at
            relationship.touch()
            self._relationships[relationship.id] = deepcopy(relationship)
            self._rebuild_indexes()
            self.sync_to_config(save=save)
            return deepcopy(self._relationships[relationship.id])

    def remove(self, relationship_id: str, save: Optional[bool] = None) -> bool:
        with self._lock:
            relationship_id = clean_text(relationship_id)
            if relationship_id not in self._relationships:
                return False
            self._relationships.pop(relationship_id, None)
            self._rebuild_indexes()
            self.sync_to_config(save=save)
            return True

    def remove_device(self, device_name: Any, save: Optional[bool] = None) -> int:
        device_name = clean_text(device_name)
        with self._lock:
            relationship_ids = list(self._device_index.get(device_name, []))
            for relationship_id in relationship_ids:
                self._relationships.pop(relationship_id, None)
            if relationship_ids:
                self._rebuild_indexes()
                self.sync_to_config(save=save)
            return len(relationship_ids)

    def clear(self, save: Optional[bool] = None) -> None:
        with self._lock:
            self._relationships.clear()
            self._rebuild_indexes()
            self.sync_to_config(save=save)

    def export_dict(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {
                relationship_id: relationship.to_dict()
                for relationship_id, relationship in self._relationships.items()
            }


class RelationshipManager:
    """Only supported write interface for relationship lifecycle operations."""

    def __init__(
        self,
        store: RelationshipStore,
        source_priorities: Optional[Dict[str, int]] = None,
    ) -> None:
        self.store = store
        self.source_priorities = dict(DEFAULT_SOURCE_PRIORITIES)
        if isinstance(source_priorities, dict):
            for source, priority in source_priorities.items():
                try:
                    self.source_priorities[normalize_source(source)] = int(priority)
                except (TypeError, ValueError):
                    continue

    def _priority_for(self, source: str, confidence: int) -> int:
        return self.source_priorities.get(
            normalize_source(source),
            clamp_confidence(confidence),
        )

    def _append_history_entry(
        self,
        relationship: Relationship,
        event: str,
        *,
        previous: Optional[Dict[str, Any]] = None,
        current: Optional[Dict[str, Any]] = None,
        details: Any = "",
        source: Any = "",
    ) -> None:
        entry = {
            "timestamp": utc_now_string(),
            "event": clean_text(event) or "updated",
            "details": clean_text(details),
            "source": normalize_source(source or relationship.source),
            "previous": deepcopy(previous) if isinstance(previous, dict) else previous,
            "current": deepcopy(current) if isinstance(current, dict) else current,
        }
        relationship.history = list(relationship.history or [])
        relationship.history.append(entry)
        if len(relationship.history) > 50:
            relationship.history = relationship.history[-50:]

    def _score_evidence_record(
        self,
        relationship: Relationship,
        record: Dict[str, Any],
        evidence_count: int,
    ) -> int:
        source_priority = self._priority_for(record.get("source", "UNKNOWN"), relationship.confidence)
        record_confidence = clamp_confidence(record.get("confidence", relationship.confidence))
        agreement_bonus = min(20, 5 * max(0, evidence_count - 1))
        freshness_bonus = 0
        observed_at = record.get("observed_at") or record.get("recorded_at") or relationship.last_verified_at or relationship.last_seen_at or relationship.updated_at
        parsed_observed = parse_timestamp(observed_at)
        if parsed_observed is not None:
            age_hours = max(0.0, (datetime.utcnow() - parsed_observed).total_seconds() / 3600.0)
            if age_hours <= 1:
                freshness_bonus = 15
            elif age_hours <= 24:
                freshness_bonus = 10
            elif age_hours <= 72:
                freshness_bonus = 5
        stability_bonus = min(10, 2 * max(0, evidence_count - 1))
        base_score = max(source_priority, record_confidence)
        return int(
            min(
                100,
                (base_score * 0.6) + agreement_bonus + freshness_bonus + stability_bonus,
            )
        )

    def _score_relationship_confidence(self, relationship: Relationship) -> int:
        if not relationship.evidence_records:
            return clamp_confidence(relationship.confidence)

        evidence_count = len(relationship.evidence_records)
        record_scores = [
            self._score_evidence_record(relationship, record, evidence_count)
            for record in relationship.evidence_records
        ]
        agreement_bonus = min(15, 3 * max(0, evidence_count - 1))
        freshness_bonus = 0
        latest_observed = ""
        for record in relationship.evidence_records:
            observed_at = record.get("observed_at") or record.get("recorded_at") or relationship.updated_at
            if not latest_observed or (observed_at and observed_at > latest_observed):
                latest_observed = observed_at
        parsed_latest = parse_timestamp(latest_observed)
        if parsed_latest is not None:
            age_hours = max(0.0, (datetime.utcnow() - parsed_latest).total_seconds() / 3600.0)
            if age_hours <= 1:
                freshness_bonus = 15
            elif age_hours <= 24:
                freshness_bonus = 10
            elif age_hours <= 72:
                freshness_bonus = 5
        stability_bonus = min(10, 2 * max(0, evidence_count - 1))
        verified_bonus = 10 if relationship.currently_verified else 0
        active_bonus = 5 if relationship.active else 0
        average_score = int(sum(record_scores) / max(1, len(record_scores)))
        combined = average_score + agreement_bonus + freshness_bonus + stability_bonus + verified_bonus + active_bonus
        return clamp_confidence(max(relationship.confidence, combined))

    def _coerce_relationship(self, candidate: Any) -> Optional[Relationship]:
        if isinstance(candidate, Relationship):
            return candidate
        if isinstance(candidate, dict):
            try:
                return Relationship.from_dict(candidate)
            except (TypeError, ValueError):
                return None
        return None

    def _candidate_relationships(
        self,
        parent: Any,
        child: Any,
        relationship_type: Any,
        *,
        parent_interface: Any = "",
        child_interface: Any = "",
    ) -> List[Relationship]:
        parent = clean_text(parent)
        child = clean_text(child)
        relationship_type = normalize_type(relationship_type)
        parent_interface = clean_text(parent_interface)
        child_interface = clean_text(child_interface)
        candidates: List[Relationship] = []
        for relationship in self.store.all():
            if relationship.parent != parent or relationship.child != child:
                continue
            if relationship.relationship_type != relationship_type:
                continue
            if parent_interface and relationship.parent_interface and relationship.parent_interface != parent_interface:
                continue
            if child_interface and relationship.child_interface and relationship.child_interface != child_interface:
                continue
            candidates.append(relationship)
        return sorted(
            candidates,
            key=lambda item: (
                item.updated_at,
                item.priority,
                item.confidence,
                len(item.evidence_records),
            ),
            reverse=True,
        )

    def _relationship_selection_score(self, relationship: Relationship) -> int:
        verified_bonus = 25 if relationship.currently_verified else 0
        active_bonus = 10 if relationship.active else 0
        evidence_bonus = min(20, len(relationship.evidence_records) * 4)
        freshness_bonus = 0
        latest_observed = relationship.last_verified_at or relationship.last_seen_at or relationship.updated_at
        parsed_latest = parse_timestamp(latest_observed)
        if parsed_latest is not None:
            age_hours = max(0.0, (datetime.utcnow() - parsed_latest).total_seconds() / 3600.0)
            if age_hours <= 1:
                freshness_bonus = 15
            elif age_hours <= 24:
                freshness_bonus = 10
            elif age_hours <= 72:
                freshness_bonus = 5
        stability_bonus = min(10, max(0, len(relationship.evidence_records) - 1) * 2)
        return (
            relationship.confidence
            + verified_bonus
            + active_bonus
            + evidence_bonus
            + freshness_bonus
            + stability_bonus
            + relationship.priority
        )

    def select_canonical_relationship(
        self,
        candidates: Iterable[Any],
        *,
        default: Optional[Relationship] = None,
    ) -> Optional[Relationship]:
        normalized: List[Relationship] = []
        for candidate in candidates:
            relationship = self._coerce_relationship(candidate)
            if relationship is None:
                continue
            normalized.append(relationship)

        if not normalized:
            return default

        normalized.sort(
            key=lambda item: (
                self._relationship_selection_score(item),
                len(item.evidence_records),
                item.priority,
                item.confidence,
                item.updated_at,
            ),
            reverse=True,
        )
        return normalized[0]

    def _relationships_conflict(self, left: Relationship, right: Relationship) -> bool:
        if left.parent != right.parent or left.child != right.child:
            return False
        if left.relationship_type != right.relationship_type:
            return False
        if left.parent_interface and right.parent_interface and left.parent_interface != right.parent_interface:
            return True
        if left.child_interface and right.child_interface and left.child_interface != right.child_interface:
            return True
        if (
            left.relationship_state != right.relationship_state
            and left.relationship_state != RelationshipState.UNKNOWN.value
            and right.relationship_state != RelationshipState.UNKNOWN.value
        ):
            return True
        return False

    def reconcile_relationships(
        self,
        relationships: Iterable[Any],
        *,
        save: Optional[bool] = None,
    ) -> Dict[str, Any]:
        normalized: List[Relationship] = []
        for relationship in relationships:
            candidate = self._coerce_relationship(relationship)
            if candidate is not None:
                normalized.append(candidate)

        if not normalized:
            return {
                "relationship": None,
                "canonical_id": "",
                "conflicts": [],
                "selected": False,
            }

        canonical = self.select_canonical_relationship(normalized)
        if canonical is None:
            canonical = normalized[0]

        conflicts = []
        for candidate in normalized:
            if candidate.id == canonical.id:
                continue
            if self._relationships_conflict(candidate, canonical):
                conflicts.append(
                    {
                        "candidate_id": candidate.id,
                        "canonical_id": canonical.id,
                        "parent_interface": candidate.parent_interface,
                        "child_interface": candidate.child_interface,
                        "relationship_state": candidate.relationship_state,
                    }
                )

        canonical.metadata = deepcopy(canonical.metadata or {})
        canonical.metadata["reconciliation"] = {
            "canonical_id": canonical.id,
            "conflict_count": len(conflicts),
            "conflicts": conflicts,
            "reconciled_at": utc_now_string(),
            "evidence_count": len(canonical.evidence_records),
        }
        canonical.confidence = self._score_relationship_confidence(canonical)
        canonical.touch()
        self._append_history_entry(
            canonical,
            "reconciled",
            previous={"candidate_count": len(normalized)},
            current={"canonical_id": canonical.id, "conflict_count": len(conflicts)},
            details="Canonical relationship selected after reconciliation",
            source=canonical.source,
        )
        upserted = self.store.upsert(canonical, save=False)
        self.store.sync_to_config(save=save)
        return {
            "relationship": upserted,
            "canonical_id": upserted.id,
            "conflicts": conflicts,
            "selected": True,
        }

    def record_evidence(
        self,
        parent: Any,
        child: Any,
        *,
        parent_interface: Any = "",
        child_interface: Any = "",
        relationship_type: Any = RelationshipType.PHYSICAL.value,
        relationship_state: Any = RelationshipState.UNKNOWN.value,
        confidence: Any = 0,
        currently_verified: Any = False,
        active: Any = True,
        source: Any = "UNKNOWN",
        evidence_id: Any = "",
        observed_at: Any = "",
        details: Any = "",
        metadata: Optional[Dict[str, Any]] = None,
        relationship_id: Any = "",
        save: Optional[bool] = None,
    ) -> Relationship:
        parent = clean_text(parent)
        child = clean_text(child)
        parent_interface = clean_text(parent_interface)
        child_interface = clean_text(child_interface)
        relationship_type = normalize_type(relationship_type)
        source = normalize_source(source)
        confidence = clamp_confidence(confidence)
        observed_at = clean_text(observed_at) or utc_now_string()
        details = clean_text(details)
        relationship_id = clean_text(relationship_id)

        relationship = None
        if relationship_id:
            relationship = self.store.get(relationship_id)
        if relationship is None:
            relationship = self.find_relationship(
                relationship_id=relationship_id,
                parent=parent,
                child=child,
                relationship_type=relationship_type,
                parent_interface=parent_interface,
                child_interface=child_interface,
            )

        if relationship is None:
            relationship = self.create_relationship(
                parent,
                child,
                parent_interface=parent_interface,
                child_interface=child_interface,
                relationship_type=relationship_type,
                relationship_state=relationship_state,
                confidence=confidence,
                currently_verified=currently_verified,
                active=active,
                evidence_sources=[source] if source != "UNKNOWN" else [],
                evidence_id=evidence_id,
                source=source,
                state_details=details,
                metadata=metadata,
                relationship_id=relationship_id,
                save=False,
            )
        else:
            relationship = deepcopy(relationship)

        record = normalize_evidence_record(
            {
                "id": clean_text(evidence_id),
                "source": source,
                "confidence": confidence,
                "observed_at": observed_at,
                "details": details,
                "metadata": deepcopy(metadata) if isinstance(metadata, dict) else {},
            },
            parent=parent,
            child=child,
            relationship_type=relationship_type,
            source=source,
            confidence=confidence,
            observed_at=observed_at,
            details=details,
            metadata=deepcopy(metadata) if isinstance(metadata, dict) else {},
        )
        existing_ids = {item.get("id", "") for item in relationship.evidence_records}
        if record["id"] in existing_ids:
            for index, existing in enumerate(relationship.evidence_records):
                if existing.get("id") == record["id"]:
                    relationship.evidence_records[index] = record
                    break
        else:
            relationship.evidence_records.append(record)

        relationship.evidence_sources = normalize_evidence_sources(
            [
                *relationship.evidence_sources,
                source,
                *[item.get("source", "") for item in relationship.evidence_records],
            ]
        )
        if source != "UNKNOWN" and source not in relationship.evidence_sources:
            relationship.evidence_sources.append(source)

        relationship.relationship_state = normalize_state(relationship_state)
        relationship.currently_verified = normalize_bool(currently_verified) or relationship.relationship_state == RelationshipState.LIVE.value
        relationship.active = normalize_bool(active, default=relationship.active)
        relationship.last_seen_at = observed_at if observed_at else relationship.last_seen_at or utc_now_string()
        if relationship.currently_verified:
            relationship.last_verified_at = observed_at if observed_at else relationship.last_verified_at or utc_now_string()

        relationship.confidence = self._score_relationship_confidence(relationship)
        relationship.priority = max(
            relationship.priority,
            self._priority_for(relationship.source or source, relationship.confidence),
        )
        relationship.source = relationship.source or source or "UNKNOWN"
        relationship.metadata = deepcopy(relationship.metadata or {})
        relationship.metadata.setdefault("evidence_engine", {})
        relationship.metadata["evidence_engine"]["last_recorded_at"] = utc_now_string()
        relationship.metadata["evidence_engine"]["record_count"] = len(relationship.evidence_records)
        relationship.metadata["evidence_engine"]["last_source"] = relationship.source
        relationship.touch()
        self._append_history_entry(
            relationship,
            "evidence_recorded",
            previous={"confidence": relationship.confidence},
            current={"confidence": relationship.confidence, "evidence_count": len(relationship.evidence_records)},
            details=details,
            source=relationship.source,
        )

        related_candidates = self._candidate_relationships(
            parent,
            child,
            relationship_type,
            parent_interface=parent_interface,
            child_interface=child_interface,
        )
        related_candidates = [item for item in related_candidates if item.id != relationship.id]
        related_candidates.append(relationship)
        reconciliation = self.reconcile_relationships(related_candidates, save=False)
        final_relationship = reconciliation.get("relationship") or relationship
        if save is not None:
            self.store.upsert(final_relationship, save=save)
        else:
            self.store.upsert(final_relationship, save=False)
        return self.store.get(final_relationship.id) or final_relationship

    def create_relationship(
        self,
        parent: Any,
        child: Any,
        *,
        parent_interface: Any = "",
        child_interface: Any = "",
        relationship_type: Any = RelationshipType.PHYSICAL.value,
        relationship_state: Any = RelationshipState.UNKNOWN.value,
        confidence: Any = 0,
        currently_verified: Any = False,
        active: Any = True,
        evidence_sources: Any = None,
        evidence_id: Any = "",
        source: Any = "UNKNOWN",
        priority: Optional[int] = None,
        state_details: Any = "",
        metadata: Optional[Dict[str, Any]] = None,
        relationship_id: Optional[str] = None,
        save: Optional[bool] = None,
    ) -> Relationship:
        parent = clean_text(parent)
        child = clean_text(child)
        parent_interface = clean_text(parent_interface)
        child_interface = clean_text(child_interface)
        relationship_type = normalize_type(relationship_type)
        source = normalize_source(source)
        confidence = clamp_confidence(confidence)

        if not relationship_id:
            relationship_id = stable_relationship_id(
                parent,
                child,
                relationship_type,
                parent_interface,
                child_interface,
            )

        now_value = utc_now_string()
        currently_verified = normalize_bool(currently_verified)
        evidence_sources = normalize_evidence_sources(evidence_sources)
        if source != "UNKNOWN" and source not in evidence_sources:
            evidence_sources.append(source)

        if priority is None:
            priority = self._priority_for(source, confidence)

        relationship = Relationship(
            id=clean_text(relationship_id),
            parent=parent,
            child=child,
            parent_interface=parent_interface,
            child_interface=child_interface,
            relationship_type=relationship_type,
            relationship_state=normalize_state(relationship_state),
            confidence=confidence,
            currently_verified=currently_verified,
            active=normalize_bool(active, default=True),
            evidence_sources=evidence_sources,
            evidence_records=[],
            evidence_id=clean_text(evidence_id),
            source=source,
            priority=int(priority),
            created_at=now_value,
            updated_at=now_value,
            last_verified_at=now_value if currently_verified else "",
            last_seen_at=now_value if currently_verified else "",
            state_details=clean_text(state_details),
            metadata=deepcopy(metadata) if isinstance(metadata, dict) else {},
            history=[],
        )
        self._append_history_entry(
            relationship,
            "created",
            previous={},
            current={"confidence": relationship.confidence, "source": relationship.source},
            details=clean_text(state_details),
            source=relationship.source,
        )
        return self.store.upsert(relationship, save=save)

    def upsert_relationship(
        self,
        data: Dict[str, Any],
        *,
        save: Optional[bool] = None,
        prefer_higher_priority: bool = True,
    ) -> Relationship:
        candidate = Relationship.from_dict(data)
        candidate.validate()

        existing = self.store.get(candidate.id)
        if not existing:
            identity_match = self.store.find_by_identity(
                candidate.parent,
                candidate.child,
                candidate.relationship_type,
                candidate.parent_interface,
                candidate.child_interface,
            )
            existing = identity_match

        if not existing:
            self._append_history_entry(
                candidate,
                "upserted",
                previous={},
                current={"confidence": candidate.confidence, "source": candidate.source},
                details="Relationship created through upsert",
                source=candidate.source,
            )
            return self.store.upsert(candidate, save=save)

        if prefer_higher_priority and candidate.priority < existing.priority:
            merged = self._merge_relationships(existing, candidate, preserve_primary=True)
        else:
            merged = self._merge_relationships(candidate, existing, preserve_primary=True)

        merged.id = existing.id
        merged.created_at = existing.created_at
        self._append_history_entry(
            merged,
            "merged",
            previous={"confidence": existing.confidence},
            current={"confidence": merged.confidence, "source": merged.source},
            details="Relationship merged during upsert",
            source=merged.source,
        )
        return self.store.upsert(merged, save=save)

    def _merge_relationships(
        self,
        primary: Relationship,
        secondary: Relationship,
        *,
        preserve_primary: bool = True,
    ) -> Relationship:
        merged = deepcopy(primary if preserve_primary else secondary)
        other = secondary if preserve_primary else primary

        merged.confidence = max(primary.confidence, secondary.confidence)
        merged.priority = max(primary.priority, secondary.priority)
        merged.currently_verified = (
            primary.currently_verified or secondary.currently_verified
        )
        merged.active = primary.active or secondary.active

        evidence = list(primary.evidence_sources)
        for source in secondary.evidence_sources:
            if source not in evidence:
                evidence.append(source)
        merged.evidence_sources = evidence

        if not merged.parent_interface:
            merged.parent_interface = other.parent_interface
        if not merged.child_interface:
            merged.child_interface = other.child_interface
        if not merged.evidence_id:
            merged.evidence_id = other.evidence_id
        if not merged.last_verified_at:
            merged.last_verified_at = other.last_verified_at
        if not merged.last_seen_at:
            merged.last_seen_at = other.last_seen_at
        if not merged.state_details:
            merged.state_details = other.state_details

        merged.metadata = deepcopy(other.metadata)
        merged.metadata.update(deepcopy(primary.metadata))
        merged.updated_at = utc_now_string()
        return merged

    def update_relationship(
        self,
        relationship_id: Any,
        *,
        save: Optional[bool] = None,
        **changes: Any,
    ) -> Relationship:
        relationship_id = clean_text(relationship_id)
        existing = self.store.get(relationship_id)
        if not existing:
            raise KeyError(f"Relationship not found: {relationship_id}")

        allowed_fields = {
            "parent",
            "child",
            "parent_interface",
            "child_interface",
            "relationship_type",
            "relationship_state",
            "confidence",
            "currently_verified",
            "active",
            "evidence_sources",
            "evidence_id",
            "source",
            "priority",
            "last_verified_at",
            "last_seen_at",
            "state_details",
            "metadata",
        }

        for field_name, value in changes.items():
            if field_name not in allowed_fields:
                continue

            if field_name in {"parent", "child", "parent_interface", "child_interface"}:
                setattr(existing, field_name, clean_text(value))
            elif field_name == "relationship_type":
                existing.relationship_type = normalize_type(value)
            elif field_name == "relationship_state":
                existing.relationship_state = normalize_state(value)
            elif field_name == "confidence":
                existing.confidence = clamp_confidence(value)
            elif field_name in {"currently_verified", "active"}:
                setattr(existing, field_name, normalize_bool(value))
            elif field_name == "evidence_sources":
                existing.evidence_sources = normalize_evidence_sources(value)
            elif field_name == "source":
                existing.source = normalize_source(value)
            elif field_name == "priority":
                try:
                    existing.priority = int(value)
                except (TypeError, ValueError):
                    pass
            elif field_name == "metadata":
                if isinstance(value, dict):
                    existing.metadata = deepcopy(value)
            else:
                setattr(existing, field_name, clean_text(value))

        existing.touch()
        existing.validate()
        self._append_history_entry(
            existing,
            "updated",
            previous={"changes": sorted(changes.keys())},
            current={"confidence": existing.confidence, "source": existing.source},
            details="Relationship updated",
            source=existing.source,
        )
        return self.store.upsert(existing, save=save)

    def delete_relationship(
        self,
        relationship_id: Any,
        *,
        save: Optional[bool] = None,
    ) -> bool:
        return self.store.remove(clean_text(relationship_id), save=save)

    def delete_device_relationships(
        self,
        device_name: Any,
        *,
        save: Optional[bool] = None,
    ) -> int:
        return self.store.remove_device(device_name, save=save)

    def verify_relationship(
        self,
        relationship_id: Any,
        *,
        source: Any = "",
        confidence: Any = None,
        evidence_id: Any = "",
        state_details: Any = "",
        save: Optional[bool] = None,
    ) -> Relationship:
        existing = self.store.get(clean_text(relationship_id))
        if not existing:
            raise KeyError(f"Relationship not found: {relationship_id}")

        now_value = utc_now_string()
        existing.currently_verified = True
        existing.active = True
        existing.relationship_state = RelationshipState.LIVE.value
        existing.last_verified_at = now_value
        existing.last_seen_at = now_value

        source = normalize_source(source)
        if source != "UNKNOWN":
            existing.source = source
            if source not in existing.evidence_sources:
                existing.evidence_sources.append(source)
            existing.priority = max(
                existing.priority,
                self._priority_for(source, existing.confidence),
            )

        if confidence is not None:
            existing.confidence = clamp_confidence(confidence)

        if clean_text(evidence_id):
            existing.evidence_id = clean_text(evidence_id)

        if clean_text(state_details):
            existing.state_details = clean_text(state_details)

        existing.touch()
        return self.store.upsert(existing, save=save)

    def mark_cached(
        self,
        relationship_id: Any,
        *,
        confidence: Optional[int] = None,
        state_details: Any = "",
        save: Optional[bool] = None,
    ) -> Relationship:
        existing = self.store.get(clean_text(relationship_id))
        if not existing:
            raise KeyError(f"Relationship not found: {relationship_id}")

        existing.currently_verified = False
        existing.relationship_state = RelationshipState.CACHED.value
        existing.source = (
            existing.source if existing.source != "UNKNOWN" else "CACHED"
        )
        if confidence is not None:
            existing.confidence = clamp_confidence(confidence)
        if clean_text(state_details):
            existing.state_details = clean_text(state_details)
        existing.touch()
        self._append_history_entry(
            existing,
            "cached",
            previous={"confidence": existing.confidence},
            current={"confidence": existing.confidence, "source": existing.source},
            details=clean_text(state_details),
            source=existing.source,
        )
        return self.store.upsert(existing, save=save)

    def set_relationship_state(
        self,
        relationship_id: Any,
        state: Any,
        *,
        state_details: Any = "",
        active: Optional[bool] = None,
        save: Optional[bool] = None,
    ) -> Relationship:
        existing = self.store.get(clean_text(relationship_id))
        if not existing:
            raise KeyError(f"Relationship not found: {relationship_id}")

        existing.relationship_state = normalize_state(state)
        if clean_text(state_details):
            existing.state_details = clean_text(state_details)
        if active is not None:
            existing.active = normalize_bool(active)
        if existing.relationship_state != RelationshipState.LIVE.value:
            existing.currently_verified = False
        existing.touch()
        self._append_history_entry(
            existing,
            "state_changed",
            previous={"state": existing.relationship_state},
            current={"state": normalize_state(state), "active": existing.active},
            details=clean_text(state_details),
            source=existing.source,
        )
        return self.store.upsert(existing, save=save)

    def find_relationship(
        self,
        *,
        relationship_id: Any = "",
        parent: Any = "",
        child: Any = "",
        relationship_type: Any = RelationshipType.PHYSICAL.value,
        parent_interface: Any = "",
        child_interface: Any = "",
    ) -> Optional[Relationship]:
        if clean_text(relationship_id):
            return self.store.get(clean_text(relationship_id))
        return self.store.find_by_identity(
            parent,
            child,
            relationship_type,
            parent_interface,
            child_interface,
        )

    def list_relationships(
        self,
        *,
        parent: Any = "",
        child: Any = "",
        device: Any = "",
        state: Any = "",
        relationship_type: Any = "",
        source: Any = "",
        active_only: bool = False,
        verified_only: bool = False,
    ) -> List[Relationship]:
        if clean_text(device):
            candidates = self.store.relationships_for_device(device)
        else:
            candidates = self.store.all()

        parent = clean_text(parent)
        child = clean_text(child)
        state = normalize_state(state) if clean_text(state) else ""
        relationship_type = (
            normalize_type(relationship_type) if clean_text(relationship_type) else ""
        )
        source = normalize_source(source) if clean_text(source) else ""

        results = []
        for relationship in candidates:
            if parent and relationship.parent != parent:
                continue
            if child and relationship.child != child:
                continue
            if state and relationship.relationship_state != state:
                continue
            if relationship_type and relationship.relationship_type != relationship_type:
                continue
            if source and relationship.source != source:
                continue
            if active_only and not relationship.active:
                continue
            if verified_only and not relationship.currently_verified:
                continue
            results.append(relationship)

        return sorted(
            results,
            key=lambda relationship: (
                relationship.parent,
                relationship.child,
                -relationship.priority,
                relationship.id,
            ),
        )

    def get_preferred_relationship_for_child(
        self,
        child: Any,
        *,
        include_inactive: bool = False,
    ) -> Optional[Relationship]:
        relationships = self.list_relationships(child=child)
        if not include_inactive:
            relationships = [item for item in relationships if item.active]
        if not relationships:
            return None

        relationships.sort(
            key=lambda item: (
                1 if item.currently_verified else 0,
                item.priority,
                item.confidence,
                item.updated_at,
            ),
            reverse=True,
        )
        return relationships[0]

    def serialize_relationship(
        self,
        relationship_id: Any,
    ) -> Optional[Dict[str, Any]]:
        relationship = self.store.get(clean_text(relationship_id))
        return relationship.to_dict() if relationship else None

    def serialize_all(self) -> Dict[str, Dict[str, Any]]:
        return self.store.export_dict()


def _legacy_projection_selection_rank(relationship: Optional["Relationship"]) -> Tuple[int, int, int, int, int, int, str]:
    if relationship is None:
        return (99, 1, 1, 0, 0, 0, "")

    metadata = deepcopy(relationship.metadata or {}) if isinstance(relationship.metadata, dict) else {}
    selection_source = clean_text(metadata.get("selection_source", "")).lower()
    state = normalize_state(relationship.relationship_state)
    source = normalize_source(relationship.source)
    relationship_type = normalize_type(relationship.relationship_type)
    verified = 1 if relationship.currently_verified else 0
    active = 1 if relationship.active else 0

    if selection_source in {"preferred_role_path", "role_path", "configured_role_path"} or "role path" in selection_source or "preferred role" in selection_source:
        rank = 0
    elif source in {"MANUAL", "CONFIGURED", "PROVISIONING"} or state in {"CONFIGURED", "MANUAL"}:
        rank = 1
    elif relationship_type in {RelationshipType.DEPENDENCY.value, RelationshipType.SERVICE.value, RelationshipType.CONTAINER.value} or source in {"DEPENDENCY", "INFRASTRUCTURE"} or "infrastructure" in selection_source or "dependency" in selection_source:
        rank = 2
    elif verified and source in {"CDP", "LLDP", "SNMP"} and relationship_type == RelationshipType.PHYSICAL.value:
        rank = 3
    elif state in {RelationshipState.CACHED.value, RelationshipState.UNKNOWN.value} or source in {"CACHED", "UNKNOWN"}:
        rank = 4
    else:
        rank = 5

    return (
        rank,
        0 if active else 1,
        0 if verified else 1,
        -clamp_confidence(relationship.confidence),
        -max(0, relationship.priority),
        -int(relationship.updated_at > ""),
        clean_text(relationship.id),
    )


def _legacy_projection_existing_rank(record: Optional[Dict[str, Any]]) -> Tuple[int, int, int, int, int, int, str]:
    if not isinstance(record, dict):
        return (99, 1, 1, 0, 0, 0, "")

    selection_source = clean_text(record.get("selection_source", "")).lower()
    relationship_text = clean_text(record.get("relationship", "")).lower()
    source = normalize_source(record.get("source", ""))
    state = normalize_state(record.get("relationship_state", ""))
    verified = 1 if bool(record.get("currently_verified", False)) else 0
    active = 1 if bool(record.get("active", True)) else 0

    if selection_source in {"preferred_role_path", "role_path", "configured_role_path"} or "role path" in selection_source or "preferred role" in selection_source or "configured infrastructure role path" in relationship_text:
        rank = 0
    elif source in {"MANUAL", "CONFIGURED", "PROVISIONING"} or state in {"CONFIGURED", "MANUAL"}:
        rank = 1
    elif source in {"DEPENDENCY", "INFRASTRUCTURE"} or "dependency" in relationship_text or "infrastructure" in relationship_text:
        rank = 2
    elif verified and source in {"CDP", "LLDP", "SNMP"}:
        rank = 3
    elif state in {RelationshipState.CACHED.value, RelationshipState.UNKNOWN.value} or source in {"CACHED", "UNKNOWN"}:
        rank = 4
    else:
        rank = 5

    return (
        rank,
        0 if active else 1,
        0 if verified else 1,
        -clamp_confidence(record.get("confidence", 0)),
        0,
        0,
        clean_text(record.get("relationship_id", "")),
    )


def _should_replace_existing_legacy_entry(
    selected_relationship: Optional["Relationship"],
    existing_record: Optional[Dict[str, Any]],
) -> bool:
    if selected_relationship is None:
        return False
    if not isinstance(existing_record, dict):
        return True

    selected_rank = _legacy_projection_selection_rank(selected_relationship)
    existing_rank = _legacy_projection_existing_rank(existing_record)
    if selected_rank[0] < existing_rank[0]:
        return True
    if selected_rank[0] > existing_rank[0]:
        return False

    if selected_rank[1] != existing_rank[1]:
        return selected_rank[1] < existing_rank[1]
    if selected_rank[2] != existing_rank[2]:
        return selected_rank[2] < existing_rank[2]
    if selected_rank[3] != existing_rank[3]:
        return selected_rank[3] < existing_rank[3]
    if selected_rank[4] != existing_rank[4]:
        return selected_rank[4] < existing_rank[4]
    return False


def serialize_relationships_for_legacy_projection(
    manager: Optional["RelationshipManager"],
    existing: Optional[Dict[str, Any]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Return a config-compatible device_relationships projection from the authoritative store."""
    projection: Dict[str, Dict[str, Any]] = {}

    if isinstance(existing, dict):
        for child_name, record in existing.items():
            if isinstance(record, dict):
                projection[clean_text(child_name)] = deepcopy(record)

    if manager is None:
        return projection

    authoritative_children: Dict[str, List["Relationship"]] = {}
    for relationship in manager.list_relationships():
        if not relationship or not relationship.child:
            continue
        authoritative_children.setdefault(relationship.child, [])
        authoritative_children[relationship.child].append(relationship)

    for child_name, relationships in authoritative_children.items():
        if not relationships:
            continue

        selected_relationship = None
        for relationship in relationships:
            if selected_relationship is None:
                selected_relationship = relationship
                continue
            candidate_rank = _legacy_projection_selection_rank(relationship)
            selected_rank = _legacy_projection_selection_rank(selected_relationship)
            if candidate_rank < selected_rank:
                selected_relationship = relationship
            elif candidate_rank == selected_rank:
                if relationship.confidence > selected_relationship.confidence:
                    selected_relationship = relationship
                elif relationship.confidence == selected_relationship.confidence and relationship.priority > selected_relationship.priority:
                    selected_relationship = relationship
                elif relationship.confidence == selected_relationship.confidence and relationship.priority == selected_relationship.priority and relationship.updated_at > selected_relationship.updated_at:
                    selected_relationship = relationship
                elif relationship.confidence == selected_relationship.confidence and relationship.priority == selected_relationship.priority and relationship.updated_at == selected_relationship.updated_at and relationship.id < selected_relationship.id:
                    selected_relationship = relationship

        existing_record = projection.get(child_name)
        should_replace = _should_replace_existing_legacy_entry(selected_relationship, existing_record)
        if not should_replace and existing_record is not None:
            continue

        if selected_relationship is None:
            continue

        metadata = deepcopy(selected_relationship.metadata or {}) if isinstance(selected_relationship.metadata, dict) else {}
        legacy_relationship = clean_text(
            metadata.get("legacy_relationship")
            or selected_relationship.state_details
            or "Relationship Manager Link"
        )

        projection[child_name] = {
            "parent": selected_relationship.parent,
            "relationship": legacy_relationship or "Relationship Manager Link",
            "source": selected_relationship.source or "relationship_manager",
            "selection_source": clean_text(metadata.get("selection_source", selected_relationship.source or "")),
            "source_interface": selected_relationship.parent_interface,
            "destination_interface": selected_relationship.child_interface,
            "confidence": clamp_confidence(selected_relationship.confidence),
            "evidence_sources": list(selected_relationship.evidence_sources),
            "evidence_id": selected_relationship.evidence_id,
            "relationship_type": selected_relationship.relationship_type,
            "relationship_state": selected_relationship.relationship_state,
            "relationship_state_details": selected_relationship.state_details,
            "currently_verified": bool(selected_relationship.currently_verified),
            "active": bool(selected_relationship.active),
            "last_verified_at": selected_relationship.last_verified_at,
            "last_seen_at": selected_relationship.last_seen_at,
            "updated_at": selected_relationship.updated_at,
            "relationship_id": selected_relationship.id,
            "metadata": metadata,
        }

    return projection


def migrate_legacy_relationships(
    config: Dict[str, Any],
    manager: RelationshipManager,
    *,
    save: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Migrate legacy relationship structures into the Phase 27A store.

    Migration is additive and idempotent. Legacy keys are preserved so the
    existing application continues to operate during later Phase 27 work.
    """
    if not isinstance(config, dict):
        raise TypeError("Config must be a dictionary.")

    migrated = 0
    skipped = 0
    errors: List[str] = []

    def migrate_record(raw: Dict[str, Any], defaults: Optional[Dict[str, Any]] = None) -> None:
        nonlocal migrated, skipped
        if not isinstance(raw, dict):
            skipped += 1
            return

        payload = deepcopy(defaults) if isinstance(defaults, dict) else {}
        payload.update(deepcopy(raw))

        try:
            relationship = Relationship.from_dict(payload)
            relationship.validate()
            before = manager.find_relationship(
                parent=relationship.parent,
                child=relationship.child,
                relationship_type=relationship.relationship_type,
                parent_interface=relationship.parent_interface,
                child_interface=relationship.child_interface,
            )
            manager.upsert_relationship(
                relationship.to_dict(),
                save=False,
                prefer_higher_priority=True,
            )
            if before:
                skipped += 1
            else:
                migrated += 1
        except (TypeError, ValueError, KeyError) as exc:
            errors.append(str(exc))

    legacy_device_relationships = config.get("device_relationships", {})
    if isinstance(legacy_device_relationships, dict):
        for child_name, raw in legacy_device_relationships.items():
            if isinstance(raw, str):
                raw = {"parent": raw}
            if not isinstance(raw, dict):
                skipped += 1
                continue
            defaults = {
                "child": clean_text(child_name),
                "relationship_type": raw.get("relationship_type", "PHYSICAL"),
                "relationship_state": raw.get(
                    "relationship_state",
                    "MANUAL" if raw.get("manual") else "CONFIGURED",
                ),
                "source": raw.get(
                    "source",
                    "MANUAL" if raw.get("manual") else "CONFIGURED",
                ),
                "confidence": raw.get("confidence", 80 if raw.get("manual") else 60),
                "currently_verified": raw.get("currently_verified", False),
            }
            migrate_record(raw, defaults)

    for key in (
        "infrastructure_links",
        "generated_infrastructure_links",
        "infrastructure_relationships",
    ):
        raw_collection = config.get(key, [])
        if isinstance(raw_collection, dict):
            iterable: Iterable[Any] = raw_collection.values()
        elif isinstance(raw_collection, list):
            iterable = raw_collection
        else:
            continue

        for raw in iterable:
            if not isinstance(raw, dict):
                skipped += 1
                continue

            defaults = {
                "parent": raw.get("parent", raw.get("from", "")),
                "child": raw.get("child", raw.get("to", "")),
                "parent_interface": raw.get(
                    "parent_interface",
                    raw.get("from_interface", ""),
                ),
                "child_interface": raw.get(
                    "child_interface",
                    raw.get("to_interface", ""),
                ),
                "relationship_type": raw.get("relationship_type", "PHYSICAL"),
                "relationship_state": raw.get(
                    "relationship_state",
                    "LIVE" if raw.get("currently_verified") else "CONFIGURED",
                ),
                "source": raw.get(
                    "source",
                    raw.get("selection_source", "CONFIGURED"),
                ),
                "confidence": raw.get("confidence", 60),
            }
            migrate_record(raw, defaults)

    merged_physical_links = config.get("merged_physical_links", {})
    if isinstance(merged_physical_links, dict):
        iterable = merged_physical_links.values()
    elif isinstance(merged_physical_links, list):
        iterable = merged_physical_links
    else:
        iterable = []

    for raw in iterable:
        if not isinstance(raw, dict):
            skipped += 1
            continue
        defaults = {
            "parent": raw.get("parent", raw.get("from", "")),
            "child": raw.get("child", raw.get("to", "")),
            "parent_interface": raw.get(
                "parent_interface",
                raw.get("from_interface", raw.get("local_interface", "")),
            ),
            "child_interface": raw.get(
                "child_interface",
                raw.get("to_interface", raw.get("remote_interface", "")),
            ),
            "relationship_type": "PHYSICAL",
            "relationship_state": "LIVE" if raw.get("active") else "CACHED",
            "source": raw.get("source", "CDP"),
            "confidence": raw.get("confidence", 0),
            "currently_verified": raw.get("active", False),
            "active": raw.get("active", True),
        }
        migrate_record(raw, defaults)

    metadata = config.setdefault(DEFAULT_METADATA_KEY, {})
    metadata["phase"] = "27A"
    metadata["engine_version"] = ENGINE_VERSION
    metadata["migration_complete"] = True
    metadata["last_migration_at"] = utc_now_string()
    metadata["last_migration_summary"] = {
        "migrated": migrated,
        "skipped_or_updated": skipped,
        "errors": len(errors),
    }
    if errors:
        metadata["last_migration_errors"] = errors[-50:]
    else:
        metadata.pop("last_migration_errors", None)

    manager.store.sync_to_config(save=save)

    return {
        "success": len(errors) == 0,
        "phase": "27A",
        "engine_version": ENGINE_VERSION,
        "migrated": migrated,
        "skipped_or_updated": skipped,
        "errors": errors,
        "relationship_count": manager.store.count(),
    }


def initialize_relationship_engine(
    config: Dict[str, Any],
    *,
    config_path: Optional[str] = None,
    autosave: bool = False,
    migrate_legacy: bool = True,
    source_priorities: Optional[Dict[str, int]] = None,
) -> Tuple[RelationshipStore, RelationshipManager, Dict[str, Any]]:
    """Initialize the Phase 27A store, manager, and optional legacy migration."""
    store = RelationshipStore(
        config=config,
        config_path=config_path,
        autosave=autosave,
    )
    manager = RelationshipManager(
        store=store,
        source_priorities=source_priorities,
    )

    if migrate_legacy:
        migration = migrate_legacy_relationships(
            config,
            manager,
            save=autosave,
        )
    else:
        migration = {
            "success": True,
            "phase": "27A",
            "engine_version": ENGINE_VERSION,
            "migrated": 0,
            "skipped_or_updated": 0,
            "errors": [],
            "relationship_count": store.count(),
        }

    return store, manager, migration


__all__ = [
    "ENGINE_VERSION",
    "DEFAULT_STORE_KEY",
    "DEFAULT_DEVICE_INDEX_KEY",
    "DEFAULT_METADATA_KEY",
    "RelationshipState",
    "RelationshipType",
    "Relationship",
    "RelationshipStore",
    "RelationshipManager",
    "serialize_relationships_for_legacy_projection",
    "clean_text",
    "clamp_confidence",
    "normalize_bool",
    "normalize_state",
    "normalize_type",
    "normalize_source",
    "normalize_evidence_sources",
    "normalize_evidence_records",
    "relationship_identity_key",
    "stable_relationship_id",
    "migrate_legacy_relationships",
    "initialize_relationship_engine",
]
