"""Activity events for Philips Home Access locks.

One event entity per lock. When the coordinator sees a new operation record
(door unlocked, locked, PIN used, alarm, ...) it fires an HA event that
automations can react to — e.g. notify when the door is unlocked.

The activity feed depends on the newer "/app/*" API, which needs the datacenter
host to be resolved (see docs/reverse-engineering-notes.md). Until then the
coordinator returns no activity and these entities simply stay idle.
"""
from __future__ import annotations

import logging

from homeassistant.components.event import EventEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import (
    _RECORD_ID_KEYS,
    _RECORD_LIST_KEYS,
    _RECORD_TYPE_KEYS,
    _RECORD_USER_KEYS,
)
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# Event types we expose. Exact record-type values from the cloud are not yet
# confirmed, so incoming types are mapped onto this set and anything unmatched
# becomes "other" (with the raw record kept in the event attributes).
EVENT_TYPES = [
    "lock",
    "unlock",
    "pin_unlock",
    "fingerprint_unlock",
    "app_unlock",
    "auto_lock",
    "alarm",
    "tamper",
    "doorbell",
    "other",
]


def _first(record: dict, keys):
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return None


def _records_from(activity) -> list[dict]:
    """Pull the record list out of whatever envelope the API returns."""
    if isinstance(activity, list):
        return [r for r in activity if isinstance(r, dict)]
    if isinstance(activity, dict):
        for key in _RECORD_LIST_KEYS:
            value = activity.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
        # A single record returned bare.
        if _first(activity, _RECORD_ID_KEYS) is not None:
            return [activity]
    return []


def _classify(record: dict) -> str:
    raw = _first(record, _RECORD_TYPE_KEYS)
    text = str(raw).lower() if raw is not None else ""
    if any(t in text for t in ("tamper", "pry", "destroy")):
        return "tamper"
    if any(t in text for t in ("alarm", "duress", "warn")):
        return "alarm"
    if "doorbell" in text or "visit" in text:
        return "doorbell"
    if "auto" in text and "lock" in text:
        return "auto_lock"
    if "finger" in text:
        return "fingerprint_unlock"
    if "pin" in text or "password" in text or "passcode" in text:
        return "pin_unlock"
    if "app" in text or "remote" in text:
        return "app_unlock"
    if "unlock" in text or "open" in text:
        return "unlock"
    if "lock" in text or "close" in text:
        return "lock"
    return "other"


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    lock_devices = [
        d for d in coordinator.data["devices"].values() if d.get("deviceType") == "LOCK"
    ]
    async_add_entities(PhilipsActivityEvent(coordinator, d) for d in lock_devices)


class PhilipsActivityEvent(CoordinatorEntity, EventEntity):
    _attr_event_types = EVENT_TYPES
    _attr_icon = "mdi:history"

    def __init__(self, coordinator, device):
        super().__init__(coordinator)
        self._esn = device["wifiSN"]
        self._attr_name = f"{device.get('lockNickname', 'Lock')} Activity"
        self._attr_unique_id = f"philips_{self._esn}_activity"
        self._attr_device_info = {"identifiers": {(DOMAIN, self._esn)}}
        self._last_record_id = None

    def _handle_coordinator_update(self) -> None:
        activity = (self.coordinator.data or {}).get("activity", {}).get(self._esn)
        records = _records_from(activity)
        if not records:
            return

        newest = records[0]
        record_id = _first(newest, _RECORD_ID_KEYS)

        # On the first poll, remember where we are without firing a burst of
        # historical events.
        if self._last_record_id is None:
            self._last_record_id = record_id
            return

        if record_id == self._last_record_id:
            return
        self._last_record_id = record_id

        event_type = _classify(newest)
        attributes = {
            "user": _first(newest, _RECORD_USER_KEYS),
            "record_id": record_id,
            "raw": newest,
        }
        _LOGGER.debug("event: firing %s for esn=%s", event_type, self._esn)
        self._trigger_event(event_type, attributes)
        super()._handle_coordinator_update()
