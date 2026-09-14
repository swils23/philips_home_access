from __future__ import annotations

import logging

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.const import PERCENTAGE, SIGNAL_STRENGTH_DECIBELS_MILLIWATT
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    devices = coordinator.data["devices"].values()

    entities = []
    for d in devices:
        esn = d.get("wifiSN")
        if not esn:
            continue
        name = d.get("lockNickname") or "Philips Home Access Device"
        device_info = {
            "identifiers": {(DOMAIN, esn)},
            "name": name,
            "manufacturer": "Philips",
            "model": d.get("productModel", "Philips Home Access Device"),
            "sw_version": d.get("lockSoftwareVersion")
            or d.get("wifiVersion")
            or d.get("gatewayVersion"),
        }
        device_type = d.get("deviceType")
        if device_type == "LOCK":
            entities.append(PhilipsBatterySensor(coordinator, esn, name, device_info))
            entities.append(PhilipsSignalSensor(coordinator, esn, name, device_info))
        elif device_type == "GATEWAY":
            entities.append(PhilipsSignalSensor(coordinator, esn, name, device_info))

    _LOGGER.debug("sensor: adding %d entities", len(entities))
    async_add_entities(entities)


class PhilipsBaseSensor(CoordinatorEntity, SensorEntity):
    def __init__(self, coordinator, esn: str, name: str, device_info: dict):
        super().__init__(coordinator)
        self._esn = esn
        self._name = name
        self._attr_device_info = device_info

    @property
    def _device(self):
        return self.coordinator.data["devices"].get(self._esn)

    @property
    def available(self) -> bool:
        return super().available and self._device is not None


class PhilipsBatterySensor(PhilipsBaseSensor):
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_icon = "mdi:battery"

    def __init__(self, coordinator, esn, name, device_info):
        super().__init__(coordinator, esn, name, device_info)
        self._attr_name = f"{name} Battery"
        self._attr_unique_id = f"philips_{esn}_battery"

    @property
    def native_value(self):
        device = self._device
        return device.get("power") if device else None


class PhilipsSignalSensor(PhilipsBaseSensor):
    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_native_unit_of_measurement = SIGNAL_STRENGTH_DECIBELS_MILLIWATT
    _attr_icon = "mdi:wifi"

    def __init__(self, coordinator, esn, name, device_info):
        super().__init__(coordinator, esn, name, device_info)
        self._attr_name = f"{name} WiFi Signal"
        self._attr_unique_id = f"philips_{esn}_rssi"

    @property
    def native_value(self):
        device = self._device
        if not device:
            return None
        raw = device.get("rssi", 0)
        if isinstance(raw, str):
            raw = raw.replace("dBm", "").strip()
        try:
            return float(raw)
        except (TypeError, ValueError):
            return None
