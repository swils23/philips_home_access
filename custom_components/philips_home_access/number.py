import logging

from homeassistant.components.number import NumberEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    lock_devices = [
        d for d in coordinator.data["devices"].values() if d.get("deviceType") == "LOCK"
    ]
    async_add_entities(PhilipsAutoLockTime(coordinator, d) for d in lock_devices)


class PhilipsAutoLockTime(CoordinatorEntity, NumberEntity):
    _attr_native_min_value = 10
    _attr_native_max_value = 180
    _attr_native_step = 1
    _attr_native_unit_of_measurement = "s"

    def __init__(self, coordinator, device):
        super().__init__(coordinator)
        self._api = coordinator.api
        self._esn = device["wifiSN"]
        self._attr_name = f"{device['lockNickname']} Auto-Lock Delay"
        self._attr_unique_id = f"{self._esn}_autolock_time"
        self._attr_device_info = {"identifiers": {(DOMAIN, self._esn)}}

    @property
    def _device(self):
        return self.coordinator.data["devices"].get(self._esn)

    @property
    def available(self) -> bool:
        # Only meaningful while auto-lock mode is enabled (amMode == 0).
        device = self._device
        return super().available and device is not None and device.get("amMode") == 0

    @property
    def native_value(self):
        device = self._device
        return device.get("autoLockTime") if device else None

    async def async_set_native_value(self, value):
        _LOGGER.info("number: setting auto-lock delay for esn=%s to %s", self._esn, int(value))
        resp = await self.hass.async_add_executor_job(
            self._api.set_auto_lock_time, self._esn, int(value)
        )
        _LOGGER.debug("number: set auto-lock delay response for esn=%s: %s", self._esn, resp)
        await self.coordinator.async_request_refresh()
