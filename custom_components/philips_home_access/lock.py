import logging
from datetime import datetime, timedelta

from homeassistant.components.lock import LockEntity
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    devices = coordinator.data["devices"].values()
    lock_devices = [d for d in devices if d.get("deviceType") == "LOCK"]
    async_add_entities(
        PhilipsHomeAccessLock(coordinator, device) for device in lock_devices
    )


class PhilipsHomeAccessLock(CoordinatorEntity, LockEntity):
    _attr_icon = "mdi:lock-smart"
    _attr_has_entity_name = False

    def __init__(self, coordinator, device_data):
        super().__init__(coordinator)
        self._api = coordinator.api
        self._esn = device_data["wifiSN"]
        self._attr_name = device_data.get("lockNickname", "Lock")
        self._attr_unique_id = f"philips_{self._esn}_lock"
        # After a lock/unlock the cloud lags a poll or two, so hold an optimistic
        # value until this deadline instead of letting a stale poll flip it back.
        self._optimistic_until = None
        self._optimistic_locked = None

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self._esn)},
            name=self._attr_name,
            manufacturer="Philips",
            model=device_data.get("productModel", "Lock"),
            sw_version=device_data.get("lockSoftwareVersion"),
        )

    @property
    def _device(self):
        return self.coordinator.data["devices"].get(self._esn)

    @property
    def available(self) -> bool:
        return super().available and self._device is not None

    @property
    def is_locked(self):
        if self._optimistic_until and datetime.utcnow() < self._optimistic_until:
            return self._optimistic_locked
        device = self._device
        if not device:
            return None
        return device.get("openStatus") == 1

    async def async_lock(self, **kwargs):
        await self._async_set(True)

    async def async_unlock(self, **kwargs):
        await self._async_set(False)

    async def _async_set(self, lock_it):
        _LOGGER.debug("lock: %s requested for esn=%s", "lock" if lock_it else "unlock", self._esn)
        resp = await self.hass.async_add_executor_job(
            self._api.set_lock_state, self._esn, lock_it
        )
        _LOGGER.debug("lock: response for esn=%s: %s", self._esn, resp)
        if isinstance(resp, dict) and resp.get("code") == 200:
            self._optimistic_locked = lock_it
            self._optimistic_until = datetime.utcnow() + timedelta(seconds=30)
            self.async_write_ha_state()
        await self.coordinator.async_request_refresh()
