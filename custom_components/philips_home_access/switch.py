import logging

from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    lock_devices = [
        d for d in coordinator.data["devices"].values() if d.get("deviceType") == "LOCK"
    ]
    async_add_entities(PhilipsAutoLockSwitch(coordinator, d) for d in lock_devices)


class PhilipsAutoLockSwitch(CoordinatorEntity, SwitchEntity):
    def __init__(self, coordinator, device):
        super().__init__(coordinator)
        self._api = coordinator.api
        self._esn = device["wifiSN"]
        self._attr_name = f"{device['lockNickname']} Auto-Lock"
        self._attr_unique_id = f"{self._esn}_autolock_switch"
        self._attr_device_info = {"identifiers": {(DOMAIN, self._esn)}}

    @property
    def _device(self):
        return self.coordinator.data["devices"].get(self._esn)

    @property
    def available(self) -> bool:
        return super().available and self._device is not None

    @property
    def is_on(self):
        device = self._device
        # amMode == 0 means auto-lock is enabled.
        return device.get("amMode") == 0 if device else None

    async def async_turn_on(self, **kwargs):
        await self._async_set(True)

    async def async_turn_off(self, **kwargs):
        await self._async_set(False)

    async def _async_set(self, enabled):
        _LOGGER.debug("switch: %s auto-lock for esn=%s", "enabling" if enabled else "disabling", self._esn)
        resp = await self.hass.async_add_executor_job(
            self._api.set_auto_lock_mode, self._esn, enabled
        )
        _LOGGER.debug("switch: response for esn=%s: %s", self._esn, resp)
        # Refresh so both this switch and the linked auto-lock-delay number pick
        # up the new amMode from a single poll.
        await self.coordinator.async_request_refresh()
