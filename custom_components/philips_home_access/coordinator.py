"""Shared polling for Philips Home Access.

Before this, every lock/sensor/number entity called get_devices() on its own
poll, so one lock produced four-plus identical requests a minute against an API
whose session is easily invalidated. The coordinator fetches the device list
once per interval and every entity reads from the shared result.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import PhilipsAppApiUnavailable, PhilipsSessionExpired
from .const import (
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL_MINUTES,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class PhilipsDataUpdateCoordinator(DataUpdateCoordinator):
    """Fetch the device list (and, when available, latest activity) once."""

    def __init__(self, hass, entry, api):
        self.api = api
        self.entry = entry
        interval_minutes = entry.options.get(
            CONF_SCAN_INTERVAL,
            entry.data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL_MINUTES),
        )
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{entry.entry_id}",
            update_interval=timedelta(minutes=interval_minutes),
        )
        # esn -> newest activity record id already seen, so the event platform
        # can tell a genuinely new event from a repeat of the last poll.
        self._last_activity_id: dict[str, str] = {}

    async def _async_update_data(self):
        try:
            devices = await self.hass.async_add_executor_job(self.api.get_devices)
        except PhilipsSessionExpired as err:
            # 444: another login stole the session. Surface as auth failure so
            # Home Assistant starts the repair/reauth flow.
            raise ConfigEntryAuthFailed("Philips Home Access session expired") from err
        except Exception as err:  # noqa: BLE001 - surface as a normal update failure
            raise UpdateFailed(f"Error fetching Philips devices: {err}") from err

        devices_by_esn = {d["wifiSN"]: d for d in devices if d.get("wifiSN")}

        activity_by_esn = await self._async_fetch_activity(devices_by_esn)

        return {"devices": devices_by_esn, "activity": activity_by_esn}

    async def _async_fetch_activity(self, devices_by_esn):
        """Fetch latest activity per lock, if the app host has been resolved.

        This is a no-op (returns empty) until api.app_host is known, so the
        event platform simply stays idle rather than erroring.
        """
        if not getattr(self.api, "app_host", None):
            return {}

        activity: dict[str, dict] = {}
        for esn, device in devices_by_esn.items():
            if device.get("deviceType") != "LOCK":
                continue
            try:
                resp = await self.hass.async_add_executor_job(
                    self.api.get_latest_activity, esn
                )
            except PhilipsAppApiUnavailable:
                return {}
            except PhilipsSessionExpired as err:
                raise ConfigEntryAuthFailed("Philips Home Access session expired") from err
            except Exception as err:  # noqa: BLE001 - activity is best-effort
                _LOGGER.debug("activity fetch failed for %s: %r", esn, err)
                continue
            if isinstance(resp, dict) and str(resp.get("code")) == "200":
                activity[esn] = resp.get("data")
        return activity

    def device(self, esn):
        """Return the latest device dict for an esn, or None."""
        if not self.data:
            return None
        return self.data.get("devices", {}).get(esn)
