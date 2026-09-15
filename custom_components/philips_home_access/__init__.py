import logging

import voluptuous as vol

from homeassistant.components.persistent_notification import async_create as persistent_notify
from homeassistant.core import ServiceCall
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.issue_registry import IssueSeverity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)
PLATFORMS = ["lock", "sensor", "switch", "number", "event"]
ISSUE_AUTH = "auth_invalid"


def _issue_id(entry_id: str) -> str:
    return f"{ISSUE_AUTH}_{entry_id}"


def create_auth_issue(hass, entry):
    ir.async_create_issue(
        hass,
        DOMAIN,
        _issue_id(entry.entry_id),
        is_fixable=True,
        severity=IssueSeverity.ERROR,
        translation_key="reauth_required",
        translation_placeholders={"name": entry.title},
        data={"entry_id": entry.entry_id},
    )


def clear_auth_issue(hass, entry):
    ir.async_delete_issue(hass, DOMAIN, _issue_id(entry.entry_id))
    hass.async_create_task(
        hass.services.async_call(
            "persistent_notification",
            "dismiss",
            {"notification_id": f"{DOMAIN}_{entry.entry_id}_auth"},
        )
    )


async def async_setup(hass, config):
    hass.data.setdefault(DOMAIN, {})
    _async_register_services(hass)
    return True


async def _async_reload_entry(hass, entry):
    await hass.config_entries.async_reload(entry.entry_id)


async def async_setup_entry(hass, entry):
    from .api import PhilipsHomeAccessAPI
    from .coordinator import PhilipsDataUpdateCoordinator
    from homeassistant.exceptions import ConfigEntryAuthFailed

    _LOGGER.debug(
        "Setting up entry %s for username=%s region=%s",
        entry.entry_id,
        entry.data.get("username"),
        entry.data.get("region"),
    )

    api = PhilipsHomeAccessAPI(
        entry.data["username"],
        entry.data["password"],
        entry.data["region"],
        app_host=entry.options.get("app_host") or entry.data.get("app_host"),
    )

    hass.data.setdefault(DOMAIN, {})

    try:
        await hass.async_add_executor_job(api.login)
        _LOGGER.debug("Initial login succeeded for entry %s", entry.entry_id)
    except Exception as err:
        _LOGGER.debug("Initial login failed for entry %s: %r", entry.entry_id, err)
        create_auth_issue(hass, entry)
        raise ConfigEntryAuthFailed(
            "Philips Home Access authentication failed. Please reconfigure."
        ) from err

    coordinator = PhilipsDataUpdateCoordinator(hass, entry, api)
    await coordinator.async_config_entry_first_refresh()

    clear_auth_issue(hass, entry)
    hass.data[DOMAIN][entry.entry_id] = coordinator
    hass.data[DOMAIN][f"{entry.entry_id}_update_listener"] = entry.add_update_listener(
        _async_reload_entry
    )

    _LOGGER.debug("Forwarding entry %s to platforms: %s", entry.entry_id, PLATFORMS)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass, entry):
    unsub_update_listener = hass.data[DOMAIN].pop(f"{entry.entry_id}_update_listener", None)
    if unsub_update_listener:
        unsub_update_listener()

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok


# ---------------------------------------------------------------------------
# Services for credential (PIN/fingerprint) and share management. These call the
# newer "/app/*" API surface, which needs the datacenter host to be resolved
# first (see docs/reverse-engineering-notes.md); until then they raise a clear
# error instead of silently doing nothing.
# ---------------------------------------------------------------------------

SERVICE_CREATE_PIN = "create_pin"
SERVICE_DELETE_CREDENTIAL = "delete_credential"
SERVICE_ADD_SHARE = "add_share"
SERVICE_REMOVE_SHARE = "remove_share"

_CREATE_PIN_SCHEMA = vol.Schema(
    {
        vol.Required("esn"): cv.string,
        vol.Required("name"): cv.string,
        vol.Required("pin"): cv.string,
    }
)
_DELETE_CREDENTIAL_SCHEMA = vol.Schema(
    {vol.Required("esn"): cv.string, vol.Required("num"): vol.Coerce(int)}
)
_ADD_SHARE_SCHEMA = vol.Schema(
    {
        vol.Required("esn"): cv.string,
        vol.Required("account"): cv.string,
        vol.Optional("nickname"): cv.string,
    }
)
_REMOVE_SHARE_SCHEMA = vol.Schema(
    {vol.Required("esn"): cv.string, vol.Required("share_id"): cv.string}
)


def _api_for_esn(hass, esn):
    """Find the coordinator/api whose account can see this lock."""
    for value in hass.data.get(DOMAIN, {}).values():
        api = getattr(value, "api", None)
        if api is None:
            continue
        if value.data and esn in value.data.get("devices", {}):
            return api
    raise HomeAssistantError(
        f"No configured Philips Home Access account currently sees lock {esn}."
    )


def _async_register_services(hass):
    if hass.services.has_service(DOMAIN, SERVICE_CREATE_PIN):
        return

    from .api import PhilipsAppApiUnavailable

    async def _run(call: ServiceCall, fn_name, *arg_names):
        esn = call.data["esn"]
        api = _api_for_esn(hass, esn)
        fn = getattr(api, fn_name)
        args = [call.data[a] for a in arg_names]
        kwargs = {}
        if fn_name == "add_share" and call.data.get("nickname"):
            kwargs["nickname"] = call.data["nickname"]
        try:
            resp = await hass.async_add_executor_job(lambda: fn(esn, *args, **kwargs))
        except PhilipsAppApiUnavailable as err:
            raise HomeAssistantError(
                "This feature needs the Philips datacenter host to be resolved "
                "first. See docs/reverse-engineering-notes.md."
            ) from err
        except Exception as err:  # noqa: BLE001
            raise HomeAssistantError(f"Philips Home Access request failed: {err}") from err
        if isinstance(resp, dict) and str(resp.get("code")) not in ("200", "None"):
            raise HomeAssistantError(
                f"Philips Home Access returned code={resp.get('code')} msg={resp.get('msg')}"
            )

    async def create_pin(call: ServiceCall):
        await _run(call, "create_pin", "name", "pin")

    async def delete_credential(call: ServiceCall):
        await _run(call, "delete_key", "num")

    async def add_share(call: ServiceCall):
        await _run(call, "add_share", "account")

    async def remove_share(call: ServiceCall):
        await _run(call, "delete_share", "share_id")

    hass.services.async_register(DOMAIN, SERVICE_CREATE_PIN, create_pin, schema=_CREATE_PIN_SCHEMA)
    hass.services.async_register(
        DOMAIN, SERVICE_DELETE_CREDENTIAL, delete_credential, schema=_DELETE_CREDENTIAL_SCHEMA
    )
    hass.services.async_register(DOMAIN, SERVICE_ADD_SHARE, add_share, schema=_ADD_SHARE_SCHEMA)
    hass.services.async_register(
        DOMAIN, SERVICE_REMOVE_SHARE, remove_share, schema=_REMOVE_SHARE_SCHEMA
    )
