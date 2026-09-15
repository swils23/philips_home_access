# Philips Home Access (Home Assistant Integration)

Home Assistant custom integration for Philips Home Access WiFi locks.

This integration allows you to monitor and control Philips Home Access locks directly from Home Assistant.

> **This is a fork** of [rjbogz/philips_home_access](https://github.com/rjbogz/philips_home_access)
> adding shared-account control, activity events, and PIN/sharing management.
> See [Fork additions](#fork-additions) below.

## Features

- Lock and unlock your Philips Home Access lock
- View lock status
- Monitor battery level
- Monitor WiFi signal strength
- Automatic session expiration detection
- Repair flow support for re-authentication
- **Works from a shared account** — control the lock without logging the owner out
- **Activity events** — fire Home Assistant events on unlock/lock/alarm for notifications
- **PIN and sharing services** — create PINs, delete credentials, add/remove shares

## Fork additions

### Shared-account control

The upstream note "you can not be logged in to the app and this integration at
the same time" is about a single account: logging in one place invalidates the
other's session. The fix is to share the lock to a **second** account in the
Philips app and configure the integration with that shared account — the owner's
app session then stays alive. Device discovery was made to see shared devices
(they arrive under a different key in the API), and lock/unlock works
identically from the shared account.

### Sharing management (working)

Services `philips_home_access.add_share` and `remove_share` (see `services.yaml`)
share a lock with another account and revoke it, using the North America
datacenter host (`api.homeaccesstech.com`) that ships as the default `app_host`.
Verified live. Removing a share only revokes the `shareId` you pass — existing
shares are left alone.

### Activity events (working)

Each lock gets an `event` entity that fires when a new operation record appears
(`POST /v3/device/operation-list`), so you can notify on activity — e.g. when the
door is unlocked. The cloud's event codes aren't fully documented, so the entity
exposes them raw (`event_code`, `event_type_code`, `event_source`, plus
`pin_nickname` when a PIN was used) for automations to match on precisely.

### Credential (PIN/fingerprint) listing and deletion

- **List** — `POST /v3/device/key-list` returns `pwdList` (PINs) and
  `fingerprintList` (fingerprints), among other types. Verified live.
- **Delete** — the `delete_credential` service removes a credential by its slot
  number (`num` from the list). It's targeted (device + registry removal, both
  signature-verified against the app's own request) and cannot affect any other
  slot.

**Creating** a PIN is not wired up: it ends in a full-list-replace (a wrong
request wipes the other PINs — this happened once in testing and was restored)
*and* an encrypted device-programming step whose payload isn't confirmed, so a
"created" PIN might list but not open the door. `create_pin` returns a clear
error; [`docs/reverse-engineering-notes.md`](docs/reverse-engineering-notes.md)
documents exactly what remains (the write signing itself is already solved).

### The `tools/` and `../android-re/` helpers

`tools/` holds the discovery probes used to reverse-engineer the API; the shared
`android-re/` workbench (a rooted-emulator + mitmproxy + Frida setup usable by
other projects) is for capturing the one request needed to finish the
activity/PIN/sharing features. Both are documented in the RE notes.

## Supported Devices

So far, I have only tested with:

- Philips Home Access WiFi Locks
  - This also includes locks that are controlled through a wifi gateway

Let me know if your lock works or help me add support it.

## Notes

- You can not be logged in to the Philips Home Access app and this integration at the same time. Logging in to one will sign you out of the other.
- I have only added basic sensors for this, but I'm open to adding more support (getting other data about the lock, adjusting settings, etc.)
- This integration is a work in progress. I only have 1 lock so my testing was limited.
- The polling interval can be changed later from the integration's menu in Home Assistant.

## Installation

### Option 1: Install via HACS (recommended)

1. Open HACS in Home Assistant
2. Go to **Integrations**
3. Click the three-dot menu → **Custom repositories**
4. Add this repository: https://github.com/rjbogz/philips_home_access
5. Select category: **Integration**
6. Click **Install**
7. Restart Home Assistant

---

### Option 2: Manual installation

1. Copy the folder: custom_components/philips_home_access
2. Restart Home Assistant

---

## Configuration

1. Go to: Settings → Devices & Services → Add Integration
2. Search for: Philips Home Access
3. Enter:

- Username (email)
- Password
- Region

4. Click Submit

---

## Authentication Handling

This integration automatically detects when your session becomes invalid.

If you log in through the official Philips app, Home Assistant may require re-authentication. A Repair notification will appear allowing you to enter updated credentials.

---

## Entities Created

For each lock:

- Lock entity
- Battery sensor
- WiFi signal strength sensor
- Auto-Lock toggle
- Auto-Lock delay (10s-180s)
- Activity event entity (idle until the datacenter host is configured)


For each gateway:

- WiFi signal strength sensor

---

## Known Limitations

- Requires Philips cloud access
- Polling interval is configurable from 1 to 60 minutes
- Internet connection required

---

## Debug Logging

Add to `configuration.yaml`:

```
logger:
  logs:
    custom_components.philips_home_access: debug
```
