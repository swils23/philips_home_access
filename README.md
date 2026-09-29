# Philips Home Access (Home Assistant Integration)

Home Assistant custom integration for Philips Home Access WiFi locks.

This integration allows you to monitor and control Philips Home Access locks directly from Home Assistant.

## Features

- Lock and unlock your Philips Home Access lock
- View lock status
- Monitor battery level
- Monitor WiFi signal strength
- Automatic session expiration detection
- Repair flow support for re-authentication

## Supported Devices

So far, I have only tested with:

- Philips Home Access WiFi Locks
  - This also includes locks that are controlled through a wifi gateway

Let me know if your lock works or help me add support it.

## Notes

- You can not be logged in to the Philips Home Access app and this integration with the same account at the same time. Logging in to one will sign you out of the other. To use both, see [Using a shared account](#using-a-shared-account).
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

## Using a shared account

Each account can only have one active session, so signing in to the app logs
Home Assistant out (and vice versa). To keep using the app on your phone:

1. Create a second Philips Home Access account (e.g. a dedicated email for Home Assistant).
2. In the app, on your main account, share the lock with that second account.
3. Configure this integration with the second account.

Shared locks are discovered and controlled the same way as owned ones — lock,
unlock, status and sensors all work — and your main account's app session stays
signed in.

If your account doesn't show up under `PhilipsNorthAmerica`, try
`PhilipsNorthAmericaNew`.

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

## Support

If this integration helped you, consider supporting development:

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/yellow_img.png)](https://buymeacoffee.com/rjbogz)
