# Kastle Access for Home Assistant

Unofficial Home Assistant integration for [Kastle Systems](https://www.kastle.com/) access control. Unlock doors managed by Kastle directly from Home Assistant.

## Features

- Unlock any Kastle-managed door you have access to
- Automatic discovery of all authorized readers
- Lock entities integrate with HA automations, scripts, and dashboards
- Secure: generates its own cryptographic keypair, signs every request

## Installation

### HACS (Recommended)

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=cinderblock&repository=ha-kastle&category=integration)

Or add manually:

1. Open HACS in Home Assistant
2. Click the three-dot menu → **Custom repositories**
3. Add `https://github.com/cinderblock/ha-kastle` with category **Integration**
4. Search for "Kastle Access" and click **Install**
5. Restart Home Assistant

### Manual

1. Copy the `custom_components/kastle/` folder into your Home Assistant `config/custom_components/` directory
2. Restart Home Assistant

## Setup

1. Go to **Settings → Devices & Services → Add Integration**
2. Search for **Kastle Access**
3. Enter your Kastle account email, country code, and phone number
4. Check your email for a 6-digit verification PIN
5. Enter the PIN to complete setup

All authorized doors will automatically appear as lock entities.

## Usage

Each door appears as a lock entity. Use the **Unlock** action to momentarily unlatch the door (same as tapping "Remote Unlock" in the Kastle app).

Doors auto-lock, so the entity always returns to the "Locked" state after a few seconds.

### Rediscover Readers

If your access permissions change, call the `kastle.rediscover_readers` service to refresh the list of available doors.

### Automations

```yaml
# Example: unlock the front gate when arriving home
automation:
  - trigger:
      - platform: zone
        entity_id: person.cameron
        zone: zone.home
        event: enter
    action:
      - service: lock.unlock
        target:
          entity_id: lock.front_entry_gate_14
```

## How It Works

This integration communicates directly with Kastle's cloud API (`mykastle.com`). It generates its own EC P-256 keypair and registers as a device, just like the official Kastle Presence mobile app. Each unlock request is signed with ECDSA, using the same protocol the app uses.

**Important**: Setting up this integration will de-register the Kastle Presence app on your phone (only one device can be registered at a time). You can re-register the app by logging in again, but that will invalidate this integration's credentials (triggering a re-auth flow).

## Troubleshooting

- **"Authentication expired"**: Your security token has expired. The integration will prompt you to re-authenticate with a new PIN.
- **No readers found**: Call `kastle.rediscover_readers` or check that your Kastle account has remote unlock permissions.
- **Unlock fails**: Check the Home Assistant logs (`Logger: custom_components.kastle`) for detailed error messages.

## License

MIT
