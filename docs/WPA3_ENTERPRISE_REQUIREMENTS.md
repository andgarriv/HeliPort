# WPA3-Enterprise Status

This repository contains HeliPort + ClientKit.
WPA3-Enterprise behavior depends on the paired `itlwm` build.

## What Is Already Wired In This Repo

- WPA2/WPA3 Enterprise security types are detected and represented in UI.
- Enterprise credentials (`username`, `password`, `identity`) are captured and persisted.
- `ClientKit` exposes `KEYAVAIL/KEYRUN` bridge calls (`set_key_available`, `run_key`) to feed PMK into the kext RSN state machine.
- HeliPort now has an integrated EAP-TTLS launch path that starts `wpa_supplicant` with administrator privileges.
- During enterprise connect, HeliPort waits for supplicant completion and then relies on the authenticated state from supplicant/net80211.

## Current Limitations

1. The integrated supplicant path currently targets EAP-TTLS + MSCHAPv2 only.
2. `wpa_supplicant`/`wpa_cli` must be installed on the host (searched in `/opt/homebrew`, `/usr/local`, `/usr/sbin`).
3. Full enterprise profile transport is still missing in the app/kext API (method selection, cert chain, anonymous identity, phase2 variants).
4. Capability negotiation is still missing (driver does not tell HeliPort which enterprise modes are truly supported).

## Practical Notes

- HeliPort will request admin rights when starting the integrated supplicant flow.
- If `password` is provided as a 64-hex PMK (optionally prefixed by `pmk:`), HeliPort uses the direct `KEYAVAIL/KEYRUN` path instead of EAP-TTLS.
