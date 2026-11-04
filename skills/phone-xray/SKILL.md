---
name: phone-xray
description: Audit an Android phone or TV the user owns over adb. Use when the user asks what their phone or TV can leak, which apps can read data and upload it, or wants to debloat or block trackers with a way to undo.
---

# phone-xray

Run from the repo root. It needs Python 3 and, for a real device, `adb`.

1. Try it with no device: `python phone_xray.py --demo`
2. Audit a USB device: `python phone_xray.py`
3. Audit a TV on Wi-Fi: `python phone_xray.py --connect <ip>:5555`
4. Read `xray-report/report.json` and explain the top findings in plain language. A score shows what an app could do, not what it does.
5. Show the user `xray-report/plan.txt` and get a clear yes before any change.
6. Apply only after that yes: `python phone_xray.py --apply`
7. Undo: `python phone_xray.py --undo xray-report/rollback.txt`

Rules:
- Only audit devices the user owns or is authorized to audit.
- Do not add packages to the plan by hand. Protected packages are protected for a reason.
- `blocklist.txt` holds tracker hosts only. Do not add hosts from the "do not block" list.
