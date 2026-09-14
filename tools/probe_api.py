#!/usr/bin/env python3
"""Discovery probe for the Philips Home Access cloud API.

The API is undocumented, so this script does two jobs:

1. Dumps exactly what an account sees from the device list and attribute
   endpoints. Run it with a *shared* account to find out which keys shared
   devices arrive under and which user slot the account occupies.
2. Sweeps a ranked list of candidate activity/history endpoints and reports
   which ones exist, so the activity feed can be wired to a real route.

Output is redacted by default and safe to paste into an issue or a chat.
Pass --raw to see unredacted values locally.

Usage:
    pip install requests pycryptodome
    python3 tools/probe_api.py -u you@example.com -p 'password' -r PhilipsNorthAmerica
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import pathlib
import sys
import time
from typing import Any

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

try:
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
except ImportError:
    sys.exit("Missing dependency: pip install pycryptodome")


# --- Load the integration's constants without importing the HA package -------

_CONST_PATH = (
    pathlib.Path(__file__).resolve().parent.parent
    / "custom_components"
    / "philips_home_access"
    / "const.py"
)
_spec = importlib.util.spec_from_file_location("_pha_const", _CONST_PATH)
_const = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_const)

LOGIN_STATIC_TOKEN = _const.LOGIN_STATIC_TOKEN
RSA_PRIVATE_SIGN = _const.RSA_PRIVATE_SIGN
REGIONS = _const.REGIONS

LOGIN_URL = "https://user-oneness.juziwulian.com/homeaccess/oauth/login"
API_HOST = "https://api.idlespacetech.com"


# --- Redaction ---------------------------------------------------------------

SENSITIVE_KEYS = {
    "token", "uid", "mac", "wifisn", "mastersn", "esn", "sign", "encryptdata",
    "email", "phone", "mobile", "identifier", "credential", "password",
    "nickname", "locknickname", "username", "account", "avatar", "headimg",
    "wifimac", "bluetoothmac", "ssid", "ip", "deviceid", "familyid", "homeid",
}

_raw_mode = False


def redact(obj: Any, key: str | None = None) -> Any:
    """Recursively mask sensitive values while preserving structure and types."""
    if _raw_mode:
        return obj
    if isinstance(obj, dict):
        return {k: redact(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v, key) for v in obj]
    if key and key.lower() in SENSITIVE_KEYS and obj not in (None, "", 0):
        text = str(obj)
        head = text[:4] if len(text) > 8 else ""
        return f"<{head}***len={len(text)}>"
    return obj


def dump(label: str, obj: Any) -> None:
    print(f"\n----- {label} -----")
    print(json.dumps(redact(obj), indent=2, sort_keys=True, ensure_ascii=False)[:20000])


# --- Signing -----------------------------------------------------------------

def sign_payload(payload: dict) -> str:
    key = RSA.import_key(RSA_PRIVATE_SIGN)
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    digest = SHA256.new(canonical.encode())
    return base64.b64encode(pkcs1_15.new(key).sign(digest)).decode()


def api_headers(token: str) -> dict:
    return {
        "token": token,
        "k-tenant": "philips",
        "k-version": "4.11.0",
        "k-language": "en_US",
        "k-signv": "1.0.0",
        "encrypt_data": "physical_encrypt_data",
        "reqSource": "app",
        "lang": "en_US",
        "language": "en_US",
        "timestamp": str(int(time.time() * 1000)),
        "Content-Type": "application/json",
    }


# --- Candidate activity endpoints -------------------------------------------
#
# Ranked by how closely they follow the naming of the six endpoints the
# integration already uses:
#   /homeaccess/device/list, /v3/api/device/set-am-mode,
#   /v3/api/device/set-auto-lock-time, /v3/device/{open,close}-device,
#   /v3/gateway/set-lock-{open,close}, /v4/device/query-device-attr

CANDIDATE_PATHS = [
    # v4 query-* family (same generation as query-device-attr)
    "/v4/device/query-device-record",
    "/v4/device/query-device-log",
    "/v4/device/query-device-event",
    "/v4/device/query-open-record",
    "/v4/device/query-operation-record",
    "/v4/device/query-device-history",
    "/v4/device/query-lock-record",
    "/v4/device/query-device-message",
    "/v4/message/query-message-list",
    "/v4/message/query-message-record",
    # v3/api/device family (same generation as set-am-mode)
    "/v3/api/device/record-list",
    "/v3/api/device/operation-record",
    "/v3/api/device/open-record",
    "/v3/api/device/log-list",
    "/v3/api/device/event-list",
    "/v3/api/device/history-list",
    "/v3/api/device/alarm-list",
    "/v3/api/device/get-record",
    "/v3/api/message/list",
    "/v3/api/message/record-list",
    # v3/device family (same generation as open-device)
    "/v3/device/record-list",
    "/v3/device/query-record",
    "/v3/device/device-record",
    "/v3/device/open-record",
    # homeaccess family (same generation as device/list)
    "/homeaccess/device/record/list",
    "/homeaccess/device/log/list",
    "/homeaccess/device/event/list",
    "/homeaccess/record/list",
    "/homeaccess/message/list",
    "/homeaccess/device/operation/list",
]

# Payload shapes to try per path. Pagination naming varies across this vendor's
# endpoints, so try the three common conventions plus a bare esn.
def payload_variants(esn: str, uid: str) -> list[tuple[str, dict]]:
    now = str(int(time.time() * 1000))
    return [
        ("pageNo/pageSize", {"esn": esn, "pageNo": 1, "pageSize": 20, "reqTime": now}),
        ("pageNum/pageSize", {"esn": esn, "pageNum": 1, "pageSize": 20, "reqTime": now}),
        ("page/size+uid", {"esn": esn, "uid": uid, "page": 1, "size": 20, "reqTime": now}),
        ("bare esn", {"esn": esn, "reqTime": now}),
    ]


def classify(status: int, body: Any) -> tuple[str, str]:
    """Return (verdict, detail). Distinguishes 'no such route' from 'bad params'."""
    if status == 404:
        return "MISSING", "404 not found"
    if status in (401, 403):
        return "AUTH", f"http {status}"
    if not isinstance(body, dict):
        return "MISSING", f"http {status}, non-JSON"

    code = str(body.get("code", ""))
    msg = body.get("msg") or body.get("errCode") or ""
    data = body.get("data")

    if code == "200":
        if data:
            return "HIT", f"code 200 with data ({type(data).__name__})"
        return "EMPTY", "code 200 but data empty (route exists)"
    if code == "444":
        return "EXPIRED", "session expired (code 444) - re-run, app may have stolen the session"
    if code in ("404", "10404"):
        return "MISSING", f"code {code} {msg}"
    # A parameter/validation complaint means the route is real.
    return "EXISTS", f"code {code} {msg}"


def main() -> int:
    global _raw_mode

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-u", "--username", required=True)
    ap.add_argument("-p", "--password", required=True)
    ap.add_argument("-r", "--region", default=REGIONS[0], choices=REGIONS)
    ap.add_argument("--raw", action="store_true", help="do not redact output (local use only)")
    ap.add_argument("--skip-probe", action="store_true", help="only dump account/device data")
    ap.add_argument("-o", "--out", help="also write full report to this JSON file")
    ap.add_argument("--delay", type=float, default=0.25,
                    help="seconds between probe requests (default 0.25, be polite)")
    args = ap.parse_args()

    _raw_mode = args.raw
    report: dict[str, Any] = {"region": args.region}

    print("=" * 72)
    print("NOTE: logging in here signs this account out of the Philips app.")
    print("Run this with the SHARED account, not the owner account, so the")
    print("owner's app session stays alive.")
    print("=" * 72)

    # --- 1. Login -----------------------------------------------------------
    print("=== LOGIN ===")
    resp = requests.post(
        LOGIN_URL,
        headers={
            "reqSource": "app",
            "lang": "en_US",
            "language": "en_US",
            "timestamp": str(int(time.time())),
            "token": LOGIN_STATIC_TOKEN,
            "Content-Type": "application/json; charset=utf-8",
        },
        json={"identifier": args.username, "credential": args.password, "areacode": "1"},
        timeout=15,
    )
    login = resp.json()
    print(f"http {resp.status_code}, code {login.get('code')}, errCode {login.get('errCode')}")
    if login.get("code") != 200:
        print("Login failed. Check credentials/region.")
        return 1

    users = login.get("data", {}).get("users", [])
    dump("LOGIN users[] (shows every region/tenant this account belongs to)", users)
    report["login_users"] = redact(users)

    token = uid = None
    for user in users:
        if user.get("code") == args.region:
            token, uid = user.get("token"), user.get("uid")
    if not token:
        print(f"\nRegion {args.region} not present. Try one of: "
              f"{[u.get('code') for u in users]}")
        return 1
    print(f"\nAuthenticated. uid={redact(uid, 'uid')}")

    # --- 2. Device list -----------------------------------------------------
    print("\n=== DEVICE LIST (full raw structure) ===")
    resp = requests.post(
        f"{API_HOST}/homeaccess/device/list",
        headers={
            "token": token,
            "reqSource": "app",
            "timestamp": str(int(time.time())),
            "Content-Type": "application/json; charset=utf-8",
        },
        json={"uid": uid},
        timeout=15,
    )
    devlist = resp.json()
    data_block = devlist.get("data") or {}

    # The integration only reads data.wifiList. Show every key so we can see
    # whether shared devices arrive somewhere else entirely.
    print(f"http {resp.status_code}, code {devlist.get('code')}")
    print("\nKEYS UNDER data: (integration currently reads only 'wifiList')")
    for key, value in sorted(data_block.items()):
        shape = f"list[{len(value)}]" if isinstance(value, list) else type(value).__name__
        flag = "  <-- READ TODAY" if key == "wifiList" else ""
        print(f"  {key}: {shape}{flag}")

    dump("FULL device/list response", devlist)
    report["device_list"] = redact(devlist)

    # Collect devices from every list-shaped key, not just wifiList.
    devices = []
    for key, value in data_block.items():
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    devices.append((key, item))

    print(f"\nFound {len(devices)} device object(s) across all keys.")
    for source_key, device in devices:
        print(f"  [{source_key}] type={device.get('deviceType')} "
              f"model={device.get('productModel')} "
              f"esn={redact(device.get('wifiSN'), 'wifiSN')} "
              f"masterSn={redact(device.get('masterSn'), 'masterSn')}")

    # Surface any field that looks like a per-user slot. set_lock_state()
    # hardcodes userNumberId=0, which is very likely the owner's slot.
    print("\nFIELDS THAT LOOK LIKE A USER SLOT / SHARE ROLE:")
    slot_hits = {}
    for source_key, device in devices:
        for field, value in device.items():
            low = field.lower()
            if any(t in low for t in ("usernumber", "userid", "role", "share", "admin", "owner", "permission", "member")):
                slot_hits[f"{source_key}.{field}"] = value
    if slot_hits:
        for field, value in sorted(slot_hits.items()):
            print(f"  {field} = {value!r}")
    else:
        print("  (none found - shared role may only appear in the attr call below)")
    report["user_slot_fields"] = slot_hits

    locks = [d for _, d in devices if d.get("deviceType") == "LOCK"]
    if not locks:
        print("\nNo LOCK devices visible to this account. Stopping.")
        return 1
    esn = locks[0].get("wifiSN")

    # --- 3. Device attributes ----------------------------------------------
    print("\n=== QUERY-DEVICE-ATTR ===")
    now = str(int(time.time() * 1000))
    payload = {"esn": esn, "reqTime": now}
    payload["sign"] = sign_payload(payload)
    resp = requests.post(
        f"{API_HOST}/v4/device/query-device-attr",
        headers=api_headers(token), json=payload, timeout=15,
    )
    attr = resp.json()
    dump("query-device-attr", attr)
    report["device_attr"] = redact(attr)

    if args.skip_probe:
        _write(args, report)
        return 0

    # --- 4. Endpoint sweep --------------------------------------------------
    print(f"\n=== PROBING {len(CANDIDATE_PATHS)} CANDIDATE ACTIVITY ENDPOINTS ===")
    print("Looking for HIT (returned records) or EXISTS (route real, params wrong).\n")

    findings = []
    for path in CANDIDATE_PATHS:
        url = f"{API_HOST}{path}"
        best = None
        for shape_name, base_payload in payload_variants(esn, uid):
            body = dict(base_payload)
            body["sign"] = sign_payload(body)
            time.sleep(args.delay)
            try:
                resp = requests.post(url, headers=api_headers(token), json=body, timeout=10)
            except requests.RequestException as err:
                best = ("ERROR", repr(err)[:80], shape_name, None)
                break
            try:
                parsed = resp.json()
            except ValueError:
                parsed = resp.text[:200]
            verdict, detail = classify(resp.status_code, parsed)
            if best is None or _rank(verdict) > _rank(best[0]):
                best = (verdict, detail, shape_name, parsed)
            if verdict == "HIT":
                break

        verdict, detail, shape_name, parsed = best
        marker = {"HIT": "***", "EXISTS": " ->", "EMPTY": " ->"}.get(verdict, "   ")
        print(f"{marker} {verdict:8} {path}  [{shape_name}]  {detail}")
        if verdict in ("HIT", "EXISTS", "EMPTY"):
            findings.append({"path": path, "verdict": verdict, "detail": detail,
                             "payload_shape": shape_name, "response": redact(parsed)})

    report["probe_findings"] = findings

    print("\n=== SUMMARY ===")
    hits = [f for f in findings if f["verdict"] == "HIT"]
    if hits:
        print(f"{len(hits)} endpoint(s) returned records:")
        for finding in hits:
            print(f"  {finding['path']}  (payload: {finding['payload_shape']})")
            dump(f"RECORDS from {finding['path']}", finding["response"])
    elif findings:
        print("No endpoint returned records, but these routes appear to exist")
        print("(they rejected params rather than 404ing) - worth a closer look:")
        for finding in findings:
            print(f"  {finding['verdict']:8} {finding['path']}  {finding['detail']}")
    else:
        print("Nothing found. The activity endpoint needs a traffic capture:")
        print("  1. Install HTTP Toolkit (httptoolkit.com) or mitmproxy")
        print("  2. Proxy your phone through it, trust the CA cert")
        print("  3. Open the Philips app -> lock -> activity/history screen")
        print("  4. Look for a POST to api.idlespacetech.com and share it")
        print("\nIf the app pins certificates, the records may instead arrive")
        print("via push notification rather than a pollable endpoint.")

    _write(args, report)
    return 0


def _rank(verdict: str) -> int:
    return {"HIT": 5, "EXISTS": 4, "EMPTY": 3, "AUTH": 2, "EXPIRED": 2,
            "ERROR": 1, "MISSING": 0}.get(verdict, 0)


def _write(args, report: dict) -> None:
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False))
        print(f"\nReport written to {args.out}"
              f"{' (UNREDACTED)' if args.raw else ' (redacted, safe to share)'}")


if __name__ == "__main__":
    sys.exit(main())
