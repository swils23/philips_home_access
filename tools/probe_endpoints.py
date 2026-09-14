#!/usr/bin/env python3
"""Probe the exact endpoints recovered from the app's JS bundle.

Read-only endpoints only, so it is safe to run against a live account: it never
locks, unlocks, shares, or deletes anything. It resolves which host serves the
`/app/*` and `/philips/*` paths and prints the real response schema for the
activity feed and share list, which the integration then models.
"""
from __future__ import annotations
import argparse, base64, importlib.util, json, pathlib, sys, time

import requests
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

_C = pathlib.Path(__file__).resolve().parent.parent / "custom_components/philips_home_access/const.py"
_s = importlib.util.spec_from_file_location("_c", _C); _m = importlib.util.module_from_spec(_s); _s.loader.exec_module(_m)
LOGIN_STATIC_TOKEN, RSA_PRIVATE_SIGN, REGIONS = _m.LOGIN_STATIC_TOKEN, _m.RSA_PRIVATE_SIGN, _m.REGIONS

LOGIN_URL = "https://user-oneness.juziwulian.com/homeaccess/oauth/login"
# Candidate hosts to resolve the /app and /philips path prefixes against.
HOSTS = ["https://api.idlespacetech.com", "https://user-oneness.juziwulian.com"]

# Read-only endpoints only. (esn, uid, paging) get filled per-request.
READ_ENDPOINTS = [
    "/app/record/operation/latest",
    "/app/record/operation/list",
    "/app/record/operation/alarm",
    "/app/record/operation/visit",
    "/app/activity-log/logs",
    "/philips/record/operation/list",
    "/philips/record/operation/latest",
    "/app/wifi/share/list",
    "/app/iot/ble/device/user/list/",
    "/philips/device/secret/key",
]


def sign(payload: dict) -> str:
    key = RSA.import_key(RSA_PRIVATE_SIGN)
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return base64.b64encode(pkcs1_15.new(key).sign(SHA256.new(canonical.encode()))).decode()


def headers(token: str) -> dict:
    return {
        "token": token, "k-tenant": "philips", "k-version": "4.11.0",
        "k-language": "en_US", "k-signv": "1.0.0", "encrypt_data": "physical_encrypt_data",
        "reqSource": "app", "lang": "en_US", "language": "en_US",
        "timestamp": str(int(time.time() * 1000)), "Content-Type": "application/json",
    }


def login(user, pw, region):
    r = requests.post(LOGIN_URL, headers={
        "reqSource": "app", "lang": "en_US", "language": "en_US",
        "timestamp": str(int(time.time())), "token": LOGIN_STATIC_TOKEN,
        "Content-Type": "application/json; charset=utf-8",
    }, json={"identifier": user, "credential": pw, "areacode": "1"}, timeout=15).json()
    if r.get("code") != 200:
        sys.exit(f"login failed: {r.get('errCode')}")
    for u in r["data"]["users"]:
        if u.get("code") == region:
            return u["token"], u["uid"]
    sys.exit(f"region {region} not found; have {[u.get('code') for u in r['data']['users']]}")


def get_devices(token, uid):
    r = requests.post("https://api.idlespacetech.com/homeaccess/device/list",
                      headers={"token": token, "reqSource": "app",
                               "timestamp": str(int(time.time())), "Content-Type": "application/json; charset=utf-8"},
                      json={"uid": uid}, timeout=15).json()
    out = []
    for v in (r.get("data") or {}).values():
        if isinstance(v, list):
            out += [d for d in v if isinstance(d, dict) and d.get("wifiSN")]
    return out


def probe(host, path, token, uid, esn):
    now = str(int(time.time() * 1000))
    payload = {"esn": esn, "uid": uid, "wifiSN": esn, "pageNo": 1, "pageSize": 5, "reqTime": now}
    payload["sign"] = sign(payload)
    try:
        r = requests.post(host + path, headers=headers(token), json=payload, timeout=12)
    except requests.RequestException as e:
        return {"verdict": "ERROR", "detail": repr(e)[:80]}
    try:
        body = r.json()
    except ValueError:
        return {"verdict": "MISSING" if r.status_code == 404 else "NONJSON",
                "http": r.status_code, "text": r.text[:150]}
    code = str(body.get("code"))
    data = body.get("data")
    if r.status_code == 404 or code in ("404", "10404"):
        return {"verdict": "MISSING", "http": r.status_code, "code": code, "msg": body.get("msg")}
    if code == "200":
        v = "HIT" if data not in (None, [], {}) else "EMPTY"
        return {"verdict": v, "code": code, "data": data, "keys_hint": _shape(data)}
    return {"verdict": "EXISTS", "http": r.status_code, "code": code, "msg": body.get("msg")}


def _shape(data):
    if isinstance(data, dict):
        # If it wraps a list, describe the first record's fields.
        for k, v in data.items():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                return {"list_key": k, "count": len(v), "record_fields": sorted(v[0].keys())}
        return {"dict_keys": sorted(data.keys())}
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return {"count": len(data), "record_fields": sorted(data[0].keys())}
    return type(data).__name__


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--username", required=True)
    ap.add_argument("-p", "--password", required=True)
    ap.add_argument("-r", "--region", default=REGIONS[0])
    ap.add_argument("-o", "--out")
    args = ap.parse_args()

    token, uid = login(args.username, args.password, args.region)
    devices = get_devices(token, uid)
    locks = [d for d in devices if d.get("deviceType") == "LOCK"]
    if not locks:
        sys.exit("no lock visible to this account")
    esn = locks[0]["wifiSN"]
    print(f"account uid={uid[:6]}*** lock esn={esn[:4]}*** ({len(devices)} devices)\n")

    report = {}
    for path in READ_ENDPOINTS:
        best_host, best = None, None
        for host in HOSTS:
            res = probe(host, path, token, uid, esn)
            if best is None or _rank(res["verdict"]) > _rank(best["verdict"]):
                best, best_host = res, host
            if res["verdict"] in ("HIT", "EXISTS"):
                break
            time.sleep(0.2)
        report[path] = {"host": best_host, **best}
        mark = {"HIT": "***", "EXISTS": " ->", "EMPTY": " ->"}.get(best["verdict"], "   ")
        print(f"{mark} {best['verdict']:7} {path}")
        print(f"      host={best_host}  { {k:v for k,v in best.items() if k in ('code','msg','http','keys_hint')} }")

    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(report, indent=2, default=str))
        print(f"\nfull report -> {args.out}")


def _rank(v):
    return {"HIT": 5, "EXISTS": 4, "EMPTY": 3, "NONJSON": 2, "ERROR": 1, "MISSING": 0}.get(v, 0)


if __name__ == "__main__":
    main()
