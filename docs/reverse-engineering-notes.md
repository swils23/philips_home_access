# Reverse-engineering notes

Working notes from adding shared-account control, activity data, credential
(PIN/fingerprint) management, and share management to this integration. Kept so
the next person (or a later capture session) can finish the parts that are
blocked on one missing value.

## The cloud API at a glance

Three cooperating hosts, not one:

| Host | Serves | Auth |
| --- | --- | --- |
| `user-oneness.juziwulian.com` | `/homeaccess/oauth/login`, account (`/homeaccess/account`, 405 on POST → it's GET) | static `LOGIN_STATIC_TOKEN` for login; per-user `token` after |
| `api.idlespacetech.com` | `/homeaccess/device/list`, `/v3/*`, `/v4/*` (lock/unlock, attrs, auto-lock) | per-user `token` + RSA signature in body |
| **north-america datacenter host** (unresolved) | `/app/*`, `/philips/record/*`, `/philips/device/secret/*` (activity, PINs, sharing) | per-user `token` + signature; exact scheme unconfirmed |

`login` returns `data.users[]`, one entry per region/datacenter the account
belongs to, each with its own `token` (and `dataCenter`, e.g. `north-america`).
Regions seen live: `PhilipsOneness`, `PhilipsSingapore`, `PhilipsNorthAmerica`
(dataCenter `north-america`), `PhilipsNorthAmericaNew` (`north-america-new`).
The integration's `REGIONS` was missing `PhilipsNorthAmericaNew` — added.

## Signing

- **idlespacetech `/v3`,`/v4`**: `sign = base64(RSA_PKCS1v15_sign(SHA256(canonical)))`,
  where `canonical = json.dumps(payload, sort_keys=True, separators=(",",":"))`.
  This is what the integration already does and it works.
- **The app's newer client** (from the decompiled Hermes bundle) builds the
  signature with JSEncrypt: `sign256(data, priv) = hex2b64(RSA.sign(SHA256(data)))`
  → also base64, BUT the signed string is `JSON.stringify(signObject)` in
  **insertion order** (not sorted), and the sign-object is often a specific
  subset (e.g. `{reqTime, wifiSN}`) distinct from the request body.
- The private key the app signs with (bundle offset ~line 181947 of the Hermes
  disassembly) is **byte-identical** to `RSA_PRIVATE_SIGN` in `const.py`.

## The shared-account model (feature: shared control) — SOLVED

`get_devices` on idlespacetech returns shared devices under **`wifiList`**, same
key as owned devices, with these extra fields on a shared lock:

- `isAdmin: 0` (owner sees `1`)
- `adminUid`, `adminName` (the owner)
- `shareUid` (this account), `shareId` (the share relationship id)
- `shareUserType: 1`
- `userNumberId: 0` — **same as the owner**, so the hardcoded `userNumberId: 0`
  in `set_lock_state` is NOT a blocker; shared lock/unlock uses the identical
  path and works. Verified: the shared account reads the lock's `device/list`
  and `query-device-attr` fine.

So shared-account control needs no new endpoints — only robust device discovery
(scan every list key, not just `wifiList`) and the region fix. Both done.

## Endpoints recovered from the app (Hermes/React Native bundle)

Extracted from `com.conex.philips` v4.19.2 base APK `assets/index.android.bundle`
(Hermes bytecode v96) by disassembling the string table. `/pages/*` entries are
in-app screens, not API calls, and are excluded.

**Activity / history (feature: notifications for unlock, etc.)**
- `/app/record/operation/latest` — newest event(s); ideal for polling
- `/app/record/operation/list` — paged history (`pageNo`,`pageSize`)
- `/app/record/operation/alarm` — alarms (duress, tamper)
- `/app/record/operation/visit` — visitor records
- `/app/activity-log/logs`
- `/philips/record/operation/{list,latest,alarm,visit}` — tenant-prefixed twins

**PIN / credential CRUD (feature: manage PINs/fingerprints)**
- `/app/iot/ble/device/user/key/create|update|delete` — credentials; the type
  (password/PIN, fingerprint, card, face) is a field in the payload
- `/philips/device/secret/setPolicyPwd|delPolicyPwd` — temporary/policy PINs
- `/philips/device/secret/oneKeyUnlock`, `/philips/device/secret/key`

**Sharing management (feature: manage sharing from the plugin)**
- `/app/wifi/share/add|del|list|updatenickname`
- `/app/iot/ble/device/user/create|delete|update|list|sync|nickname/update`
- account creation: `/app/user/sendToken` → `/app/user/checkCode` →
  `/app/user/reg/putuserbyemail`; also `/app/user/getRegions`, `/app/user/getUserInfo`

Full extracted path list: `tools/apipaths.txt` (generated; see discovery tools).

## The blocker (features: activity, PINs, sharing)

All `/app/*` and `/philips/record|secret|share/*` endpoints return a uniform
`code: 500` via `user-oneness` and `404` via `idlespacetech`, for **every**
method/header/body/signature combination — including a bare-token `getUserInfo`.
A uniform 500 independent of the request means the request never reaches the
handler: `user-oneness` proxies `/app/*` to the account's **datacenter** service
and that hop fails from this entry host. The datacenter base URL is resolved at
runtime (Huawei GRS / dbankcloud style) — it is **not** a literal in the bundle,
**not** in the login response, and **not** DNS-guessable (tried the obvious
`user-northamerica`, `api-na`, etc. — none resolve).

### How to finish it (one capture)

Point a proxy at the real app once and grab a single `/app/*` request:

1. Run the app on Android with a system-trusted mitmproxy CA (see
   `../android-re/` for the workbench, or a physical device).
2. Open the lock's **activity/history** screen (fires `/app/record/operation/*`).
3. From the captured request, record: the **Host**, the full **header set**
   (esp. any `k-*`, `appId`, `sign*`, `nonce`), and the exact request **body**.

With those three facts, fill in `PhilipsHomeAccessAPI._app_host` and
`_app_request()` in `api.py` (structure + endpoints already in place) and the
activity/PIN/share features light up. Everything else is already wired.

Note: the app is React Native + Hermes, arm64-only in the APKPure build; a plain
x86_64 emulator can't run it without an x86_64/universal build or an
ARM-translation system image.
