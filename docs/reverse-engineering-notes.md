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
| **`api.homeaccesstech.com`** (North America datacenter; mirror `api.securelocktech.com`) | sharing (`/wifi/share/*`), activity (`/homeaccess/record/operation/*`), credentials (`/homeaccess/device/user/*`) | per-user `token` + RSA signature in body |

**The datacenter host was recovered by running the app** (see `../android-re/CAPTURE.md`):
on an emulator whose image has ARM translation (`ro.dalvik.vm.native.bridge=
libndk_translation.so`, e.g. the API 36 google_apis x86_64 image), the arm64-only
APK installs and runs. Routed through mitmproxy, the app hits **`api.homeaccesstech.com`**
(and `api.securelocktech.com`) at startup — the base URL its `getRegions` response
returns as `appHttpAddr` for North America. It is not present in the APK (JS bundle
or native libs) or the login response; it is fetched at runtime. Other regions have
their own host.

Note the server drops the app's `/app/` route prefix: the JS calls
`/app/wifi/share/list`, the server path is `/wifi/share/list`.

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

## Status per feature — all confirmed live

The real server paths were captured by driving the running app through mitmproxy
(`../android-re/CAPTURE.md`). The app's JS route names are NOT the server paths.
All of the below return `code:200` with real data via `api.homeaccesstech.com`,
using the header set `token`, `k-tenant: philips`, `k-version: 4.19.2`,
`k-language: en_US`, `k-signv: 1.0.0`, and a body signature that is
`base64(RSA-PKCS1v15(SHA256(JSON.stringify(<signed subset, insertion order>))))`.

| Feature | Server path | Body | Signed subset |
| --- | --- | --- | --- |
| Activity | `POST /v3/device/operation-list` | `{esn, page}` (page int) | `{esn, page, reqTime}` |
| Credentials (PIN + fingerprint) | `POST /v3/device/key-list` | `{esn}` | `{esn, reqTime}` |
| Sharing | `POST /wifi/share/list` | `{uid, wifiSN}` | `{reqTime, wifiSN}` |

- **Activity** `data` is a list of records: `{_id, wifiSN, eventType, eventCode,
  eventSource, createTime, timesTamp, type, userId, userNickname, pwdNickname,
  uid, timeZone}`. The numeric event codes are not fully documented; the event
  platform exposes them raw and a non-empty `pwdNickname` marks a PIN use.
- **Credentials** `data` groups by type: `pwdList` (PINs, each `{_id, num,
  nickName, pwdValue, type, uid}`), `fingerprintList`, `faceList`, `cardList`,
  `offlinePwdList`, `timePwdList`, `palmList`.
- **Sharing** `data` is the share list (`_id` = shareId, `uname`, `userNickname`).

Signature verification is strict on `/v3/device/*` (a wrong signed-subset returns
`code:594 "Signature Verification Failed"`) and lenient on `/wifi/share/*`. The
signing was cross-checked by reproducing a captured `function-List` signature and
the captured `operation-list` / `key-list` signatures byte-for-byte
(see `tests/test_logic.py::test_activity_signature_matches_captured`).

**Credential create/delete: captured, but deliberately NOT wired to fire.**
Captured live by adding and removing a test PIN (a permanent PIN, `pwdType: 1`):

Create is three steps:
1. `POST /v3/device/insert-pwd` — `{encryptData: <RSA-encrypted>}`, the device-
   programming step (encrypted with the public key like `set_lock_state`;
   plaintext unknown).
2. `POST /v3/device/ble-add-key-list` — `{esn, sign, reqTime, pwdList: [...]}`
   where `pwdList` is the **entire** credential list (`{pwdValue, pwdType,
   nickName, num, type, createTime, startTime, endTime}`). **This is a full-list
   replace**: sending only the new entry wipes every existing PIN — observed live
   (a test add reduced three PINs to one). A correct create MUST read the current
   list and send existing + new together.
3. `POST /v3/device/update-key-nickname` — `{esn, handMode, pwdType, num, sign,
   reqTime, nickname}`, sets the name.

Delete is targeted (safer):
1. `POST /v3/device/remove-pwd` — `{esn, sign, reqTime, params:{partsSn, partsMac,
   keyNum, keyType}}`.
2. `POST /v3/device/ble-remove-pwd-list` — `{esn, sign, reqTime, pwdList:[{pwdType,
   num}]}`.

**Write signing is solved.** These `/v3/device/*` endpoints (on
`api.idlespacetech.com`, the `set_lock_state` family — *not* the newer
homeaccesstech reads) sign the **whole body with SORTED keys** — the integration's
existing `_sign`, not the reads' insertion-order `_sign_app`. Reproduced the
captured `ble-add-key-list`, `remove-pwd`, `ble-remove-pwd-list` and
`update-key-nickname` signatures byte-for-byte.

- **`delete_key` is implemented and functional**: `remove-pwd` (device, plaintext)
  then `ble-remove-pwd-list` (registry), both targeted by the slot number — it
  cannot touch any other slot, so it needed no destructive live test.
- **`create_pin` still raises.** Two things remain, and both need writes to a
  physical lock to confirm: (1) the encrypted device step
  `POST /v3/device/insert-pwd` — `{encryptData}` wrapping a sorted-signed payload
  (like `set_lock_state`) whose ~351-byte (3 RSA block) field schema is
  unconfirmed; a registry-only create (skipping it) would list a PIN that does
  not open the door. (2) `ble-add-key-list` is a full-list REPLACE, so create must
  resend every existing entry (reconstructed from `key-list`, which omits
  `createTime`/`startTime`/`endTime`) plus the new one — trustworthy only once
  tested live. A careful live trial on a free slot (never including existing
  entries, cleaned up after) is the way to finish it.

### How the capture was done

The arm64-only APK (`com.conex.philips`) runs on the **API 36 google_apis
x86_64** emulator image (ARM translation: `ro.dalvik.vm.native.bridge=
libndk_translation.so`). mitmproxy decrypts the Philips API hosts once the CA is
added to the conscrypt APEX store (`re.ps1 cert`, Android 14+). The login host
`user-oneness.juziwulian.com` **pins** its certificate, so log in with the proxy
off (direct), then turn the proxy on and open the lock's Activities / PIN /
Fingerprint screens to capture `operation-list` / `key-list`. Full runbook:
`../android-re/CAPTURE.md`.
