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

## Status per feature

**Sharing (`/wifi/share/*`): working and verified live.**
`POST https://api.homeaccesstech.com/wifi/share/list` with body
`{"uid":...,"wifiSN":...,"sign":...,"reqTime":...}`, signature over the
insertion-ordered subset `{"reqTime":...,"wifiSN":...}`, returns `code:200` with
the real share list (`_id` = shareId, `uname`, `userNickname`). `add`/`del`/
`updatenickname` use the same host and scheme with the bundle's field names.
Wired in `api.py` (`list_shares`/`add_share`/`delete_share`) and exposed as the
`add_share`/`remove_share` services.

**Activity (`/homeaccess/record/operation/{latest,list,alarm}`) and credentials
(`/homeaccess/device/user/*`, keys): host + route confirmed, exact request body
still open.** These return `code:500` (route exists — a wrong path 404s) for
every body/param/sign/encrypt combination tried directly, while `/wifi/share/list`
and `/homeaccess/device/list` on the same host with the same signing return 200.
So the record/credential endpoints need a request shape the app produces that
direct probing hasn't reproduced. They are wired to the right host and paths;
the remaining work is to confirm the body from one capture of the app's own
request (it only makes these once logged in and viewing a lock's activity).

### Finishing activity + credentials (one capture)

With the workbench (`../android-re/`, `CAPTURE.md`): the arm64 app runs on the
API 36 x86_64 image (ARM translation), mitmproxy decrypts the Philips API hosts
after the CA is added to the conscrypt APEX store (`re.ps1 cert` handles Android
14+). Log into the app (owner account), open a lock's **activity** screen, and
read the `POST .../record/operation/*` request body from mitmweb. Match it in
`api.py` `get_activity`/`get_latest_activity`. Note a couple of analytics/login
hosts pin certificates (Frida `unpin` if login must go through the proxy).
