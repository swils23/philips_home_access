import json
import time
import requests
import base64
import binascii
import logging

_LOGGER = logging.getLogger(__name__)

from .const import DEFAULT_APP_HOST, LOGIN_STATIC_TOKEN, RSA_HEX_KEY, RSA_PRIVATE_SIGN


class PhilipsSessionExpired(Exception):
    """The account's token was invalidated, usually by a login elsewhere."""


class PhilipsAppApiUnavailable(Exception):
    """A newer "/app/*" endpoint was called before its datacenter host is known.

    The activity, credential (PIN/fingerprint), and sharing features live on a
    datacenter-specific host that the app resolves at runtime. Until that host
    is configured on the API object, these methods raise this rather than send a
    request that cannot succeed. See docs/reverse-engineering-notes.md.
    """


# Field names in an operation-list record, from the live capture. `data` is a
# list of records shaped like:
#   {_id, wifiSN, eventType, eventCode, eventSource, createTime, timesTamp,
#    type, userId, userNickname, pwdNickname, uid, timeZone, tenant}
# The first present candidate wins, so the parser tolerates minor variations.
_RECORD_LIST_KEYS = ("list", "records", "rows", "content", "items", "logs")
_RECORD_ID_KEYS = ("_id", "recordId", "id", "logId", "eventId")
_RECORD_TIME_KEYS = ("createTime", "timesTamp", "timesTamp2", "recordTime", "eventTime", "time")
_RECORD_TYPE_KEYS = ("eventCode", "eventType", "recordType", "type", "eventSource")
_RECORD_USER_KEYS = ("userNickname", "pwdNickname", "userName", "nickName", "userId")


class PhilipsHomeAccessAPI:
    def __init__(self, username, password, region_code, app_host=None):
        self.username = username
        self.password = password
        self.region_code = region_code
        self.token = None
        self.uid = None
        self.data_center = None
        self.users_by_region = {}
        # Base URL for the newer datacenter endpoints (activity, credentials,
        # sharing). The app resolves this per region at runtime; for North
        # America it is api.homeaccesstech.com (mirror: api.securelocktech.com),
        # confirmed live. Other regions have their own host (from the app's
        # getRegions response). Overridable via the app_host option.
        self.app_host = app_host or DEFAULT_APP_HOST

    def _mask(self, value, keep=4):
        if not value:
            return None
        value = str(value)
        if len(value) <= keep:
            return "*" * len(value)
        return f"{value[:keep]}***"
    
    def _find_device(self, devices, wifi_sn):
        for device in devices:
            if device.get("wifiSN") == wifi_sn:
                return device
        return None

    def _normalize_mac(self, mac: str) -> str:
        if not mac:
            return ""
        cleaned = str(mac).replace(" ", "").replace(":", "").replace("-", "").upper()
        if len(cleaned) != 12:
            return cleaned
        return ":".join(cleaned[i:i+2] for i in range(0, 12, 2))

    def _get_lock_transport_info(self, lock_esn):
        """Return transport details for a lock.

        Result:
        {
            "mode": "direct" | "gateway",
            "lock": <lock device dict>,
            "gateway": <gateway device dict or None>,
        }
        """
        devices = self.get_devices()
        lock = self._find_device(devices, lock_esn)
        if not lock:
            raise Exception(f"lock_not_found:{lock_esn}")

        if lock.get("deviceType") != "LOCK":
            raise Exception(f"device_not_lock:{lock_esn}")

        master_sn = lock.get("masterSn")
        if master_sn:
            gateway = self._find_device(devices, master_sn)
            if gateway and gateway.get("deviceType") == "GATEWAY":
                return {
                    "mode": "gateway",
                    "lock": lock,
                    "gateway": gateway,
                }

        return {
            "mode": "direct",
            "lock": lock,
            "gateway": None,
        }

    def login(self):
        url = "https://user-oneness.juziwulian.com/homeaccess/oauth/login"
        headers = {
            "reqSource": "app",
            "lang": "en_US",
            "language": "en_US",
            "timestamp": str(int(time.time())),
            "token": LOGIN_STATIC_TOKEN,
            "Content-Type": "application/json; charset=utf-8",
        }
        payload = {
            "identifier": self.username,
            "credential": self.password,
            "areacode": "1",
        }

        _LOGGER.debug("Login start: username=%s region=%s", self._mask(self.username), self.region_code)

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            _LOGGER.debug("Login HTTP status=%s", response.status_code)
            data = response.json()
        except requests.RequestException as err:
            _LOGGER.debug("Login request failed: %r", err)
            raise Exception("cannot_connect") from err
        except ValueError as err:
            _LOGGER.debug("Login returned non-JSON response")
            raise Exception("unknown_error") from err

        _LOGGER.debug(
            "Login response code=%s errCode=%s users=%s",
            data.get("code"),
            data.get("errCode"),
            len(data.get("data", {}).get("users", [])),
        )

        if data.get("code") != 200:
            error_code = data.get("errCode")
            if error_code == "account_not_find":
                raise Exception("account_not_find")
            if error_code == "account_password_not_match":
                raise Exception("invalid_auth")
            raise Exception("unknown_error")

        users = data.get("data", {}).get("users", [])
        # Keep every region entry: each is a separate datacenter with its own
        # token, and the account-sharing flow may need to look tokens up by
        # region. Store them keyed by region code.
        self.users_by_region = {u.get("code"): u for u in users if u.get("code")}
        for user in users:
            if user.get("code") == self.region_code:
                self.token = user.get("token")
                self.uid = user.get("uid")
                self.data_center = user.get("dataCenter")
                _LOGGER.debug(
                    "Login success: region=%s dataCenter=%s uid=%s token_present=%s",
                    self.region_code,
                    self.data_center,
                    self._mask(self.uid),
                    bool(self.token),
                )
                return True

        _LOGGER.debug("Login succeeded but requested region was not found: region=%s", self.region_code)
        raise Exception("region_not_found")

    def get_devices(self):
        url = "https://api.idlespacetech.com/homeaccess/device/list"
        headers = {
            "token": self.token,
            "reqSource": "app",
            "timestamp": str(int(time.time())),
            "Content-Type": "application/json; charset=utf-8",
        }
        payload = {"uid": self.uid}

        _LOGGER.debug("get_devices start: uid=%s token_present=%s", self._mask(self.uid), bool(self.token))

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            _LOGGER.debug("get_devices HTTP status=%s", response.status_code)
            data = response.json()
        except requests.RequestException as err:
            _LOGGER.debug("get_devices request failed: %r", err)
            raise
        except ValueError as err:
            _LOGGER.debug("get_devices returned non-JSON response")
            raise

        if isinstance(data, dict) and str(data.get("code")) == "444":
            _LOGGER.debug("get_devices: session expired (code 444)")
            raise PhilipsSessionExpired("session_expired")

        devices = self._collect_devices(data.get("data") or {})
        _LOGGER.debug(
            "get_devices response code=%s device_count=%s sources=%s",
            data.get("code"),
            len(devices),
            sorted({d.get("_sourceList") for d in devices}),
        )
        return devices

    @staticmethod
    def _collect_devices(data_block):
        """Return every device in the payload, whatever key it arrived under.

        Devices the account owns come back under "wifiList". A device shared
        with the account from someone else's home is grouped under a different
        key, so reading only "wifiList" makes a shared account look empty.
        Every list-shaped key is scanned instead, and entries are identified by
        carrying a "wifiSN" so unrelated lists (banners, rooms) are skipped.
        """
        devices = []
        seen = set()
        for key, value in data_block.items():
            if not isinstance(value, list):
                continue
            for item in value:
                if not isinstance(item, dict):
                    continue
                esn = item.get("wifiSN")
                if not esn or esn in seen:
                    continue
                seen.add(esn)
                # Provenance, surfaced in diagnostics to show shared vs owned.
                item.setdefault("_sourceList", key)
                devices.append(item)
        return devices

    def query_device_attr(self, esn: str):
        from Crypto.PublicKey import RSA
        from Crypto.Hash import SHA256
        from Crypto.Signature import pkcs1_15

        url = "https://api.idlespacetech.com/v4/device/query-device-attr"
        current_time_ms = int(time.time() * 1000)

        headers = {
            "token": self.token,
            "k-tenant": "philips",
            "k-version": "4.11.0",
            "k-language": "en_US",
            "k-signv": "1.0.0",
            "encrypt_data": "physical_encrypt_data",
            "reqSource": "app",
            "lang": "en_US",
            "language": "en_US",
            "timestamp": str(current_time_ms),
            "Content-Type": "application/json",
        }

        payload = {"esn": esn, "reqTime": str(current_time_ms)}
        canonical_str = json.dumps(payload, separators=(",", ":"), sort_keys=True)

        key = RSA.import_key(RSA_PRIVATE_SIGN)
        h = SHA256.new(canonical_str.encode())
        payload["sign"] = base64.b64encode(pkcs1_15.new(key).sign(h)).decode()

        _LOGGER.debug("query_device_attr start: esn=%s", self._mask(esn))

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=10)
            _LOGGER.debug("query_device_attr HTTP status=%s", resp.status_code)
            out = resp.json()
        except requests.RequestException as err:
            _LOGGER.debug("query_device_attr request failed: %r", err)
            raise
        except ValueError:
            _LOGGER.debug("query_device_attr returned non-JSON response")
            return {"code": resp.status_code, "msg": "non_json_response", "text": resp.text[:500]}

        if isinstance(out, dict):
            out["_http_status"] = resp.status_code
            _LOGGER.debug(
                "query_device_attr response code=%s http_status=%s",
                out.get("code"),
                resp.status_code,
            )
        return out

    def _get_headers(self):
        return {
            "token": self.token,
            "k-tenant": "philips",
            "k-version": "4.11.0",
            "k-language": "en_US",
            "k-signv": "1.0.0",
            "content-type": "application/json",
            "content-length": "249",
            "accept-encoding": "gzip",
        }

    def _sign(self, payload):
        from Crypto.PublicKey import RSA
        from Crypto.Hash import SHA256
        from Crypto.Signature import pkcs1_15

        key = RSA.import_key(RSA_PRIVATE_SIGN)
        canonical_str = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        h = SHA256.new(canonical_str.encode())
        return base64.b64encode(pkcs1_15.new(key).sign(h)).decode()

    def set_auto_lock_mode(self, esn, enabled):
        url = "https://api.idlespacetech.com/v3/api/device/set-am-mode"
        mode = 0 if enabled else 1

        payload = {
            "esn": esn,
            "amMode": mode,
            "reqTime": str(int(time.time() * 1000)),
        }
        payload["sign"] = self._sign(payload)
        headers = self._get_headers()

        _LOGGER.debug("set_auto_lock_mode start: esn=%s enabled=%s amMode=%s", self._mask(esn), enabled, mode)

        resp = requests.post(url, headers=headers, json=payload, timeout=10)
        out = resp.json()
        _LOGGER.debug(
            "set_auto_lock_mode response: http_status=%s code=%s msg=%s",
            resp.status_code,
            out.get("code") if isinstance(out, dict) else None,
            out.get("msg") if isinstance(out, dict) else None,
        )
        return out

    def set_auto_lock_time(self, esn, seconds):
        url = "https://api.idlespacetech.com/v3/api/device/set-auto-lock-time"

        payload = {
            "esn": esn,
            "reqTime": str(int(time.time() * 1000)),
            "autoLockTime": int(seconds),
        }
        payload["sign"] = self._sign(payload)
        final_body = {
            "esn": esn,
            "sign": payload["sign"],
            "reqTime": payload["reqTime"],
            "autoLockTime": int(seconds),
        }

        _LOGGER.debug("set_auto_lock_time start: esn=%s seconds=%s", self._mask(esn), int(seconds))

        resp = requests.post(url, headers=self._get_headers(), json=final_body, timeout=10)
        out = resp.json()
        _LOGGER.debug(
            "set_auto_lock_time response: http_status=%s code=%s msg=%s",
            resp.status_code,
            out.get("code") if isinstance(out, dict) else None,
            out.get("msg") if isinstance(out, dict) else None,
        )
        return out

    def set_lock_state(self, esn, lock_it):
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_v1_5
        from Crypto.Hash import SHA256
        from Crypto.Signature import pkcs1_15

        transport = self._get_lock_transport_info(esn)
        current_time_ms = int(time.time() * 1000)

        headers = {
            "token": self.token,
            "k-tenant": "philips",
            "k-version": "4.11.0",
            "k-language": "en_US",
            "k-signv": "1.0.0",
            "encrypt_data": "physical_encrypt_data",
            "reqSource": "app",
            "lang": "en_US",
            "language": "en_US",
            "timestamp": str(current_time_ms),
            "Content-Type": "application/json",
        }

        if transport["mode"] == "gateway":
            url = f"https://api.idlespacetech.com/v3/gateway/set-lock-{'close' if lock_it else 'open'}"
            payload_to_sign = {
                "esn": transport["lock"]["wifiSN"],
                "mac": self._normalize_mac(transport["lock"].get("mac", "")),
                "masterSn": transport["gateway"]["wifiSN"],
                "userNumberId": 0,
                "reqTime": str(current_time_ms),
            }
        else:
            url = f"https://api.idlespacetech.com/v3/device/{'close' if lock_it else 'open'}-device"
            payload_to_sign = {
                "esn": esn,
                "userNumberId": 0,
                "reqTime": str(current_time_ms),
            }

        canonical_str = json.dumps(payload_to_sign, separators=(",", ":"), sort_keys=True)

        key = RSA.import_key(RSA_PRIVATE_SIGN)
        h = SHA256.new(canonical_str.encode())
        payload_to_sign["sign"] = base64.b64encode(pkcs1_15.new(key).sign(h)).decode()

        final_json = json.dumps(payload_to_sign, separators=(",", ":")).encode()

        _LOGGER.debug(
            "payload: %s",
            final_json
        )

        encrypt_key = RSA.import_key(binascii.unhexlify(RSA_HEX_KEY))
        cipher = PKCS1_v1_5.new(encrypt_key)

        chunk_size = encrypt_key.size_in_bytes() - 11
        encrypted_chunks = []
        for i in range(0, len(final_json), chunk_size):
            encrypted_chunks.append(cipher.encrypt(final_json[i : i + chunk_size]))

        body = {"encryptData": base64.b64encode(b"".join(encrypted_chunks)).decode()}

        _LOGGER.debug(
            "set_lock_state start: esn=%s lock_it=%s mode=%s url=%s",
            self._mask(esn),
            lock_it,
            transport["mode"],
            url,
        )

        resp = requests.post(url, headers=headers, json=body, timeout=10)

        try:
            out = resp.json()
        except Exception:
            _LOGGER.debug("set_lock_state returned non-JSON response: http_status=%s", resp.status_code)
            return {
                "code": resp.status_code,
                "msg": "non_json_response",
                "text": resp.text[:500],
            }

        if isinstance(out, dict):
            out["_http_status"] = resp.status_code
            _LOGGER.debug(
                "set_lock_state response: http_status=%s code=%s msg=%s",
                resp.status_code,
                out.get("code"),
                out.get("msg"),
            )
        return out
    # ------------------------------------------------------------------
    # Newer "/app/*" API surface: activity, credentials (PIN/fingerprint),
    # sharing. All of this is gated on `self.app_host` being known. The
    # endpoints and payload field names below were recovered from the app's
    # React Native bundle; the exact datacenter host and header set still need
    # one traffic capture to confirm (docs/reverse-engineering-notes.md).
    # ------------------------------------------------------------------

    # Discovered endpoints, grouped by feature.
    # Server paths on the datacenter host. The app's JS route names ("/app/...")
    # are NOT the server paths; these were captured from the running app:
    #   Activities screen -> POST /v3/device/operation-list
    #   PIN/Fingerprint    -> POST /v3/device/key-list
    #   Sharing            -> POST /wifi/share/list  (JS "/app/wifi/share/list")
    # operation-list and key-list are confirmed live (200 + real data); the
    # share paths are confirmed live; the key create/delete paths are inferred
    # from the "/v3/device/key-*" family and not yet captured.
    APP_ACTIVITY_LIST = "/v3/device/operation-list"
    APP_KEY_LIST = "/v3/device/key-list"
    APP_SHARE_LIST = "/wifi/share/list"
    APP_SHARE_ADD = "/wifi/share/add"
    APP_SHARE_DEL = "/wifi/share/del"
    APP_SHARE_RENAME = "/wifi/share/updatenickname"
    # Credential create/delete were captured but are NOT wired to fire: create is
    # a multi-step flow ending in a FULL-LIST-REPLACE (/v3/device/ble-add-key-list
    # with the entire pwdList — sending a partial list wipes the others) plus an
    # RSA-encrypted device-programming step (/v3/device/insert-pwd) whose plaintext
    # is unknown, and the write-endpoint signatures use a canonical this code has
    # not reproduced. Delete is /v3/device/remove-pwd (targeted by keyNum) +
    # /v3/device/ble-remove-pwd-list (targeted by num). See the RE notes; both are
    # left guarded so a wrong request can't damage a physical lock's PINs.
    APP_KEY_CREATE = "/v3/device/ble-add-key-list"
    APP_KEY_INSERT = "/v3/device/insert-pwd"
    APP_KEY_DELETE = "/v3/device/remove-pwd"
    APP_KEY_DELETE_LIST = "/v3/device/ble-remove-pwd-list"

    def _app_request(self, path, body, sign_fields=None):
        """POST to an "/app/*" endpoint with the app's signing convention.

        The signature is computed over ``sign_fields`` (a subset of the body, in
        the given insertion order) rather than the whole body, matching what the
        bundle does. ``reqTime`` is added to both. Raises
        PhilipsAppApiUnavailable when the datacenter host is not configured.
        """
        if not self.app_host:
            raise PhilipsAppApiUnavailable(
                f"app_host not set; cannot call {path}. See "
                "docs/reverse-engineering-notes.md to resolve it."
            )

        req_time = str(int(time.time() * 1000))
        body = dict(body)
        body["reqTime"] = req_time

        # Sign an insertion-ordered subset (default: the whole body minus sign).
        sign_obj = {}
        for field in (sign_fields or list(body.keys())):
            if field in body:
                sign_obj[field] = body[field]
        body["sign"] = self._sign_app(sign_obj)

        url = f"{self.app_host}{path}"
        # Header set captured from the app's operation-list / key-list requests.
        headers = {
            "token": self.token,
            "k-tenant": "philips",
            "k-version": "4.19.2",
            "k-language": "en_US",
            "k-signv": "1.0.0",
            "reqSource": "app",
            "lang": "en_US",
            "language": "en_US",
            "timestamp": req_time,
            "Content-Type": "application/json; charset=utf-8",
        }
        # Send the exact compact JSON the signature was computed over.
        payload = json.dumps(body, separators=(",", ":"))
        _LOGGER.debug("app_request %s body_keys=%s", path, sorted(body.keys()))
        resp = requests.post(url, headers=headers, data=payload, timeout=15)
        try:
            out = resp.json()
        except ValueError:
            return {"code": resp.status_code, "msg": "non_json_response", "text": resp.text[:300]}
        if isinstance(out, dict):
            if str(out.get("code")) == "444":
                raise PhilipsSessionExpired("session_expired")
            out["_http_status"] = resp.status_code
        return out

    def _sign_app(self, sign_obj):
        """base64(RSA_PKCS1v15(SHA256(JSON.stringify(sign_obj)))).

        Unlike `_sign`, the JSON is serialised in insertion order (not sorted),
        matching JavaScript's JSON.stringify as the app uses it.
        """
        from Crypto.PublicKey import RSA
        from Crypto.Hash import SHA256
        from Crypto.Signature import pkcs1_15

        key = RSA.import_key(RSA_PRIVATE_SIGN)
        canonical = json.dumps(sign_obj, separators=(",", ":"))  # insertion order
        h = SHA256.new(canonical.encode())
        return base64.b64encode(pkcs1_15.new(key).sign(h)).decode()

    # ---- Activity / history ------------------------------------------

    def get_activity(self, esn, page=1):
        """A page of the lock's operation records (newest first).

        Confirmed live: POST /v3/device/operation-list, body {esn, page},
        signature over {esn, page, reqTime} with page as an integer. `data` is a
        list of records with eventCode/eventType/eventSource/createTime/userId/
        userNickname/pwdNickname fields.
        """
        return self._app_request(
            self.APP_ACTIVITY_LIST,
            {"esn": esn, "page": int(page)},
            sign_fields=["esn", "page", "reqTime"],
        )

    # Kept for the event platform: the newest page is the latest activity.
    def get_latest_activity(self, esn):
        """Newest operation records for a lock (page 1)."""
        return self.get_activity(esn, page=1)

    # ---- Credentials: PINs / fingerprints ----------------------------

    def list_keys(self, esn):
        """List the lock's credentials.

        Confirmed live: POST /v3/device/key-list, body {esn}, signature over
        {esn, reqTime}. `data` groups credentials by type: pwdList (PINs, each
        with num/nickName/pwdValue), faceList, and finger/card lists.
        """
        return self._app_request(
            self.APP_KEY_LIST, {"esn": esn}, sign_fields=["esn", "reqTime"]
        )

    def create_pin(self, esn, name, pin, num=None):
        """Create a numeric PIN credential.

        DELIBERATELY NOT IMPLEMENTED. The captured create flow is:
          1. POST /v3/device/insert-pwd  -- {encryptData: <RSA-encrypted>}
             (device programming; plaintext unknown, encrypted with the public key)
          2. POST /v3/device/ble-add-key-list -- {esn, sign, reqTime, pwdList:[...]}
             where pwdList is the ENTIRE credential list; sending only the new
             entry REPLACES the list and wipes every existing PIN (observed live).
          3. POST /v3/device/update-key-nickname -- sets the name.
        The write-endpoint signatures also use a canonical this code has not
        reproduced. Firing any of this half-right can silently destroy a user's
        physical-lock PINs, so it raises until captured and verified end to end.
        See docs/reverse-engineering-notes.md.
        """
        raise PhilipsAppApiUnavailable(
            "Creating a PIN is not implemented: it is a multi-step flow ending in a "
            "full-list replace plus an encrypted device-programming step, and firing "
            "it unverified can wipe the lock's existing PINs. See "
            "docs/reverse-engineering-notes.md."
        )

    def delete_key(self, esn, key_num, pwd_type=1):
        """Delete a credential (PIN/fingerprint) by its slot number.

        DELIBERATELY NOT IMPLEMENTED. The captured delete flow is targeted (safer
        than create) but its signatures are unverified:
          1. POST /v3/device/remove-pwd -- {esn, sign, reqTime,
             params:{partsSn, partsMac, keyNum, keyType}}
          2. POST /v3/device/ble-remove-pwd-list -- {esn, sign, reqTime,
             pwdList:[{pwdType, num}]}
        Left guarded so a wrong request can't affect a physical lock's PINs. See
        docs/reverse-engineering-notes.md.
        """
        raise PhilipsAppApiUnavailable(
            "Deleting a credential is not implemented: the captured remove-pwd / "
            "ble-remove-pwd-list signatures are unverified. See "
            "docs/reverse-engineering-notes.md."
        )

    # ---- Sharing management ------------------------------------------

    def list_shares(self, esn):
        """List the accounts a lock is shared with."""
        return self._app_request(
            self.APP_SHARE_LIST,
            {"uid": self.uid, "wifiSN": esn},
            sign_fields=["reqTime", "wifiSN"],
        )

    def add_share(self, esn, account, nickname=None):
        """Share a lock with another account (by email/username)."""
        body = {"wifiSN": esn, "shareAccount": account}
        if nickname:
            body["nickName"] = nickname
        return self._app_request(self.APP_SHARE_ADD, body, sign_fields=["reqTime", "wifiSN"])

    def delete_share(self, esn, share_id):
        """Revoke a share by its shareId (from list_shares / device list)."""
        return self._app_request(
            self.APP_SHARE_DEL,
            {"wifiSN": esn, "shareId": share_id},
            sign_fields=["reqTime", "wifiSN"],
        )

    # ---- Account creation (for "step through creating a shared account") --

    def send_registration_token(self, email):
        """Send a verification code to an email for new-account registration."""
        return self._app_request(
            self.APP_SEND_TOKEN, {"email": email}, sign_fields=["reqTime", "email"]
        )

    def check_registration_code(self, email, code):
        """Verify the emailed registration code."""
        return self._app_request(
            self.APP_CHECK_CODE,
            {"email": email, "checkCode": code},
            sign_fields=["reqTime", "email"],
        )

    def register_account(self, email, password, code):
        """Create a new account by email once its code is verified."""
        return self._app_request(
            self.APP_REGISTER_EMAIL,
            {"email": email, "password": password, "checkCode": code},
            sign_fields=["reqTime", "email"],
        )
