import json
import time
import requests
import base64
import binascii
import logging

_LOGGER = logging.getLogger(__name__)

from .const import LOGIN_STATIC_TOKEN, RSA_HEX_KEY, RSA_PRIVATE_SIGN


class PhilipsSessionExpired(Exception):
    """The account's token was invalidated, usually by a login elsewhere."""


class PhilipsAppApiUnavailable(Exception):
    """A newer "/app/*" endpoint was called before its datacenter host is known.

    The activity, credential (PIN/fingerprint), and sharing features live on a
    datacenter-specific host that the app resolves at runtime. Until that host
    is configured on the API object, these methods raise this rather than send a
    request that cannot succeed. See docs/reverse-engineering-notes.md.
    """


# Candidate keys for the list of records inside an activity response envelope.
_RECORD_LIST_KEYS = ("list", "records", "rows", "content", "data", "items", "logs")

# Candidate field names when normalising a single activity record. The activity
# endpoint is undocumented, so each logical field is resolved from the first
# candidate the record actually carries.
_RECORD_ID_KEYS = ("recordId", "id", "logId", "eventId", "msgId", "seq")
_RECORD_TIME_KEYS = (
    "createTime", "recordTime", "openTime", "operateTime", "eventTime",
    "gmtCreate", "time", "timestamp", "ts",
)
_RECORD_TYPE_KEYS = (
    "recordType", "eventType", "operateType", "openType", "type", "action",
    "opType", "msgType",
)
_RECORD_USER_KEYS = (
    "userName", "nickName", "userNickname", "opUser", "operator", "userAlias",
    "memberName", "userNumberId", "userNumber",
)


class PhilipsHomeAccessAPI:
    def __init__(self, username, password, region_code, app_host=None):
        self.username = username
        self.password = password
        self.region_code = region_code
        self.token = None
        self.uid = None
        self.data_center = None
        self.users_by_region = {}
        # Base URL for the newer "/app/*" and "/philips/record|secret|share/*"
        # endpoints (activity, credentials, sharing). These live on a per-
        # datacenter host that is resolved by the app at runtime and is not a
        # literal we can hardcode. Until it is known (see
        # docs/reverse-engineering-notes.md) the app-layer methods raise
        # PhilipsAppApiUnavailable instead of firing malformed requests.
        self.app_host = app_host

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
    APP_ACTIVITY_LATEST = "/app/record/operation/latest"
    APP_ACTIVITY_LIST = "/app/record/operation/list"
    APP_ACTIVITY_ALARM = "/app/record/operation/alarm"
    APP_KEY_CREATE = "/app/iot/ble/device/user/key/create"
    APP_KEY_UPDATE = "/app/iot/ble/device/user/key/update"
    APP_KEY_DELETE = "/app/iot/ble/device/user/key/delete"
    APP_USER_LIST = "/app/iot/ble/device/user/list/"
    APP_SHARE_ADD = "/app/wifi/share/add"
    APP_SHARE_DEL = "/app/wifi/share/del"
    APP_SHARE_LIST = "/app/wifi/share/list"
    APP_SHARE_RENAME = "/app/wifi/share/updatenickname"
    APP_SEND_TOKEN = "/app/user/sendToken"
    APP_CHECK_CODE = "/app/user/checkCode"
    APP_REGISTER_EMAIL = "/app/user/reg/putuserbyemail"

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
        headers = {
            "token": self.token,
            "k-tenant": "philips",
            "k-version": "4.11.0",
            "k-language": "en_US",
            "k-signv": "1.0.0",
            "reqSource": "app",
            "lang": "en_US",
            "language": "en_US",
            "timestamp": req_time,
            "Content-Type": "application/json; charset=utf-8",
        }
        _LOGGER.debug("app_request %s body_keys=%s", path, sorted(body.keys()))
        resp = requests.post(url, headers=headers, json=body, timeout=15)
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

    def get_latest_activity(self, esn):
        """Most recent operation record(s) for a lock (for event polling)."""
        return self._app_request(
            self.APP_ACTIVITY_LATEST,
            {"wifiSN": esn},
            sign_fields=["reqTime", "wifiSN"],
        )

    def get_activity(self, esn, page_no=1, page_size=20):
        """A page of the operation history for a lock."""
        return self._app_request(
            self.APP_ACTIVITY_LIST,
            {"wifiSN": esn, "pageNo": page_no, "pageSize": page_size},
            sign_fields=["reqTime", "wifiSN"],
        )

    def get_alarms(self, esn, page_no=1, page_size=20):
        """A page of alarm records (duress, tamper, etc.) for a lock."""
        return self._app_request(
            self.APP_ACTIVITY_ALARM,
            {"wifiSN": esn, "pageNo": page_no, "pageSize": page_size},
            sign_fields=["reqTime", "wifiSN"],
        )

    # ---- Credentials: PINs / fingerprints ----------------------------

    def list_keys(self, esn):
        """List the credentials (PINs, fingerprints, cards, faces) on a lock."""
        return self._app_request(
            self.APP_USER_LIST, {"wifiSN": esn}, sign_fields=["reqTime", "wifiSN"]
        )

    def create_pin(self, esn, name, pin, key_type=1, user_number_id=0):
        """Create a numeric PIN credential.

        key_type follows the app's credential type enum (1 = password/PIN). The
        payload field names come from the bundle; confirm against a capture.
        """
        return self._app_request(
            self.APP_KEY_CREATE,
            {
                "wifiSN": esn,
                "userNumberId": user_number_id,
                "keyType": key_type,
                "keyName": name,
                "keyValue": pin,
            },
            sign_fields=["reqTime", "wifiSN"],
        )

    def update_key(self, esn, key_id, name=None, pin=None):
        """Rename or change a credential (used for PINs and fingerprint labels)."""
        body = {"wifiSN": esn, "keyId": key_id}
        if name is not None:
            body["keyName"] = name
        if pin is not None:
            body["keyValue"] = pin
        return self._app_request(self.APP_KEY_UPDATE, body, sign_fields=["reqTime", "wifiSN"])

    def delete_key(self, esn, key_id):
        """Delete a credential (PIN or fingerprint) by its id."""
        return self._app_request(
            self.APP_KEY_DELETE,
            {"wifiSN": esn, "keyId": key_id},
            sign_fields=["reqTime", "wifiSN"],
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
