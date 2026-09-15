"""Unit tests for the reverse-engineered logic.

Run: pip install pytest homeassistant pycryptodome cryptography
     pytest tests/
"""
import base64
import hashlib
import json
import pathlib
import sys

import pytest

CC = str(pathlib.Path(__file__).resolve().parent.parent / "custom_components")
if CC not in sys.path:
    sys.path.insert(0, CC)

from philips_home_access.api import PhilipsHomeAccessAPI  # noqa: E402
from philips_home_access import event as event_mod  # noqa: E402


# --- shared-account device discovery ---------------------------------------

def test_collect_devices_reads_every_list_key():
    """Shared devices can arrive under keys other than wifiList."""
    data = {
        "wifiList": [{"wifiSN": "OWN1", "deviceType": "LOCK"}],
        "shareList": [{"wifiSN": "SHARED1", "deviceType": "LOCK", "isAdmin": 0}],
        "gwList": [{"wifiSN": "GW1", "deviceType": "GATEWAY"}],
        "banner": [{"title": "ignore me"}],  # no wifiSN -> skipped
        "count": 3,  # non-list -> ignored
    }
    out = PhilipsHomeAccessAPI._collect_devices(data)
    esns = {d["wifiSN"] for d in out}
    assert esns == {"OWN1", "SHARED1", "GW1"}


def test_collect_devices_dedups_and_tags_provenance():
    data = {
        "wifiList": [{"wifiSN": "A", "deviceType": "LOCK"}],
        "otherList": [{"wifiSN": "A", "deviceType": "LOCK"}],  # dup esn
    }
    out = PhilipsHomeAccessAPI._collect_devices(data)
    assert len(out) == 1
    assert out[0]["_sourceList"] == "wifiList"


def test_collect_devices_empty():
    assert PhilipsHomeAccessAPI._collect_devices({}) == []


# --- app-request signing ----------------------------------------------------

def test_sign_app_is_insertion_order_not_sorted():
    """The app signs JSON.stringify order; sorting the keys must differ."""
    api = PhilipsHomeAccessAPI("u", "p", "PhilipsNorthAmerica")
    obj = {"wifiSN": "ZZZ", "reqTime": "111"}  # insertion order != sorted order
    sig = api._sign_app(obj)

    # Recompute the expected signature over the insertion-ordered canonical.
    from Crypto.PublicKey import RSA
    from Crypto.Hash import SHA256
    from Crypto.Signature import pkcs1_15
    from philips_home_access.const import RSA_PRIVATE_SIGN

    key = RSA.import_key(RSA_PRIVATE_SIGN)
    canonical = json.dumps(obj, separators=(",", ":"))
    expected = base64.b64encode(
        pkcs1_15.new(key).sign(SHA256.new(canonical.encode()))
    ).decode()
    assert sig == expected

    # A sorted canonical would produce a different signature.
    sorted_canonical = json.dumps(obj, separators=(",", ":"), sort_keys=True)
    assert canonical != sorted_canonical


def test_default_app_host_is_north_america():
    from philips_home_access.const import DEFAULT_APP_HOST

    api = PhilipsHomeAccessAPI("u", "p", "PhilipsNorthAmerica")
    assert api.app_host == DEFAULT_APP_HOST == "https://api.homeaccesstech.com"
    # An explicit host overrides the default.
    api2 = PhilipsHomeAccessAPI("u", "p", "X", app_host="https://example.test")
    assert api2.app_host == "https://example.test"


def test_app_methods_raise_when_host_unset():
    from philips_home_access.api import PhilipsAppApiUnavailable

    api = PhilipsHomeAccessAPI("u", "p", "PhilipsNorthAmerica")
    api.app_host = None  # simulate an unresolved region
    api.token = "t"
    api.uid = "uid"
    for call in (
        lambda: api.get_latest_activity("ESN"),
        lambda: api.list_keys("ESN"),
        lambda: api.list_shares("ESN"),
        lambda: api.create_pin("ESN", "n", "1234"),
    ):
        with pytest.raises(PhilipsAppApiUnavailable):
            call()


def test_share_list_builds_confirmed_request(monkeypatch):
    """list_shares must POST /wifi/share/list with body {uid,wifiSN,sign,reqTime}."""
    import philips_home_access.api as apimod

    captured = {}

    class _Resp:
        status_code = 200

        def json(self):
            return {"code": 200, "data": []}

    def fake_post(url, headers=None, data=None, timeout=None):
        captured["url"] = url
        captured["body"] = json.loads(data)
        return _Resp()

    monkeypatch.setattr(apimod.requests, "post", fake_post)
    api = PhilipsHomeAccessAPI("u", "p", "PhilipsNorthAmerica")
    api.token, api.uid = "tok", "myuid"
    api.list_shares("ESN123")
    assert captured["url"] == "https://api.homeaccesstech.com/wifi/share/list"
    assert captured["body"]["wifiSN"] == "ESN123"
    assert captured["body"]["uid"] == "myuid"
    assert "sign" in captured["body"] and "reqTime" in captured["body"]


# --- activity classification ------------------------------------------------

@pytest.mark.parametrize(
    "record_type,expected",
    [
        ("app_unlock", "app_unlock"),
        ("fingerprintOpen", "fingerprint_unlock"),
        ("PIN_UNLOCK", "pin_unlock"),
        ("password", "pin_unlock"),
        ("autoLock", "auto_lock"),
        ("door_open", "unlock"),
        ("lock", "lock"),
        ("tamperAlarm", "tamper"),
        ("duress", "alarm"),
        ("visitor", "doorbell"),
        ("something_new", "operation"),
    ],
)
def test_classify(record_type, expected):
    assert event_mod._classify({"recordType": record_type}) == expected


def test_classify_real_records():
    # Numeric operation records default to "operation"; a PIN leaves pwdNickname.
    assert event_mod._classify({"eventCode": 8, "eventSource": 255}) == "operation"
    assert event_mod._classify({"eventCode": 9, "pwdNickname": "Sam"}) == "pin_unlock"


def test_delete_key_builds_targeted_two_step_request(monkeypatch):
    """delete_key must send remove-pwd then ble-remove-pwd-list, each targeted by
    the slot number (never a full list), on the idlespacetech host, sorted-signed.
    """
    import philips_home_access.api as apimod

    calls = []

    class _R:
        status_code = 200

        def json(self):
            return {"code": 200, "msg": "Success"}

    def fake_post(url, headers=None, data=None, timeout=None):
        calls.append((url, json.loads(data)))
        return _R()

    monkeypatch.setattr(apimod.requests, "post", fake_post)
    api = PhilipsHomeAccessAPI("u", "p", "PhilipsNorthAmerica")
    api.token = "tok"
    api.delete_key("ESN123", 2)

    assert calls[0][0] == "https://api.idlespacetech.com/v3/device/remove-pwd"
    assert calls[0][1]["params"]["keyNum"] == 2
    assert calls[1][0] == "https://api.idlespacetech.com/v3/device/ble-remove-pwd-list"
    assert calls[1][1]["pwdList"] == [{"pwdType": 1, "num": 2}]
    # Both targeted (no full list) and both signed with reqTime.
    for _, body in calls:
        assert "sign" in body and "reqTime" in body


def test_create_pin_flow_and_createtime_is_int(monkeypatch):
    """create_pin reads the list, then insert-pwd + ble-add (full list, existing
    kept) + nickname. createTime must be coerced to int (key-list returns a
    string; the API 401s on a string)."""
    import philips_home_access.api as apimod

    posts = []

    class _R:
        status_code = 200

        def json(self):
            return {"code": 200, "msg": "Success"}

    def fake_post(url, headers=None, data=None, json=None, timeout=None):
        posts.append((url, json if json is not None else globals()["json"].loads(data)))
        return _R()

    monkeypatch.setattr(apimod.requests, "post", fake_post)
    api = PhilipsHomeAccessAPI("u", "p", "PhilipsNorthAmerica")
    api.token = "tok"
    # existing PIN at slot 1 with a STRING createTime (as the live API returns).
    monkeypatch.setattr(
        api, "list_keys",
        lambda esn: {"data": {"pwdList": [
            {"num": 1, "nickName": "Existing", "pwdValue": "0000", "type": 0, "createTime": "1700000000"}
        ]}},
    )
    api.create_pin("ESN", "Guest", "0007")

    paths = [u.split("idlespacetech.com")[1] for u, _ in posts]
    assert paths[0] == "/v3/device/insert-pwd"          # encrypted device step
    assert paths[1] == "/v3/device/ble-add-key-list"    # registry
    assert paths[2] == "/v3/device/update-key-nickname"
    ble_body = posts[1][1]
    nums = {e["num"] for e in ble_body["pwdList"]}
    assert nums == {0, 1}                                 # existing kept + new at free slot 0
    for e in ble_body["pwdList"]:
        assert isinstance(e["createTime"], int)          # coerced from string


def test_create_pin_preserves_fingerprints(monkeypatch):
    """ble-add-key-list replaces the whole credential set, so create_pin must
    resend existing fingerprints (pwdType 2) alongside the PINs, or they're wiped.
    """
    import philips_home_access.api as apimod

    posts = []

    class _R:
        status_code = 200

        def json(self):
            return {"code": 200, "msg": "Success"}

    def fake_post(url, headers=None, data=None, json=None, timeout=None):
        posts.append((url, json if json is not None else globals()["json"].loads(data)))
        return _R()

    monkeypatch.setattr(apimod.requests, "post", fake_post)
    api = PhilipsHomeAccessAPI("u", "p", "PhilipsNorthAmerica")
    api.token = "tok"
    monkeypatch.setattr(api, "list_keys", lambda esn: {"data": {
        "pwdList": [{"num": 1, "nickName": "A", "pwdValue": "0000", "type": 0, "createTime": "1700000000"}],
        "fingerprintList": [{"num": 0, "nickName": "Finger", "type": 3, "createTime": "1700000000", "items": [0]}],
    }})
    api.create_pin("ESN", "Guest", "0007")

    ble = next(b for u, b in posts if u.endswith("/v3/device/ble-add-key-list"))
    by_type = {}
    for e in ble["pwdList"]:
        by_type.setdefault(e["pwdType"], []).append(e)
    assert len(by_type[1]) == 2                       # existing PIN + new PIN
    assert len(by_type[2]) == 1                        # the fingerprint, preserved
    fp = by_type[2][0]
    assert fp["items"] == [0] and isinstance(fp["createTime"], int)


def test_create_pin_refuses_unsupported_credentials(monkeypatch):
    """Credential types create can't round-trip yet (faces/cards) still refuse."""
    from philips_home_access.api import PhilipsAppApiUnavailable

    api = PhilipsHomeAccessAPI("u", "p", "PhilipsNorthAmerica")
    api.token = "tok"
    monkeypatch.setattr(api, "list_keys", lambda esn: {"data": {
        "pwdList": [], "faceList": [{"num": 0}]}})
    with pytest.raises(PhilipsAppApiUnavailable):
        api.create_pin("ESN", "n", "0007")


def test_write_signature_is_sorted_keys():
    """/v3/device/* writes sign the whole body with SORTED keys (the set_lock_state
    family), distinct from the reads' insertion-order scheme."""
    import json as _json

    api = PhilipsHomeAccessAPI("u", "p", "PhilipsNorthAmerica")
    body = {"reqTime": "1", "esn": "E"}  # insertion order != sorted order
    # _sign sorts; _sign_app does not — they must differ for an unsorted body.
    assert api._sign(body) != api._sign_app(body)
    # sorted canonical really is sorted (esn before reqTime)
    assert _json.dumps(body, separators=(",", ":"), sort_keys=True) == '{"esn":"E","reqTime":"1"}'


def test_activity_signature_canonical_form():
    """operation-list signs {esn, page, reqTime} as compact JSON in insertion
    order with page as an int. The exact field order and page's int-ness both
    matter — the live server rejects a mismatch with code 594. (The real
    device-serial vector this was validated against is not committed.)
    """
    import json as _json

    api = PhilipsHomeAccessAPI("u", "p", "PhilipsNorthAmerica")
    esn, rt = "ESNSYNTHETIC01", "1700000000000"
    canonical = api._sign_app({"esn": esn, "page": 1, "reqTime": rt})
    # Wrong order or page-as-string produce different signatures.
    assert canonical != api._sign_app({"esn": esn, "reqTime": rt, "page": 1})
    assert canonical != api._sign_app({"esn": esn, "page": "1", "reqTime": rt})
    # page must serialise as a bare int (no quotes) in the signed string.
    assert '"page":1' in _json.dumps({"esn": esn, "page": 1, "reqTime": rt}, separators=(",", ":"))


def test_records_from_envelopes():
    assert event_mod._records_from({"list": [{"id": 1}]}) == [{"id": 1}]
    assert event_mod._records_from({"records": [{"id": 2}]}) == [{"id": 2}]
    assert event_mod._records_from([{"id": 3}]) == [{"id": 3}]
    assert event_mod._records_from({"id": 4}) == [{"id": 4}]  # bare record
    assert event_mod._records_from({}) == []
    assert event_mod._records_from(None) == []


# --- CA subject hash helper (used by the RE workbench) ----------------------

def test_subject_hash_matches_openssl_scheme():
    """subject_hash_old = first 4 bytes of MD5(DER subject), little-endian."""
    tool = pathlib.Path(__file__).resolve().parent.parent.parent / "android-re" / "scripts" / "subject_hash.py"
    if not tool.exists():
        pytest.skip("android-re workbench not present")
    import importlib.util

    spec = importlib.util.spec_from_file_location("subject_hash", tool)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unit-test-ca")])
    import datetime

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.PEM)

    import struct

    der_subject = cert.subject.public_bytes()
    expected = "%08x" % struct.unpack("<I", hashlib.md5(der_subject).digest()[:4])[0]
    assert mod.subject_hash_old(pem) == expected
