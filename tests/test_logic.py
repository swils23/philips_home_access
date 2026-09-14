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


def test_app_methods_raise_when_host_unset():
    from philips_home_access.api import PhilipsAppApiUnavailable

    api = PhilipsHomeAccessAPI("u", "p", "PhilipsNorthAmerica")  # app_host=None
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
        ("something_new", "other"),
    ],
)
def test_classify(record_type, expected):
    assert event_mod._classify({"recordType": record_type}) == expected


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
