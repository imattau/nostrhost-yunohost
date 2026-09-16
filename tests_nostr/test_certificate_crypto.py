"""Certificate handling must not depend on the legacy PyOpenSSL bindings."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from yunohost import certificate, nostr_certd


def _write_certificate(path, domain="example.test", issuer_organization="Test CA"):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Root"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_organization),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def test_certificate_status_uses_cryptography_without_email_metadata(
    tmp_path, monkeypatch
):
    domain = "example.test"
    generation = tmp_path / f"{domain}-history" / "20260915.000000-caddy"
    generation.mkdir(parents=True)
    _write_certificate(generation / "crt.pem", domain)
    (tmp_path / domain).symlink_to(generation)
    monkeypatch.setattr(certificate, "CERT_FOLDER", str(tmp_path))

    status = certificate._get_status(domain)

    assert status["subject"] == domain
    assert status["CA_name"] == "Test Root"
    assert status["CA_type"] == "other"
    assert status["style"] == "success"
    assert "email" not in status


def test_certd_reads_leaf_expiry_and_issuer_with_cryptography(tmp_path):
    cert_path = tmp_path / "crt.pem"
    _write_certificate(cert_path)

    assert nostr_certd._leaf_issuer(cert_path) == "Test Root"
    now = datetime.now(timezone.utc)
    assert nostr_certd._leaf_not_after(cert_path) > now


def test_fetch_certificate_delegates_to_caddy(monkeypatch):
    """Issuance is delegated to Caddy: ensure the domain site, export the cert."""
    from yunohost import nostr_certd

    calls = {}

    class FakeClient:
        def ensure_domain_site(self, domain):
            calls["site"] = domain

    monkeypatch.setattr("nostrhost.caddy_admin.CaddyAdminClient", lambda: FakeClient())
    monkeypatch.setattr(certificate, "_regen_dnsmasq_if_needed", lambda: None)
    monkeypatch.setattr(certificate, "_get_status", lambda domain: {"style": "success"})
    monkeypatch.setattr(nostr_certd, "export_domain", lambda domain, dry_run=False: True)

    certificate._fetch_and_enable_new_certificate("example.test")

    assert calls["site"] == "example.test"


def test_fetch_certificate_raises_when_caddy_has_no_cert(monkeypatch):
    from yunohost import nostr_certd
    from yunohost.utils.error import YunohostError

    class FakeTime:
        def __init__(self):
            self.t = 0.0

        def monotonic(self):
            return self.t

        def sleep(self, seconds):
            self.t += seconds

    class FakeClient:
        def ensure_domain_site(self, domain):
            return None

    monkeypatch.setattr(certificate, "time", FakeTime())
    monkeypatch.setattr("nostrhost.caddy_admin.CaddyAdminClient", lambda: FakeClient())
    monkeypatch.setattr(certificate, "_regen_dnsmasq_if_needed", lambda: None)
    monkeypatch.setattr(nostr_certd, "export_domain", lambda domain, dry_run=False: False)

    def no_cert(_domain):
        raise YunohostError("certmanager_no_cert_file")

    monkeypatch.setattr(certificate, "_get_status", no_cert)

    with pytest.raises(YunohostError):
        certificate._fetch_and_enable_new_certificate("example.test")
