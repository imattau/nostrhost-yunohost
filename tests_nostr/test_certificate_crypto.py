"""Certificate handling must not depend on the legacy PyOpenSSL bindings."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

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
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    assert nostr_certd._leaf_not_after(cert_path) > now


def test_generated_key_and_csr_are_standard_pem(tmp_path, monkeypatch):
    key_path = tmp_path / "key.pem"
    certificate._generate_key(key_path)
    monkeypatch.setattr("yunohost.hook.hook_callback", lambda *args, **kwargs: {})

    certificate._prepare_certificate_signing_request(
        "example.test", str(key_path), f"{tmp_path}/"
    )

    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    csr = x509.load_pem_x509_csr((tmp_path / "example.test.csr").read_bytes())
    assert key.key_size == certificate.KEY_SIZE
    assert (
        csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        == "example.test"
    )
    assert csr.is_signature_valid
