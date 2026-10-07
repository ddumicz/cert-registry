from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


class PEMError(ValueError):
    pass


def parse_pem(pem: str) -> dict:
    """Extract registry fields from a PEM certificate. Rejects private keys."""
    data = pem.encode() if isinstance(pem, str) else pem
    if b"PRIVATE KEY" in data:
        raise PEMError("Wykryto klucz prywatny – wklej wyłącznie certyfikat (część publiczną).")
    try:
        cert = x509.load_pem_x509_certificate(data)
    except ValueError as exc:
        raise PEMError("Nieprawidłowy certyfikat PEM.") from exc

    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except IndexError:
        cn = ""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_text = "\n".join(str(n.value) for n in san)
    except x509.ExtensionNotFound:
        san_text = ""

    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        algo = "RSA"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        algo = "EC"
    else:
        algo = type(key).__name__.replace("PublicKey", "").lstrip("_") or "OTHER"
    size = getattr(key, "key_size", None) or 0

    return {
        "common_name": cn,
        "san": san_text,
        "serial_number": format(cert.serial_number, "x"),
        "issuer": cert.issuer.rfc4514_string(),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "key_algorithm": algo,
        "key_size": size,
        "pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
    }
