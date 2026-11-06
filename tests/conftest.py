import shutil
import ssl
import subprocess

import pytest


@pytest.fixture(scope="session")
def tls_contexts(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    if shutil.which("openssl") is None:
        raise RuntimeError("HTTPS integration tests require openssl")
    directory = tmp_path_factory.mktemp("tls")
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.load_cert_chain(cert, key)
    return server_tls, ssl.create_default_context(cafile=str(cert))
