# === server/tls_config.py ===
import ssl


def get_tls_context():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='certs/server.crt', keyfile='certs/server.key')
    return context

