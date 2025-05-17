from cryptography.fernet import Fernet

key = Fernet.generate_key()
fernet = Fernet(key)


def encrypt(msg):
    return fernet.encrypt(msg.encode())


def decrypt(token):
    return fernet.decrypt(token).decode()

