import hmac
import hashlib
import requests


class KeyVerifier:
    SERVER_URL = "https://example.com/"
    SERVER_KEY = "ncrfQY9J6Id2VzhTlTdrXBHsGXM4jTLZkj7mBGAks3s"

    def calculate_hash(key: str, salt: str) -> str:
        key_bytes = key.encode("utf-8")
        salt_bytes = salt.encode("utf-8")

        signature = hmac.new(key_bytes, salt_bytes, hashlib.sha256).hexdigest()

        return signature

    def verify_key(key: str, salt: str, version: str) -> bool:
        key_hash = KeyVerifier.calculate_hash(key, salt)
        # Send request to server to verify key
        response = requests.post(
            KeyVerifier.SERVER_URL + "verify_key",
            json={
                "key": key_hash,
                "salt": salt,
                "version": version,
            },
        )
        if response.status_code != 200:
            return False
        server_hash = KeyVerifier.calculate_hash(KeyVerifier.SERVER_KEY, salt)
        if server_hash != response.text:
            raise ValueError(
                "Server response hash does not match expected value. server may be compromised."
            )
        return True
