import hmac
import hashlib
import requests
import random


class KeyVerifier:
    SERVER_URL = "https://your-worker.workers.dev/"
    SERVER_KEY = "YOUR_SERVER_KEY_HERE"
    SALT_LENGTH = 32

    @staticmethod
    def calculate_hash(key: str, salt: str) -> str:
        key_bytes = key.encode("utf-8")
        salt_bytes = salt.encode("utf-8")

        signature = hmac.new(key_bytes, salt_bytes, hashlib.sha256).hexdigest()

        return signature

    @staticmethod
    def verify_key(key: str, version: str) -> bool:
        salt = "".join(
            [
                random.choice(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                )
                for _ in range(KeyVerifier.SALT_LENGTH)
            ]
        )
        key_hash = KeyVerifier.calculate_hash(key, salt)
        # Send request to server to verify key
        # /check?val=key_hash&salt=salt&version=version
        response = requests.get(
            KeyVerifier.SERVER_URL + "check",
            params={
                "val": key_hash,
                "salt": salt,
                "version": version,
            },
        )
        print(response.url)
        if response.status_code != 200:
            return False
        server_hash = KeyVerifier.calculate_hash(KeyVerifier.SERVER_KEY, salt)
        if server_hash != response.text:
            raise ValueError(
                "Server response hash does not match expected value. server may be compromised."
            )
        return True


print(KeyVerifier.verify_key("my_secret_key_123", "1.0.0"))  # Example: likely False
print(
    KeyVerifier.verify_key("YOUR_PRODUCT_KEY_HERE", "1.0.0")
)  # Example: replace with your actual product key and version
print(
    KeyVerifier.verify_key("ANOTHER_EXAMPLE_PRODUCT_KEY", "2.0.0")
)  # Example: different key/version combination
