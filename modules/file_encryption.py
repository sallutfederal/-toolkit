import os
import json
import zipfile
import hashlib
from datetime import datetime

from utils.logger import get_module_logger

logger = get_module_logger("file_encryption")


SUPPORTED_ARCHIVE_FORMATS = ("zip", "7z", "rar", "tar.gz")


def _derive_key(password, salt, iterations=100000):
    import hashlib
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return key


def _xor_encrypt(data, key):
    key_bytes = key if isinstance(key, bytes) else key.encode("utf-8")
    key_len = len(key_bytes)
    encrypted = bytearray(len(data))
    for i, byte in enumerate(data):
        encrypted[i] = byte ^ key_bytes[i % key_len]
    return bytes(encrypted)


def _aes_encrypt(data, password):
    try:
        from cryptography.fernet import Fernet
        import base64
        key = hashlib.sha256(password.encode("utf-8")).digest()
        fernet_key = base64.urlsafe_b64encode(key)
        f = Fernet(fernet_key)
        return f.encrypt(data)
    except ImportError:
        logger.warning("cryptography not available, falling back to XOR encryption")
        salt = os.urandom(16)
        key = _derive_key(password, salt)
        encrypted = _xor_encrypt(data, key)
        return salt + encrypted


def _aes_decrypt(data, password):
    try:
        from cryptography.fernet import Fernet
        import base64
        key = hashlib.sha256(password.encode("utf-8")).digest()
        fernet_key = base64.urlsafe_b64encode(key)
        f = Fernet(fernet_key)
        return f.decrypt(data)
    except ImportError:
        salt = data[:16]
        encrypted = data[16:]
        key = _derive_key(password, salt)
        return _xor_encrypt(encrypted, key)


def encrypt_file(file_path, password, output_path=None):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if output_path is None:
        base, ext = os.path.splitext(file_path)
        output_path = f"{base}.encrypted{ext}"

    with open(file_path, "rb") as f:
        data = f.read()

    encrypted = _aes_encrypt(data, password)

    with open(output_path, "wb") as f:
        f.write(encrypted)

    original_hash = hashlib.sha256(data).hexdigest()
    encrypted_hash = hashlib.sha256(encrypted).hexdigest()

    logger.info("File encrypted: %s -> %s", file_path, output_path)
    logger.info("Original SHA256: %s", original_hash)
    logger.info("Encrypted SHA256: %s", encrypted_hash)

    return {
        "original": file_path,
        "encrypted": output_path,
        "original_hash": original_hash,
        "encrypted_hash": encrypted_hash,
        "size_original": len(data),
        "size_encrypted": len(encrypted),
    }


def decrypt_file(encrypted_path, password, output_path=None):
    if not os.path.isfile(encrypted_path):
        raise FileNotFoundError(f"File not found: {encrypted_path}")

    if output_path is None:
        if encrypted_path.endswith(".encrypted"):
            output_path = encrypted_path[:-10]
        else:
            output_path = encrypted_path + ".decrypted"

    with open(encrypted_path, "rb") as f:
        encrypted_data = f.read()

    decrypted = _aes_decrypt(encrypted_data, password)

    with open(output_path, "wb") as f:
        f.write(decrypted)

    decrypted_hash = hashlib.sha256(decrypted).hexdigest()

    logger.info("File decrypted: %s -> %s", encrypted_path, output_path)
    logger.info("Decrypted SHA256: %s", decrypted_hash)

    return {
        "encrypted": encrypted_path,
        "decrypted": output_path,
        "decrypted_hash": decrypted_hash,
        "size_decrypted": len(decrypted),
    }


def create_protected_archive(files, password, output_path=None, archive_format="zip", readme_text=None):
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"protected_archive_{timestamp}.{archive_format}"

    if readme_text is None:
        readme_text = f"Protected Archive\nCreated: {datetime.now().isoformat()}\nPassword required for access."

    if archive_format == "zip":
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            readme_info = zipfile.ZipInfo("README.txt")
            readme_info.date_time = datetime.now().timetuple()[:6]
            encrypted_readme = _aes_encrypt(readme_text.encode("utf-8"), password)
            zf.writestr(readme_info, encrypted_readme)

            for file_path in files:
                if not os.path.isfile(file_path):
                    logger.warning("File not found, skipping: %s", file_path)
                    continue
                arcname = os.path.basename(file_path)
                with open(file_path, "rb") as f:
                    file_data = f.read()
                encrypted_data = _aes_encrypt(file_data, password)
                zf.writestr(arcname + ".enc", encrypted_data)

        logger.info("Protected ZIP archive created: %s (%d files)", output_path, len(files))

    else:
        logger.warning("Format '%s' not fully supported, using ZIP instead", archive_format)
        return create_protected_archive(files, password, output_path, "zip", readme_text)

    return output_path


def verify_integrity(original_path, encrypted_path, password):
    if not os.path.isfile(original_path):
        raise FileNotFoundError(f"Original file not found: {original_path}")
    if not os.path.isfile(encrypted_path):
        raise FileNotFoundError(f"Encrypted file not found: {encrypted_path}")

    with open(original_path, "rb") as f:
        original_data = f.read()

    with open(encrypted_path, "rb") as f:
        encrypted_data = f.read()

    decrypted = _aes_decrypt(encrypted_data, password)

    original_hash = hashlib.sha256(original_data).hexdigest()
    decrypted_hash = hashlib.sha256(decrypted).hexdigest()

    match = original_hash == decrypted_hash

    result = {
        "original_hash": original_hash,
        "decrypted_hash": decrypted_hash,
        "integrity_verified": match,
        "size_original": len(original_data),
        "size_encrypted": len(encrypted_data),
        "size_decrypted": len(decrypted),
    }

    logger.info("Integrity check: %s for %s", "PASSED" if match else "FAILED", original_path)
    return result


def run(config=None):
    if config is None:
        config = {}

    mode = config.get("mode", "encrypt")
    password = config.get("password", "TestPassword123!")
    files = config.get("files", [])
    output_path = config.get("output_path", None)
    archive_format = config.get("archive_format", "zip")
    readme_text = config.get("readme_text", None)

    logger.info("File Encryption Module starting...")
    logger.info("Mode: %s", mode)

    if mode == "encrypt":
        results = []
        for f in files:
            result = encrypt_file(f, password, output_path)
            results.append(result)
        return results

    elif mode == "decrypt":
        results = []
        for f in files:
            result = decrypt_file(f, password, output_path)
            results.append(result)
        return results

    elif mode == "archive":
        return create_protected_archive(files, password, output_path, archive_format, readme_text)

    elif mode == "verify":
        results = []
        for f in files:
            result = verify_integrity(f, f + ".encrypted", password)
            results.append(result)
        return results

    else:
        logger.error("Unknown mode: %s", mode)
        raise ValueError(f"Unknown mode: {mode}")


if __name__ == "__main__":
    run()