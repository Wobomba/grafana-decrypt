import sqlite3, base64, json, sys
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES

def decrypt(payload: bytes, secret_key: str) -> bytes:
    salt = payload[:8]
    # Grafana derives the AES key: PBKDF2-HMAC-SHA256(secret_key, salt, 10000, 32)
    key = pbkdf2_hmac('sha256', secret_key.encode(), salt, 10000, 32)
    iv  = payload[8:8 + AES.block_size]
    ct  = payload[8 + AES.block_size:]
    # Go uses CFB128 (full-block feedback); PyCryptodome defaults to CFB8, so force 128
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    return cipher.decrypt(ct)

def main(db_path, secret_key):
    con = sqlite3.connect(db_path)
    for name, b64pw, b64bap, sjd in con.execute(
            "SELECT name, password, basic_auth_password, secure_json_data FROM data_source"):
        print(f"\n[+] data source: {name}")
        for label, b64 in (("password", b64pw), ("basic_auth_password", b64bap)):
            if b64:
                try:
                    print(f"    {label}: {decrypt(base64.b64decode(b64), secret_key).decode(errors='replace')}")
                except Exception as e:
                    print(f"    {label}: <decrypt failed: {e}>")
        if sjd:  
            try:
                for k, v in json.loads(base64.b64decode(sjd)).items():
                    print(f"    {k}: {decrypt(base64.b64decode(v), secret_key).decode(errors='replace')}")
            except Exception as e:
                print(f"    secure_json_data: <parse failed: {e}>")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(f"usage: {sys.argv[0]} <grafana.db> <secret_key>")
    main(sys.argv[1], sys.argv[2])