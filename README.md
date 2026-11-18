Grafana stores data-source credentials i.e. passwords, API keys, TLS secrets in its grafana.db SQLite database encrypted, not hashed. So once you have the database and the instance's secret_key, the secrets can be decrypted directly rather than cracked. This script automates that decryption for the Grafana 8.x AES-CFB format.
The script is a build up on CVE-2021-43798. 

Requirements
1. Python 3.6+
2. pycryptodome

To use it, run

1. pip install pycryptodome

2. python3 grafana_decrypt.py <grafana.db> <secret_key>
