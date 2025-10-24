'''
USE this header and jwt
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6MS41MjEyMzQxMjM0MjEzNDIxZSsyMiwiaWF0IjoxNTE2MjM5MDIyfQ.


It has the algorithm header set to none. {"alg":"none"}
'''



import os
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

SECRET_KEY = os.getenv('JWT_AUTH_SECRET_KEY')

@app.route('/admin', methods=['GET'])
def admin_only():
        token = request.headers.get('Authorization' , '') .replace('Bearer ', '')

        try:
                payload = jwt. decode(
                        token,
                        SECRET_KEY,
                        options={"require": ["exp", "iat"], "verify_exp": True, "verify_signature": False}
                )
                if payload.get('admin'):
                        return jsonify({"message": "Welcome to the admin panel", "data": " <!-- Sensitive data -- >"})

                return jsonify({"error": "Unauthorized!"}), 403

        except Exception as e:
                return jsonify({"error": str(e)}), 401

if __name__ == "__main__" :
        app.run(host='0.0.0.0', port=5000, debug=True)
