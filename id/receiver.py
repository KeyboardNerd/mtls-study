import os
from flask import Flask, request, jsonify
from google.oauth2 import id_token
from google.auth.transport import requests

app = Flask(__name__)

# This serves as the "Audience". In Cloud Run, it's the Service URL.
# In a VM, you might define your own string, e.g., "https://my-api"
EXPECTED_AUDIENCE = os.environ.get("EXPECTED_AUDIENCE")

def verify_identity(token):
    try:
        # Create a request object for verify_oauth2_token
        req = requests.Request()
        
        # Verify the token signature and audience
        # This checks: Is it signed by Google? Is it expired? Is it meant for ME?
        decoded_token = id_token.verify_oauth2_token(token, req, audience=EXPECTED_AUDIENCE)
        
        return decoded_token
    except Exception as e:
        print(f"Verification failed: {e}")
        return None

@app.route("/", methods=["POST"])
def receive_secure_call():
    # 1. Extract the Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    token = auth_header.split(" ")[1]

    # 2. Verify the Identity
    identity_info = verify_identity(token)
    
    if not identity_info:
        return jsonify({"error": "Invalid Identity Token"}), 403

    # 3. Success! We know exactly who called us.
    caller_email = identity_info.get("email")
    print(f"✅ Authenticated call from: {caller_email}")
    
    return jsonify({
        "message": "Identity Verified",
        "verified_caller": caller_email,
        "issued_at": identity_info.get("iat")
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
