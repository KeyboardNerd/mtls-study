import os
import requests
import google.auth.transport.requests
import google.oauth2.id_token

def make_authorized_request():
    target_url = os.environ.get("TARGET_URL")
    if not target_url:
        raise ValueError("TARGET_URL environment variable is missing")

    print(f"🔹 Attempting to call: {target_url}")

    # 1. Get the ID Token from the local Metadata Server
    # The 'audience' must match what the receiver expects (their URL)
    auth_req = google.auth.transport.requests.Request()
    token = google.oauth2.id_token.fetch_id_token(auth_req, target_url)
    
    print(f"🔹 Acquired Identity Token (truncated): {token[:15]}...")

    # 2. Send the Request with the Token
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(target_url, headers=headers)

    # 3. Print Result
    print(f"🔹 Response Code: {response.status_code}")
    print(f"🔹 Response Body: {response.text}")

if __name__ == "__main__":
    make_authorized_request()
