# Google Cloud Identity Exchange Demo

This repository demonstrates **Service-to-Service Authentication** on Google Cloud without managing secrets or passwords. 

It uses **OIDC (OpenID Connect) Identity Tokens** fetched from the metadata server to securely authenticate a "Caller" service to a "Receiver" service.

## 📂 Files Overview

| File | Description |
| :--- | :--- |
| **`receiver.py`** | A Flask web server (Target). It verifies the incoming JWT token to ensure the request is from a trusted Google Service Account. |
| **`caller.py`** | A Python script (Client). It fetches a signed Identity Token from the local Metadata Server and sends it to the Receiver. |
| **`deploy.sh`** | A "One-Shot" bash script. It enables APIs, creates Service Accounts, deploys both services to Cloud Run, and executes the test. |

---

## 🚀 Quick Start

### 1. Prerequisites
* Google Cloud Project with billing enabled.
* `gcloud` CLI installed and authorized (`gcloud auth login`).
* Permission to create Service Accounts and deploy to Cloud Run.

### 2. Deployment
Run the included script to set up the entire environment automatically.

```bash
# Make the script executable
chmod +x deploy.sh

# Run the deployment
./deploy.sh
```

### 3. Sample Output

```
✅ Demo Complete.
1. The Caller fetched an ID token for https://id-receiver-xxxxxxxxxxxx-uc.a.run.app
2. The Caller sent it to the Receiver.
3. The Receiver verified the token and logged the email: sa-caller@project_name.iam.gserviceaccount.com
```
