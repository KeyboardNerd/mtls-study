#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status

# Configuration
PROJECT_ID=$(gcloud config get-value project)
REGION="us-central1"
RECEIVER_NAME="id-receiver"
CALLER_NAME="id-caller"

# Service Account Names
RECEIVER_SA_NAME="sa-receiver"
CALLER_SA_NAME="sa-caller"

echo "🚀 Starting Identity Exchange Demo in Project: $PROJECT_ID"

# 1. Enable Services
echo "--- Enabling necessary APIs..."
gcloud services enable run.googleapis.com iam.googleapis.com cloudbuild.googleapis.com

# 2. Create Service Accounts
echo "--- Creating Service Accounts..."
# Create Receiver Identity
if ! gcloud iam service-accounts describe ${RECEIVER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com > /dev/null 2>&1; then
    gcloud iam service-accounts create $RECEIVER_SA_NAME --display-name "Receiver Identity"
fi
# Create Caller Identity
if ! gcloud iam service-accounts describe ${CALLER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com > /dev/null 2>&1; then
    gcloud iam service-accounts create $CALLER_SA_NAME --display-name "Caller Identity"
fi

RECEIVER_EMAIL="${RECEIVER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
CALLER_EMAIL="${CALLER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# 3. Deploy Receiver
echo "--- Deploying Receiver Service..."
# We deploy a dummy container first to get the URL, or use source deploy
# Note: For simplicity, we are creating 'requirements.txt' and 'Dockerfile' on the fly.

# Create temporary files
cat <<EOF > requirements.txt
flask
google-auth
requests
EOF

cat <<EOF > Dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "receiver.py"]
EOF

# Deploy Receiver (Allow unauthenticated initially to get URL, then we lock it down)
# Ideally, we set ingress to internal or require auth. Cloud Run defaults to requiring auth if not specified.
gcloud run deploy $RECEIVER_NAME \
  --source . \
  --region $REGION \
  --service-account $RECEIVER_EMAIL \
  --no-allow-unauthenticated \
  --quiet

# Capture the Receiver URL
RECEIVER_URL=$(gcloud run services describe $RECEIVER_NAME --region $REGION --format 'value(status.url)')
echo "✅ Receiver is live at: $RECEIVER_URL"

# Update Receiver with its own URL as the expected audience (Environment Variable)
gcloud run services update $RECEIVER_NAME \
  --region $REGION \
  --set-env-vars EXPECTED_AUDIENCE=$RECEIVER_URL \
  --quiet

# 4. Grant Permission (IAM)
echo "--- Granting 'Invoker' permission..."
# We explicitly allow the CALLER_SA to invoke the RECEIVER Service
gcloud run services add-iam-policy-binding $RECEIVER_NAME \
  --region $REGION \
  --member="serviceAccount:$CALLER_EMAIL" \
  --role="roles/run.invoker"

# 5. Deploy Caller
echo "--- Deploying Caller Service..."
# Create Dockerfile for Caller
cat <<EOF > Dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "caller.py"]
EOF

# Deploy Caller as a Cloud Run JOB (simulates a script/task)
gcloud run jobs deploy $CALLER_NAME \
  --source . \
  --region $REGION \
  --service-account $CALLER_EMAIL \
  --set-env-vars TARGET_URL=$RECEIVER_URL \
  --quiet

# 6. Execute the Exchange
echo "--- 🎬 ACTION: Executing the Caller Job..."
gcloud run jobs execute $CALLER_NAME --region $REGION --wait

echo "--- 🔍 Checking Logs..."
# Fetch logs from the Receiver to see if it accepted the identity
echo "Logs from the Receiver (Server):"
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=$RECEIVER_NAME" --limit 5 --format "value(textPayload)"

echo "--------------------------------------------------------"
echo "✅ Demo Complete. "
echo "1. The Caller fetched an ID token for $RECEIVER_URL"
echo "2. The Caller sent it to the Receiver."
echo "3. The Receiver verified the token and logged the email: $CALLER_EMAIL"
