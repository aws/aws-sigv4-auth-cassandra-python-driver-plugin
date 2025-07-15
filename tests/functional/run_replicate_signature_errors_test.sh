#!/bin/bash
# Script to run multi-threaded test for signature errors

# Check if required arguments are provided
if [ "$#" -lt 4 ]; then
    echo "Usage: $0 <region> <endpoint> <account-id> <role-name> [threads] [duration_minutes]"
    echo "Example: $0 us-east-1 cassandra.us-east-1.amazonaws.com 768726360020 KeyspacesIntegrationTestRole 10 15"
    exit 1
fi

REGION="$1"
ENDPOINT="$2"
ACCOUNT_ID="$3"
ROLE_NAME="$4"
THREADS="${5:-5}"
DURATION="${6:-10}"

# Ensure we're in the virtual environment
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Please run ./setup_test_env.sh first."
    exit 1
fi

# Activate the virtual environment if not already activated
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
fi

echo "Running multi-threaded test for signature errors..."
echo "Threads: ${THREADS}"
echo "Duration: ${DURATION} minutes"

python attempt_replicate_signature_errors.py --region "$REGION" --endpoint "$ENDPOINT" --account-id "$ACCOUNT_ID" --role-name "$ROLE_NAME" --threads "$THREADS" --duration "$DURATION"

# Check the exit code
if [ $? -eq 0 ]; then
    echo "Multi-threaded test completed - No signature errors detected."
else
    echo "Multi-threaded test completed - Signature errors reproduced!"
    exit 1
fi