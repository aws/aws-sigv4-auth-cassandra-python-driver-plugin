#!/bin/bash
# Script to run multi-threaded test for signature errors

# Check if required arguments are provided
if [ "$#" -lt 4 ]; then
    echo "Usage: $0 <region> <endpoint> <account-id> <role-name> [threads] [duration_minutes]"
    echo "Example: $0 us-east-1 cassandra.us-east-1.amazonaws.com <> KeyspacesIntegrationTestRole 10 15"
    exit 1
fi

REGION="$1"
ENDPOINT="$2"
ACCOUNT_ID="$3"
ROLE_NAME="$4"
THREADS="${5:-5}"
DURATION="${6:-10}"

# Check if we need to set up the test environment
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Running setup_test_env.sh..."
    ./setup_test_env.sh
    
    # Check if setup was successful
    if [ ! -d "venv" ]; then
        echo "Failed to create virtual environment. Please check setup_test_env.sh for errors."
        exit 1
    fi
    echo "Test environment setup completed successfully."
fi

# Activate the virtual environment if not already activated
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
fi

echo "Running multi-threaded test for signature errors..."
echo "Threads: ${THREADS}"
echo "Duration: ${DURATION} minutes"

# Determine the correct path to the Python script
SCRIPT_PATH="attempt_replicate_signature_errors_using_session.py"
if [ ! -f "$SCRIPT_PATH" ] && [ -f "tests/functional/$SCRIPT_PATH" ]; then
    SCRIPT_PATH="tests/functional/$SCRIPT_PATH"
fi

python "$SCRIPT_PATH" --region "$REGION" --endpoint "$ENDPOINT" --account-id "$ACCOUNT_ID" --role-name "$ROLE_NAME" --threads "$THREADS" --duration "$DURATION"

# Check the exit code
if [ $? -eq 0 ]; then
    echo "Multi-threaded test completed - No signature errors detected."
else
    echo "Multi-threaded test completed - Signature errors reproduced!"
    exit 1
fi