#!/bin/bash
# Script to set up the test environment

echo "Setting up Python test environment..."

# Create a virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python -m venv venv
fi

# Activate the virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Navigate to the root directory of the project
cd "$(dirname "$(dirname "$(dirname "${BASH_SOURCE[0]}")")")" 

# Install the plugin in development mode
echo "Installing the SigV4 auth plugin in development mode..."
pip install -e .

# Install test dependencies
echo "Installing test dependencies..."
pip install -r "$(dirname "${BASH_SOURCE[0]}")/requirements-test.txt"

echo "Test environment setup complete."
echo "You can now run tests with './run_tests.sh'"
echo "To activate this environment in the future, run 'source venv/bin/activate'"