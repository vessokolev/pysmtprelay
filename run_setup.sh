#!/bin/bash
# Quick setup script for SMTP server

echo "Setting up SMTP server..."

# Install dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Generate certificates
echo "Generating certificates..."
python3 generate_certificates.py

# Create messages directory
mkdir -p messages

echo "Setup complete!"
echo ""
echo "To start the server, run:"
echo "  python3 smtp_server.py"
echo ""
echo "To test, run (in another terminal):"
echo "  python3 test_smtp_client.py --port 587"

