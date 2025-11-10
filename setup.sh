#!/bin/bash
# Setup script for Red Team vs Blue Team Project

echo "========================================="
echo "Red Team vs Blue Team Project Setup"
echo "========================================="
echo ""

# Check Python version
echo "[*] Checking Python version..."
python3 --version || { echo "[!] Python 3 is required"; exit 1; }

# Create virtual environment
echo "[*] Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "[*] Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "[*] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "========================================="
echo "Setup complete!"
echo "========================================="
echo ""
echo "To activate the virtual environment:"
echo "  source venv/bin/activate"
echo ""
echo "To deactivate:"
echo "  deactivate"
echo ""

