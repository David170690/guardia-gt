#!/bin/bash
# Build script for Render.com
apt-get update && apt-get install -y libpq-dev gcc nmap
pip install --upgrade pip
pip install -r requirements.txt
