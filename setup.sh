#!/bin/bash
# ============================================================
# DarkNodes Bot Setup Script
# ============================================================

echo "🔹 Starting DarkNodes setup..."

# 1. Install dependencies
sudo apt update -y
sudo apt install -y python3 python3-pip python3-venv docker.io unzip

# 2. Enter your bot folder (⚠️ change path if needed)
cd /root/DarkNodes-Bot || exit 1

# 3. Setup Python virtual environment
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 4. Create system user for DarkNodes (no login shell)
sudo useradd -r -s /bin/false darknodes || true
sudo usermod -aG docker darknodes

# 5. Create systemd service file
cat <<EOF | sudo tee /etc/systemd/system/darknodes-bot.service
[Unit]
Description=DarkNodes VPS Bot
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=darknodes
WorkingDirectory=/root/DarkNodes-Bot
ExecStart=/usr/bin/python3 /root/DarkNodes-Bot/bot.py
Restart=always
RestartSec=30
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="DOCKER_HOST=unix:///var/run/docker.sock"

[Install]
WantedBy=multi-user.target
EOF

# 6. Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable darknodes-bot.service

# 7. Start the service
sudo systemctl start darknodes-bot.service

# 8. Show status
sudo systemctl status darknodes-bot.service --no-pager

echo "✅ DarkNodes bot setup complete!"
echo "➡️ To view logs: sudo journalctl -u darknodes-bot.service -f"
