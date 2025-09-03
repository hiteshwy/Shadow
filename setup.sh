#!/bin/bash
# ============================================================
# DarkNodes Bot Setup Script (Auto-detects repo location)
# ============================================================

echo "🔹 Starting DarkNodes setup..."

# 1. Install Python & base tools
sudo apt update -y
sudo apt install -y python3 python3-pip python3-venv unzip ca-certificates curl gnupg lsb-release

# 2. Fix Docker installation (official repo, avoids containerd conflict)
echo "🔹 Installing Docker from official repository..."
sudo apt remove -y docker.io containerd containerd.io || true
sudo mkdir -m 0755 -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 3. Detect Shadow repo path
if [ -d "/root/Shadow" ]; then
    BOT_PATH="/root/Shadow"
elif [ -d "/home/$USER/Shadow" ]; then
    BOT_PATH="/home/$USER/Shadow"
else
    echo "❌ Shadow repo not found in /root or /home/$USER"
    exit 1
fi

echo "✅ Using repo path: $BOT_PATH"

# 4. Setup Python virtual environment
cd "$BOT_PATH" || exit 1
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 5. Create system user for DarkNodes (no login shell)
sudo useradd -r -s /bin/false darknodes || true
sudo usermod -aG docker darknodes

# 6. Create systemd service file
cat <<EOF | sudo tee /etc/systemd/system/darknodes-bot.service
[Unit]
Description=DarkNodes VPS Bot
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=darknodes
WorkingDirectory=$BOT_PATH
ExecStart=/usr/bin/python3 $BOT_PATH/bot.py
Restart=always
RestartSec=30
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="DOCKER_HOST=unix:///var/run/docker.sock"

[Install]
WantedBy=multi-user.target
EOF

# 7. Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable darknodes-bot.service

# 8. Start the service
sudo systemctl restart darknodes-bot.service

# 9. Show status
sudo systemctl status darknodes-bot.service --no-pager

echo "✅ DarkNodes bot setup complete!"
echo "➡️ To view logs: sudo journalctl -u darknodes-bot.service -f"
