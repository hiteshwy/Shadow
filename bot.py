import discord
from discord.ext import commands
from discord import ui, app_commands
import os
import random
import string
import json
import subprocess
from dotenv import load_dotenv
import asyncio
import datetime
import docker
import time
import logging
import traceback
import aiohttp
import socket
import re
import psutil
import platform
import shutil
from typing import Optional, Literal
import sqlite3
import pickle
import base64
import threading
from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit
import docker
import paramiko
import os
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('darknodes_bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('DarkNodesBot')

# Load environment variables
load_dotenv()

# Bot configuration
TOKEN = os.getenv('DISCORD_TOKEN')
ADMIN_IDS = {int(id_) for id_ in os.getenv('ADMIN_IDS', '1210291131301101618').split(',') if id_.strip()}
ADMIN_ROLE_ID = int(os.getenv('ADMIN_ROLE_ID', '1376177459870961694'))
WATERMARK = "DarkNodes VPS Service"
WELCOME_MESSAGE = "Welcome To DarkNodes! Get Started With Us!"
MAX_VPS_PER_USER = int(os.getenv('MAX_VPS_PER_USER', '3'))
DEFAULT_OS_IMAGE = os.getenv('DEFAULT_OS_IMAGE', 'ubuntu:22.04')
DOCKER_NETWORK = os.getenv('DOCKER_NETWORK', 'bridge')
MAX_CONTAINERS = int(os.getenv('MAX_CONTAINERS', '100'))
DB_FILE = 'darknodes.db'
BACKUP_FILE = 'darknodes_backup.pkl'

# Dockerfile template for custom images
DOCKERFILE_TEMPLATE = """
FROM {base_image}

# Prevent prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install systemd, sudo, SSH, Docker and other essential packages
RUN apt-get update && \\
    apt-get install -y systemd systemd-sysv dbus sudo \\
                       curl gnupg2 apt-transport-https ca-certificates \\
                       software-properties-common \\
                       docker.io openssh-server tmate && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Root password
RUN echo "root:{root_password}" | chpasswd

# Create user and set password
RUN useradd -m -s /bin/bash {username} && \\
    echo "{username}:{user_password}" | chpasswd && \\
    usermod -aG sudo {username}

# Enable SSH login
RUN mkdir /var/run/sshd && \\
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Enable services on boot
RUN systemctl enable ssh && \\
    systemctl enable docker

# DarkNodes customization
RUN echo '{welcome_message}' > /etc/motd && \\
    echo 'echo "{welcome_message}"' >> /home/{username}/.bashrc && \\
    echo '{watermark}' > /etc/machine-info && \\
    echo 'darknodes-{vps_id}' > /etc/hostname

# Install additional useful packages
RUN apt-get update && \\
    apt-get install -y neofetch htop nano vim wget git tmux net-tools dnsutils iputils-ping && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/*

# Fix systemd inside container
STOPSIGNAL SIGRTMIN+3

# Boot into systemd (like a VM)
CMD ["/sbin/init"]
"""
class Database:
    """Handles all data persistence using SQLite3"""
    def __init__(self, db_file):
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._create_tables()
        self._initialize_settings()

    def _create_tables(self):
        """Create necessary tables"""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS vps_instances (
                token TEXT PRIMARY KEY,
                vps_id TEXT UNIQUE,
                container_id TEXT,
                memory INTEGER,
                cpu INTEGER,
                disk INTEGER,
                username TEXT,
                password TEXT,
                root_password TEXT,
                created_by TEXT,
                created_at TEXT,
                tmate_session TEXT,
                watermark TEXT,
                os_image TEXT,
                restart_count INTEGER DEFAULT 0,
                last_restart TEXT,
                status TEXT DEFAULT 'running',
                use_custom_image BOOLEAN DEFAULT 1
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS usage_stats (
                key TEXT PRIMARY KEY,
                value INTEGER DEFAULT 0
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS banned_users (
                user_id TEXT PRIMARY KEY
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_users (
                user_id TEXT PRIMARY KEY
            )
        ''')
        
        self.conn.commit()

    def _initialize_settings(self):
        """Initialize default settings"""
        defaults = {
            'max_containers': str(MAX_CONTAINERS),
            'max_vps_per_user': str(MAX_VPS_PER_USER)
        }
        for key, value in defaults.items():
            self.cursor.execute('INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)', (key, value))
        
        # Load admin users from database
        self.cursor.execute('SELECT user_id FROM admin_users')
        for row in self.cursor.fetchall():
            ADMIN_IDS.add(int(row[0]))
            
        self.conn.commit()

    def get_setting(self, key, default=None):
        self.cursor.execute('SELECT value FROM system_settings WHERE key = ?', (key,))
        result = self.cursor.fetchone()
        return int(result[0]) if result else default

    def set_setting(self, key, value):
        self.cursor.execute('INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)', (key, str(value)))
        self.conn.commit()

    def get_stat(self, key, default=0):
        self.cursor.execute('SELECT value FROM usage_stats WHERE key = ?', (key,))
        result = self.cursor.fetchone()
        return result[0] if result else default

    def increment_stat(self, key, amount=1):
        current = self.get_stat(key)
        self.cursor.execute('INSERT OR REPLACE INTO usage_stats (key, value) VALUES (?, ?)', (key, current + amount))
        self.conn.commit()

    def get_vps_by_id(self, vps_id):
        self.cursor.execute('SELECT * FROM vps_instances WHERE vps_id = ?', (vps_id,))
        row = self.cursor.fetchone()
        if not row:
            return None, None
        columns = [desc[0] for desc in self.cursor.description]
        vps = dict(zip(columns, row))
        return vps['token'], vps

    def get_vps_by_token(self, token):
        self.cursor.execute('SELECT * FROM vps_instances WHERE token = ?', (token,))
        row = self.cursor.fetchone()
        if not row:
            return None
        columns = [desc[0] for desc in self.cursor.description]
        return dict(zip(columns, row))

    def get_user_vps_count(self, user_id):
        self.cursor.execute('SELECT COUNT(*) FROM vps_instances WHERE created_by = ?', (str(user_id),))
        return self.cursor.fetchone()[0]

    def get_user_vps(self, user_id):
        self.cursor.execute('SELECT * FROM vps_instances WHERE created_by = ?', (str(user_id),))
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

    def get_all_vps(self):
        self.cursor.execute('SELECT * FROM vps_instances')
        columns = [desc[0] for desc in self.cursor.description]
        return {row[0]: dict(zip(columns, row)) for row in self.cursor.fetchall()}

    def add_vps(self, vps_data):
        columns = ', '.join(vps_data.keys())
        placeholders = ', '.join('?' for _ in vps_data)
        self.cursor.execute(f'INSERT INTO vps_instances ({columns}) VALUES ({placeholders})', tuple(vps_data.values()))
        self.conn.commit()
        self.increment_stat('total_vps_created')

    def remove_vps(self, token):
        self.cursor.execute('DELETE FROM vps_instances WHERE token = ?', (token,))
        self.conn.commit()
        return self.cursor.rowcount > 0

    def update_vps(self, token, updates):
        set_clause = ', '.join(f'{k} = ?' for k in updates)
        values = list(updates.values()) + [token]
        self.cursor.execute(f'UPDATE vps_instances SET {set_clause} WHERE token = ?', values)
        self.conn.commit()
        return self.cursor.rowcount > 0

    def is_user_banned(self, user_id):
        self.cursor.execute('SELECT 1 FROM banned_users WHERE user_id = ?', (str(user_id),))
        return self.cursor.fetchone() is not None

    def ban_user(self, user_id):
        self.cursor.execute('INSERT OR IGNORE INTO banned_users (user_id) VALUES (?)', (str(user_id),))
        self.conn.commit()

    def unban_user(self, user_id):
        self.cursor.execute('DELETE FROM banned_users WHERE user_id = ?', (str(user_id),))
        self.conn.commit()

    def get_banned_users(self):
        self.cursor.execute('SELECT user_id FROM banned_users')
        return [row[0] for row in self.cursor.fetchall()]

    def add_admin(self, user_id):
        self.cursor.execute('INSERT OR IGNORE INTO admin_users (user_id) VALUES (?)', (str(user_id),))
        self.conn.commit()
        ADMIN_IDS.add(int(user_id))

    def remove_admin(self, user_id):
        self.cursor.execute('DELETE FROM admin_users WHERE user_id = ?', (str(user_id),))
        self.conn.commit()
        if int(user_id) in ADMIN_IDS:
            ADMIN_IDS.remove(int(user_id))

    def get_admins(self):
        self.cursor.execute('SELECT user_id FROM admin_users')
        return [row[0] for row in self.cursor.fetchall()]
      def backup_data(self):
        """Backup all data to a file"""
        data = {
            'vps_instances': self.get_all_vps(),
            'usage_stats': {},
            'system_settings': {},
            'banned_users': self.get_banned_users(),
            'admin_users': self.get_admins()
        }
        
        # Get usage stats
        self.cursor.execute('SELECT * FROM usage_stats')
        for row in self.cursor.fetchall():
            data['usage_stats'][row[0]] = row[1]
            
        # Get system settings
        self.cursor.execute('SELECT * FROM system_settings')
        for row in self.cursor.fetchall():
            data['system_settings'][row[0]] = row[1]
            
        with open(BACKUP_FILE, 'wb') as f:
            pickle.dump(data, f)
            
        return True

    def restore_data(self):
        """Restore data from backup file"""
        if not os.path.exists(BACKUP_FILE):
            return False
            
        try:
            with open(BACKUP_FILE, 'rb') as f:
                data = pickle.load(f)
                
            # Clear all tables
            self.cursor.execute('DELETE FROM vps_instances')
            self.cursor.execute('DELETE FROM usage_stats')
            self.cursor.execute('DELETE FROM system_settings')
            self.cursor.execute('DELETE FROM banned_users')
            self.cursor.execute('DELETE FROM admin_users')
            
            # Restore VPS instances
            for token, vps in data['vps_instances'].items():
                columns = ', '.join(vps.keys())
                placeholders = ', '.join('?' for _ in vps)
                self.cursor.execute(f'INSERT INTO vps_instances ({columns}) VALUES ({placeholders})', tuple(vps.values()))
            
            # Restore usage stats
            for key, value in data['usage_stats'].items():
                self.cursor.execute('INSERT INTO usage_stats (key, value) VALUES (?, ?)', (key, value))
                
            # Restore system settings
            for key, value in data['system_settings'].items():
                self.cursor.execute('INSERT INTO system_settings (key, value) VALUES (?, ?)', (key, value))
                
            # Restore banned users
            for user_id in data['banned_users']:
                self.cursor.execute('INSERT INTO banned_users (user_id) VALUES (?)', (user_id,))
                
            # Restore admin users
            for user_id in data['admin_users']:
                self.cursor.execute('INSERT INTO admin_users (user_id) VALUES (?)', (user_id,))
                ADMIN_IDS.add(int(user_id))
                
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error restoring data: {e}")
            return False

    def close(self):
        self.conn.close()


# Initialize bot with command prefix '/'
class DarkNodesBot(commands.Bot):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db = Database(DB_FILE)
        self.session = None
        self.docker_client = None
        self.system_stats = {
            'cpu_usage': 0,
            'memory_usage': 0,
            'disk_usage': 0,
            'network_io': (0, 0),
            'last_updated': 0
        }
        self.my_persistent_views = {}

    async def setup_hook(self):
        self.session = aiohttp.ClientSession()
        try:
            self.docker_client = docker.from_env()
            logger.info("Docker client initialized successfully")
            self.loop.create_task(self.update_system_stats())
            # 🚫 Removed anti_miner_monitor (no more auto suspensions)
            await self.reconnect_containers()
            await self.restore_persistent_views()
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            self.docker_client = None

    async def reconnect_containers(self):
        """Reconnect to existing containers on startup"""
        if not self.docker_client:
            return
            
        for token, vps in list(self.db.get_all_vps().items()):
            if vps['status'] == 'running':
                try:
                    container = self.docker_client.containers.get(vps['container_id'])
                    if container.status != 'running':
                        container.start()
                    logger.info(f"Reconnected and started container for VPS {vps['vps_id']}")
                except docker.errors.NotFound:
                    logger.warning(f"Container {vps['container_id']} not found, removing from data")
                    self.db.remove_vps(token)
                except Exception as e:
                    logger.error(f"Error reconnecting container {vps['vps_id']}: {e}")

    async def restore_persistent_views(self):
        """Restore persistent views after restart"""
        pass
      async def update_system_stats(self):
        """Update system statistics periodically"""
        while True:
            try:
                self.system_stats['cpu_usage'] = psutil.cpu_percent(interval=1)
                self.system_stats['memory_usage'] = psutil.virtual_memory().percent
                self.system_stats['disk_usage'] = psutil.disk_usage('/').percent
                
                net_io = psutil.net_io_counters()
                self.system_stats['network_io'] = (net_io.bytes_sent, net_io.bytes_recv)
                
                self.system_stats['last_updated'] = time.time()
            except Exception as e:
                logger.error(f"Error updating system stats: {e}")
            await asyncio.sleep(10)

    async def close(self):
        await super().close()
        if self.session:
            await self.session.close()
        if self.db:
            self.db.close()


# ---------------------
# Utility Functions
# ---------------------

def generate_token(length=32):
    """Generate a random token"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_password(length=12):
    """Generate a secure random password"""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.SystemRandom().choice(chars) for _ in range(length))

def generate_username(prefix="user"):
    """Generate a username"""
    return f"{prefix}{random.randint(1000, 9999)}"

def check_admin(ctx):
    """Check if user is admin"""
    return ctx.author.id in ADMIN_IDS or (ctx.guild and any(r.id == ADMIN_ROLE_ID for r in ctx.author.roles))

def format_bytes(size):
    """Format bytes into human-readable string"""
    for unit in ['B','KB','MB','GB','TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"

def get_container_stats(container):
    """Fetch stats for a given container"""
    try:
        stats = container.stats(stream=False)
        cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - stats['precpu_stats']['cpu_usage']['total_usage']
        system_delta = stats['cpu_stats']['system_cpu_usage'] - stats['precpu_stats']['system_cpu_usage']
        cpu_usage = (cpu_delta / system_delta) * len(stats['cpu_stats']['cpu_usage'].get('percpu_usage', [])) * 100.0 if system_delta > 0 else 0.0
        memory_usage = stats['memory_stats']['usage'] / stats['memory_stats']['limit'] * 100.0
        return {
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'memory': f"{stats['memory_stats']['usage'] / 1024**2:.2f}MB / {stats['memory_stats']['limit'] / 1024**2:.2f}MB"
        }
    except Exception as e:
        logger.error(f"Error getting container stats: {e}")
        return None

def sanitize_output(output, max_length=1900):
    """Sanitize and trim output for Discord"""
    if isinstance(output, bytes):
        output = output.decode(errors='replace')
    output = str(output)
    if len(output) > max_length:
        return output[:max_length] + "... (truncated)"
    return output

def get_system_info():
    """Get host system info"""
    return {
        'os': platform.platform(),
        'cpu': platform.processor(),
        'cores': psutil.cpu_count(),
        'memory_total': psutil.virtual_memory().total,
        'memory_used': psutil.virtual_memory().used,
        'disk_total': psutil.disk_usage('/').total,
        'disk_used': psutil.disk_usage('/').used
    }
# ---------------------
# Docker Helpers
# ---------------------

def pull_image(client, image):
    try:
        client.images.pull(image)
        logger.info(f"Pulled image: {image}")
        return True
    except Exception as e:
        logger.error(f"Failed to pull image {image}: {e}")
        return False

def ensure_network(client, network_name):
    try:
        for net in client.networks.list():
            if net.name == network_name:
                return net
        return client.networks.create(network_name, driver="bridge")
    except Exception as e:
        logger.error(f"Failed to ensure network {network_name}: {e}")
        return None

def create_container(client, *, image, name, cpu, memory_mb, disk_gb, hostname, env=None):
    """Create a systemd-enabled container acting like a small VPS"""
    mem_limit = f"{memory_mb}m"
    cpu_quota = int(max(1, cpu) * 100000)  # 1 cpu = 100000
    try:
        container = client.containers.run(
            image=image,
            name=name,
            detach=True,
            stdin_open=True,
            tty=True,
            hostname=hostname,
            environment=env or {},
            privileged=True,  # required for systemd
            mem_limit=mem_limit,
            cpu_period=100000,
            cpu_quota=cpu_quota,
            network=DOCKER_NETWORK,
            volumes={
                "/sys/fs/cgroup": {"bind": "/sys/fs/cgroup", "mode": "rw"},
            },
            command=["/sbin/init"],
            restart_policy={"Name": "always"}
        )
        return container
    except docker.errors.APIError as e:
        raise RuntimeError(f"Docker API error: {e.explanation}") from e
    except Exception as e:
        raise RuntimeError(f"Failed to create container: {e}") from e
      # ---------------------
# Discord UI
# ---------------------

class Confirm(ui.View):
    def __init__(self, timeout=30):
        super().__init__(timeout=timeout)
        self.value = None

    @ui.button(label="Confirm", style=discord.ButtonStyle.green)
    async def confirm(self, interaction: discord.Interaction, button: ui.Button):
        self.value = True
        self.stop()
        await interaction.response.defer()

    @ui.button(label="Cancel", style=discord.ButtonStyle.red)
    async def cancel(self, interaction: discord.Interaction, button: ui.Button):
        self.value = False
        self.stop()
        await interaction.response.defer()
      # ---------------------
# Command Tree (Slash)
# ---------------------

intents = discord.Intents.default()
intents.message_content = False
bot = DarkNodesBot(command_prefix="/", intents=intents)

tree = bot.tree

def admin_only():
    async def predicate(interaction: discord.Interaction):
        if interaction.user.id in ADMIN_IDS:
            return True
        # role check
        if isinstance(interaction.user, discord.Member) and any(r.id == ADMIN_ROLE_ID for r in interaction.user.roles):
            return True
        raise app_commands.CheckFailure("You are not authorized to use this command.")
    return app_commands.check(predicate)

@tree.command(name="ping", description="Check if DarkNodes is alive")
async def ping_cmd(interaction: discord.Interaction):
    await interaction.response.send_message(f"Pong! {round(bot.latency*1000)} ms | {WATERMARK}", ephemeral=True)
  # ---------------------
# User Commands
# ---------------------

@tree.command(name="create_vps", description="Create your own DarkNodes VPS")
@app_commands.describe(
    cpu="Number of virtual CPUs (e.g., 1-4)",
    memory_mb="Memory in MB (e.g., 512, 1024, 2048)",
    disk_gb="Disk size in GB (metadata only)",
    image="Base OS image (e.g., ubuntu:22.04)"
)
async def create_vps_cmd(
    interaction: discord.Interaction,
    cpu: app_commands.Range[int, 1, 16],
    memory_mb: app_commands.Range[int, 256, 32768],
    disk_gb: app_commands.Range[int, 5, 512],
    image: str = DEFAULT_OS_IMAGE
):
    user = interaction.user
    if bot.db.is_user_banned(user.id):
        return await interaction.response.send_message("You are banned from creating VPS.", ephemeral=True)

    # Per-user quota
    max_per_user = bot.db.get_setting('max_vps_per_user', MAX_VPS_PER_USER)
    if bot.db.get_user_vps_count(user.id) >= max_per_user:
        return await interaction.response.send_message(f"You already have {max_per_user} VPS. Delete one to create more.", ephemeral=True)

    # Global cap
    total_running = len(bot.db.get_all_vps())
    max_total = bot.db.get_setting('max_containers', MAX_CONTAINERS)
    if total_running >= max_total:
        return await interaction.response.send_message("Capacity is full right now. Please try later.", ephemeral=True)

    await interaction.response.defer(thinking=True, ephemeral=True)

    if not bot.docker_client:
        return await interaction.followup.send("Docker isn't ready on host.", ephemeral=True)

    # Pull image & ensure network
    if not pull_image(bot.docker_client, image):
        return await interaction.followup.send(f"Failed to pull image `{image}`.", ephemeral=True)
    if not ensure_network(bot.docker_client, DOCKER_NETWORK):
        return await interaction.followup.send("Failed to ensure Docker network.", ephemeral=True)

    # Generate credentials
    vps_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    username = generate_username("dark")
    user_password = generate_password(12)
    root_password = generate_password(14)
    token = generate_token(40)
    hostname = f"darknodes-{vps_id}"

    # Build custom image from template?
    # For speed and simplicity, we configure inside first boot instead of baking a custom image.
    env = {
        "DARKNODES_WELCOME": WELCOME_MESSAGE,
        "DARKNODES_WATERMARK": WATERMARK,
        "DN_USERNAME": username,
        "DN_USERPASS": user_password,
        "DN_ROOTPASS": root_password,
        "DN_VPSID": vps_id
    }

    name = f"darknodes_{vps_id}"

    try:
        container = create_container(
            bot.docker_client,
            image=image,
            name=name,
            cpu=cpu,
            memory_mb=memory_mb,
            disk_gb=disk_gb,
            hostname=hostname,
            env=env
        )
    except Exception as e:
        return await interaction.followup.send(f"Failed to create container: `{e}`", ephemeral=True)

    # Post-boot configuration (best-effort)
    await asyncio.sleep(2)
    try:
        container.exec_run(f"bash -lc \"echo 'root:{root_password}' | chpasswd\"", user="root")
        container.exec_run(f"bash -lc \"useradd -m -s /bin/bash {username} || true\"", user="root")
        container.exec_run(f"bash -lc \"echo '{username}:{user_password}' | chpasswd\"", user="root")
        container.exec_run("bash -lc \"mkdir -p /var/run/sshd && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && systemctl enable ssh || systemctl enable sshd || true\"", user="root")
        container.exec_run("bash -lc \"systemctl restart ssh || systemctl restart sshd || true\"", user="root")
        container.exec_run(f"bash -lc \"echo '{WELCOME_MESSAGE}' > /etc/motd && echo '{hostname}' > /etc/hostname\"", user="root")
    except Exception as e:
        logger.warning(f"Post-boot config failed for {vps_id}: {e}")

    # Save to DB
    bot.db.add_vps({
        'token': token,
        'vps_id': vps_id,
        'container_id': container.id,
        'memory': memory_mb,
        'cpu': cpu,
        'disk': disk_gb,
        'username': username,
        'password': user_password,
        'root_password': root_password,
        'created_by': str(user.id),
        'created_at': datetime.datetime.utcnow().isoformat(),
        'tmate_session': '',
        'watermark': WATERMARK,
        'os_image': image,
        'status': 'running',
        'use_custom_image': 0
    })

    embed = discord.Embed(
        title="✅ DarkNodes VPS Created",
        description=f"Your VPS is live.\n\n**ID:** `{vps_id}`\n**Image:** `{image}`\n**CPU:** `{cpu}`\n**RAM:** `{memory_mb} MB`",
        color=discord.Color.green()
    )
    embed.add_field(name="User Login", value=f"**User:** `{username}`\n**Pass:** `{user_password}`", inline=True)
    embed.add_field(name="Root Login", value=f"**root** / `{root_password}`", inline=True)
    embed.add_field(name="Docker", value=f"**Container:** `{container.name}`", inline=False)
    embed.set_footer(text=WATERMARK)

    await interaction.followup.send(embed=embed, ephemeral=True)
  @tree.command(name="list_vps", description="List your DarkNodes VPS")
async def list_vps_cmd(interaction: discord.Interaction):
    vps_list = bot.db.get_user_vps(interaction.user.id)
    if not vps_list:
        return await interaction.response.send_message("You don't have any VPS yet.", ephemeral=True)

    desc = []
    for vps in vps_list:
        desc.append(f"**ID:** `{vps['vps_id']}` | **CPU:** {vps['cpu']} | **RAM:** {vps['memory']}MB | **Image:** {vps['os_image']} | **Status:** {vps['status']}")

    embed = discord.Embed(title="Your DarkNodes VPS", description="\n".join(desc), color=discord.Color.blurple())
    embed.set_footer(text=WATERMARK)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@tree.command(name="vps_stats", description="Get live stats for a VPS by ID")
@app_commands.describe(vps_id="The VPS ID from /list_vps")
async def vps_stats_cmd(interaction: discord.Interaction, vps_id: str):
    token, vps = bot.db.get_vps_by_id(vps_id)
    if not vps:
        return await interaction.response.send_message("VPS not found.", ephemeral=True)
    if str(interaction.user.id) != vps['created_by'] and interaction.user.id not in ADMIN_IDS:
        return await interaction.response.send_message("This VPS does not belong to you.", ephemeral=True)

    try:
        container = bot.docker_client.containers.get(vps['container_id'])
    except Exception:
        return await interaction.response.send_message("Container not found or not running.", ephemeral=True)

    stats = get_container_stats(container) or {}
    embed = discord.Embed(title=f"DarkNodes VPS Stats — {vps_id}", color=discord.Color.gold())
    embed.add_field(name="CPU", value=f"{stats.get('cpu_usage', 0):.2f}%", inline=True)
    embed.add_field(name="Memory", value=f"{stats.get('memory_usage', 0):.2f}%\n{stats.get('memory','-')}", inline=True)
    embed.add_field(name="Container", value=f"`{container.name}`", inline=True)
    embed.set_footer(text=WATERMARK)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@tree.command(name="delete_vps", description="Delete one of your VPS")
@app_commands.describe(vps_id="The VPS ID to delete")
async def delete_vps_cmd(interaction: discord.Interaction, vps_id: str):
    token, vps = bot.db.get_vps_by_id(vps_id)
    if not vps:
        return await interaction.response.send_message("VPS not found.", ephemeral=True)
    if str(interaction.user.id) != vps['created_by'] and interaction.user.id not in ADMIN_IDS:
        return await interaction.response.send_message("This VPS does not belong to you.", ephemeral=True)

    view = Confirm()
    await interaction.response.send_message(f"Delete VPS `{vps_id}` permanently?", view=view, ephemeral=True)
    timeout = await view.wait()
    if timeout or view.value is False:
        return

    try:
        container = bot.docker_client.containers.get(vps['container_id'])
        container.remove(force=True)
    except Exception as e:
        logger.warning(f"While deleting {vps_id}: {e}")

    bot.db.remove_vps(token)
    await interaction.followup.send(f"VPS `{vps_id}` deleted.", ephemeral=True)
  @tree.command(name="suspend_vps", description="(Admin) Suspend a VPS without deleting")
@admin_only()
@app_commands.describe(vps_id="VPS ID to suspend")
async def suspend_vps_cmd(interaction: discord.Interaction, vps_id: str):
    token, vps = bot.db.get_vps_by_id(vps_id)
    if not vps:
        return await interaction.response.send_message("VPS not found.", ephemeral=True)
    try:
        container = bot.docker_client.containers.get(vps['container_id'])
        container.stop()
        bot.db.update_vps(token, {"status": "suspended"})
        await interaction.response.send_message(f"VPS `{vps_id}` suspended.", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Failed to suspend: {e}", ephemeral=True)

@tree.command(name="unsuspend_vps", description="(Admin) Start a suspended VPS")
@admin_only()
@app_commands.describe(vps_id="VPS ID to start")
async def unsuspend_vps_cmd(interaction: discord.Interaction, vps_id: str):
    token, vps = bot.db.get_vps_by_id(vps_id)
    if not vps:
        return await interaction.response.send_message("VPS not found.", ephemeral=True)
    try:
        container = bot.docker_client.containers.get(vps['container_id'])
        container.start()
        bot.db.update_vps(token, {"status": "running"})
        await interaction.response.send_message(f"VPS `{vps_id}` started.", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Failed to start: {e}", ephemeral=True)
      @tree.command(name="system_info", description="(Admin) Show host system info")
@admin_only()
async def system_info_cmd(interaction: discord.Interaction):
    info = get_system_info()
    embed = discord.Embed(title="DarkNodes Host System", color=discord.Color.teal())
    embed.add_field(name="OS", value=info['os'], inline=False)
    embed.add_field(name="CPU", value=f"{info['cpu']} ({info['cores']} cores)", inline=False)
    embed.add_field(name="Memory", value=f"{format_bytes(info['memory_used'])} / {format_bytes(info['memory_total'])}", inline=False)
    embed.add_field(name="Disk", value=f"{format_bytes(info['disk_used'])} / {format_bytes(info['disk_total'])}", inline=False)
    embed.set_footer(text=WATERMARK)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@tree.command(name="admin_stats", description="(Admin) Overall stats")
@admin_only()
async def admin_stats_cmd(interaction: discord.Interaction):
    all_vps = bot.db.get_all_vps()
    running = sum(1 for v in all_vps.values() if v['status'] == 'running')
    suspended = sum(1 for v in all_vps.values() if v['status'] == 'suspended')
    total = len(all_vps)

    embed = discord.Embed(title="DarkNodes Admin Stats", color=discord.Color.purple())
    embed.add_field(name="Total VPS", value=str(total))
    embed.add_field(name="Running", value=str(running))
    embed.add_field(name="Suspended", value=str(suspended))
    embed.add_field(name="Max Capacity", value=str(bot.db.get_setting('max_containers', MAX_CONTAINERS)))
    embed.set_footer(text=WATERMARK)
    await interaction.response.send_message(embed=embed, ephemeral=True)
@tree.command(name="ban_user", description="(Admin) Ban a user from creating/using VPS")
@admin_only()
@app_commands.describe(user="User to ban")
async def ban_user_cmd(interaction: discord.Interaction, user: discord.User):
    bot.db.ban_user(user.id)
    await interaction.response.send_message(f"Banned {user.mention} from DarkNodes VPS.", ephemeral=True)

@tree.command(name="unban_user", description="(Admin) Unban a user")
@admin_only()
@app_commands.describe(user="User to unban")
async def unban_user_cmd(interaction: discord.Interaction, user: discord.User):
    bot.db.unban_user(user.id)
    await interaction.response.send_message(f"Unbanned {user.mention}.", ephemeral=True)

@tree.command(name="add_admin", description="(Admin) Grant bot admin to a user")
@admin_only()
@app_commands.describe(user="User to grant admin")
async def add_admin_cmd(interaction: discord.Interaction, user: discord.User):
    bot.db.add_admin(user.id)
    await interaction.response.send_message(f"Added {user.mention} as DarkNodes admin.", ephemeral=True)

@tree.command(name="remove_admin", description="(Admin) Remove bot admin from a user")
@admin_only()
@app_commands.describe(user="User to remove admin")
async def remove_admin_cmd(interaction: discord.Interaction, user: discord.User):
    bot.db.remove_admin(user.id)
    await interaction.response.send_message(f"Removed {user.mention} from DarkNodes admin.", ephemeral=True)
  @tree.command(name="backup_data", description="(Admin) Backup all DarkNodes data")
@admin_only()
async def backup_data_cmd(interaction: discord.Interaction):
    ok = bot.db.backup_data()
    await interaction.response.send_message("Backup completed." if ok else "Backup failed.", ephemeral=True)

@tree.command(name="restore_data", description="(Admin) Restore data from backup")
@admin_only()
async def restore_data_cmd(interaction: discord.Interaction):
    ok = bot.db.restore_data()
    await interaction.response.send_message("Restore completed." if ok else "Restore failed (no backup?).", ephemeral=True)

@tree.command(name="set_limits", description="(Admin) Set system limits")
@admin_only()
@app_commands.describe(max_total="Max total containers", max_per_user="Max VPS per user")
async def set_limits_cmd(interaction: discord.Interaction, max_total: int, max_per_user: int):
    bot.db.set_setting('max_containers', max_total)
    bot.db.set_setting('max_vps_per_user', max_per_user)
    await interaction.response.send_message(f"Updated limits: total={max_total}, per-user={max_per_user}", ephemeral=True)
  @bot.event
async def on_ready():
    try:
        await tree.sync()
        logger.info(f"Synced slash commands.")
    except Exception as e:
        logger.error(f"Failed to sync slash commands: {e}")
    logger.info(f"Logged in as {bot.user} | {WATERMARK}")

if __name__ == "__main__":
    if not TOKEN:
        print("ERROR: DISCORD_TOKEN not set. Put it in env or env.properties.txt")
        raise SystemExit(1)
    bot.run(TOKEN)
  
