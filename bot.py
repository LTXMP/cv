import os
import discord
from discord.ext import commands
from discord import app_commands
import sqlite3
import time
import threading
import asyncio
from ai_utils import get_ai_support_response

# Config from Env
# Config from Env
TOKEN = os.environ.get('DISCORD_TOKEN')
SUPPORT_CHANNEL_ID = 1487170317834125402
COMMANDS_CHANNEL_ID = 1487170450659479603
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.environ.get('MODEL_DIR', os.path.join(BASE_DIR, 'models'))

# FIX: If the user forgot the leading slash in Render Env Vars, fix it.
if MODEL_DIR.startswith('opt/'):
    MODEL_DIR = '/' + MODEL_DIR

MODEL_DIR = os.path.abspath(MODEL_DIR)
DB_PATH = os.path.join(MODEL_DIR, 'database.db')

class DiscordBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(command_prefix="!", intents=intents)
        self.synced = False

    async def on_ready(self):
        print(f'[Discord] Logged in as {self.user} (ID: {self.user.id})')
        if not self.synced:
            await self.tree.sync()
            self.synced = True
            print("[Discord] Slash commands synced.")

    def get_db(self):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    async def on_message(self, message):
        if message.author == self.user:
            return

        # Auto-Responder for Support Channel
        if message.channel.id == SUPPORT_CHANNEL_ID:
            print(f"[Discord] Auto-replying to: {message.content[:50]}")
            async with message.channel.typing():
                response = await asyncio.to_thread(get_ai_support_response, message.content)
                await message.reply(response)

        await self.process_commands(message)

    # --- Role Assignment ---
    async def assign_role(self, discord_id, role_id):
        try:
            guilds = self.guilds
            if not guilds: return
            guild = guilds[0] # Assuming bot is in one main guild
            member = await guild.fetch_member(int(discord_id))
            role = guild.get_role(int(role_id))
            if member and role:
                await member.add_roles(role)
                print(f"[Discord] Assigned role {role_id} to {discord_id}")
        except Exception as e:
            print(f"[Discord] Role assignment error: {e}")

# Bot Instance
bot = DiscordBot()

# --- Slash Commands ---

# --- Slash Commands & Global Check ---

@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.CheckFailure):
        await interaction.response.send_message(f"❌ This command can only be used in <#{COMMANDS_CHANNEL_ID}>", ephemeral=True)
    else:
        print(f"[Discord] Command Error: {error}")

def is_commands_channel():
    def predicate(interaction: discord.Interaction) -> bool:
        return interaction.channel_id == COMMANDS_CHANNEL_ID
    return app_commands.check(predicate)

@bot.tree.command(name="hwid", description="Check your linked HWID")
@is_commands_channel()
async def hwid(interaction: discord.Interaction):
    conn = bot.get_db()
    user = conn.execute("SELECT username FROM users WHERE discord_id = ?", (str(interaction.user.id),)).fetchone()
    if not user:
        await interaction.response.send_message("Your Discord is not linked to any account. Please link it on the website.", ephemeral=True)
        conn.close()
        return
    
    license = conn.execute("SELECT hwid FROM licenses JOIN users ON licenses.user_id = users.id WHERE users.discord_id = ?", (str(interaction.user.id),)).fetchone()
    conn.close()
    
    hwid_str = license['hwid'] if license and license['hwid'] else "None (Unbound)"
    await interaction.response.send_message(f"**User**: {user['username']}\n**Linked HWID**: `{hwid_str}`", ephemeral=True)

@bot.tree.command(name="license", description="Check your license status")
@is_commands_channel()
async def license_status(interaction: discord.Interaction):
    conn = bot.get_db()
    user = conn.execute("SELECT u.username, l.duration, l.expiry FROM users u JOIN licenses l ON u.id = l.user_id WHERE u.discord_id = ?", (str(interaction.user.id),)).fetchone()
    conn.close()
    
    if not user:
        await interaction.response.send_message("Account not linked or no active license found.", ephemeral=True)
        return

    expiry_str = time.strftime('%Y-%m-%d %H:%M', time.localtime(user['expiry'])) if user['expiry'] < 9999999999 else "Lifetime"
    status = "Active" if user['expiry'] > time.time() else "Expired"
    
    await interaction.response.send_message(f"**User**: {user['username']}\n**Status**: {status}\n**Type**: {user['duration']}\n**Expiry**: {expiry_str}", ephemeral=True)

@bot.tree.command(name="reset_hwid", description="Reset your bound HWID")
@is_commands_channel()
async def reset_hwid(interaction: discord.Interaction):
    conn = bot.get_db()
    user = conn.execute("SELECT id, last_hwid_reset FROM users WHERE discord_id = ?", (str(interaction.user.id),)).fetchone()
    
    if not user:
        await interaction.response.send_message("Account not linked.", ephemeral=True)
        conn.close()
        return

    # Check cooldown (1 hour)
    if time.time() - (user['last_hwid_reset'] or 0) < 3600:
        await interaction.response.send_message("Rate limit: You can only reset your HWID once per hour.", ephemeral=True)
        conn.close()
        return

    conn.execute("UPDATE licenses SET hwid='' WHERE user_id = ?", (user['id'],))
    conn.execute("UPDATE users SET last_hwid_reset = ? WHERE id = ?", (time.time(), user['id']))
    conn.commit()
    conn.close()
    
    await interaction.response.send_message("✅ Your HWID has been reset. It will bind to the next device you use.", ephemeral=True)

@bot.tree.command(name="models", description="Check available marketplace models")
@is_commands_channel()
async def models(interaction: discord.Interaction):
    conn = bot.get_db()
    models = conn.execute("SELECT name, marketplace_price_monthly FROM models WHERE in_marketplace = 1 LIMIT 5").fetchall()
    conn.close()
    
    if not models:
        await interaction.response.send_message("No marketplace models available at the moment.", ephemeral=True)
        return

    model_list = "\n".join([f"• **{m['name']}** - {m['marketplace_price_monthly']}€/mo" for m in models])
    await interaction.response.send_message(f"### 🛒 Marketplace Models\n{model_list}\n\n*Purchase these on the dashboard!*", ephemeral=True)

def run_bot():
    if TOKEN:
        bot.run(TOKEN)
    else:
        print("[Discord] Skipping bot startup: DISCORD_TOKEN missing.")
