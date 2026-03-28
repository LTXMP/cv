import os
import discord
from discord.ext import commands, tasks
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
        intents.members = True
        super().__init__(command_prefix="!", intents=intents)
        self.synced = False

    async def on_ready(self):
        print(f'[Discord] Logged in as {self.user} (ID: {self.user.id})')
        if not self.synced:
            # Global sync
            await self.tree.sync()
            # Guild-specific sync (Instant appearance)
            for guild in self.guilds:
                self.tree.copy_global_to(guild=guild)
                await self.tree.sync(guild=guild)
            self.synced = True
            print("[Discord] Slash commands synced (Global + Guilds).")

    def get_db(self):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    async def setup_hook(self):
        self.active_loop = asyncio.get_running_loop()
        self.sync_subscription_roles.start()

    @tasks.loop(minutes=5)
    async def sync_subscription_roles(self):
        try:
            guild = self.get_guild(1383030583839424584)
            if not guild: return
            role = guild.get_role(1487326056682881044)
            if not role: return
            
            conn = self.get_db()
            c = conn.cursor()
            
            # Find users with ACTIVE licenses
            current_time = time.time()
            query = '''
                SELECT u.discord_id 
                FROM users u
                JOIN licenses l ON u.id = l.user_id
                WHERE u.discord_id IS NOT NULL 
                AND (l.duration = 'LIFETIME' OR l.expiry > ?)
                AND l.is_paused = 0
                AND l.revoke_pending = 0
            '''
            active_users = c.execute(query, (current_time,)).fetchall()
            active_discord_ids = {str(row['discord_id']) for row in active_users}
            conn.close()
            
            # 1. Add role to active users
            for discord_id in active_discord_ids:
                # Use fetch_member if get_member fails, though intents.members should cache it
                member = guild.get_member(int(discord_id))
                if member and role not in member.roles:
                    try:
                        await member.add_roles(role, reason="Auto-sync: Active Subscription")
                        print(f"[Discord] Auto-assigned sub role to {discord_id}")
                    except: pass
                        
            # 2. Remove role from inactive users
            for member in role.members:
                if str(member.id) not in active_discord_ids:
                    try:
                        await member.remove_roles(role, reason="Auto-sync: Subscription Expired")
                        print(f"[Discord] Auto-removed sub role from {member.id}")
                    except: pass

        except Exception as e:
            print(f"[Discord] Sync role task error: {e}")

    async def on_message(self, message):
        if message.author == self.user:
            return

        # Auto-Responder for Support Channel
        if message.channel.id == SUPPORT_CHANNEL_ID:
            print(f"[Discord] Auto-replying to: {message.content[:50]}")
            async with message.channel.typing():
                response = await asyncio.to_thread(get_ai_support_response, message.content, message.author.id)
                if response and response.strip():
                    try:
                        rep = await message.reply(response)
                        print(f"[Discord] Replied to {message.author} ({len(response)} chars)")
                    except Exception as e:
                        print(f"[Discord] Reply Failed: {e}")
                else:
                    print(f"[Discord] AI returned empty response for: {message.content[:50]}")

        # Auto-Delete in Commands Channel
        if message.channel.id == COMMANDS_CHANNEL_ID:
            try:
                # Use delay=60 to delete after 1 minute
                await message.delete(delay=60)
            except Exception as e:
                print(f"[Discord] Delete failed in commands channel: {e}")

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

    # --- Multi-Server Role Features ---
    async def verify_server_admin(self, guild_id, user_discord_id):
        try:
            guild = self.get_guild(int(guild_id))
            if not guild:
                return False, "The Titan Bot is not currently in that Discord Server."
            member = guild.get_member(int(user_discord_id))
            if not member:
                try:
                    # Enforce a 5.0 second timeout so we don't hold the Flask thread forever on Discord API timeouts
                    member = await asyncio.wait_for(guild.fetch_member(int(user_discord_id)), timeout=5.0)
                except discord.NotFound:
                    return False, "You must be a member of that Discord Server to link it."
                except asyncio.TimeoutError:
                    return False, "Discord API timed out fetching your account. You may be ratelimited."
            
            if member.id == guild.owner_id or member.guild_permissions.administrator:
                return True, "Success"
            else:
                return False, "You must be an Administrator in that server to link it."
        except ValueError:
            return False, "Invalid server ID format."
        except Exception as e:
            return False, f"Bot verification error: {e}"

    async def get_guild_roles_sync(self, guild_id, user_discord_id):
        is_admin, error_msg = await self.verify_server_admin(guild_id, user_discord_id)
        if not is_admin:
            return None, error_msg
            
        guild = self.get_guild(int(guild_id))
        roles = []
        for r in guild.roles:
            if r.id != guild.id and not r.managed:
                roles.append({'id': str(r.id), 'name': r.name})
        
        roles.reverse()
        return roles, None

    async def assign_role_in_guild(self, target_discord_id, role_id, guild_id, acting_user_discord_id):
        try:
            is_admin, error_msg = await self.verify_server_admin(guild_id, acting_user_discord_id)
            if not is_admin:
                return False, f"Unauthorized: {error_msg}"
                
            guild = self.get_guild(int(guild_id))
            target_member = guild.get_member(int(target_discord_id))
            if not target_member:
                try:
                    target_member = await asyncio.wait_for(guild.fetch_member(int(target_discord_id)), timeout=5.0)
                except discord.NotFound:
                    return False, "The buyer is not currently in your Discord server."
                except asyncio.TimeoutError:
                    return False, "Discord API timed out searching for the buyer. Try again."
                    
            role = guild.get_role(int(role_id))

            if not role:
                return False, "Role not found in your server."
                
            if guild.me.top_role <= role:
                return False, "The Titan Bot's highest role must be above the role you are trying to assign."
                
            await target_member.add_roles(role, reason=f"Assigned by Seller via Dashboard")
            print(f"[Discord] Seller {acting_user_discord_id} assigned role {role_id} to {target_discord_id} in {guild_id}")
            return True, "Role assigned successfully."
            
        except discord.Forbidden:
            return False, "The bot lacks 'Manage Roles' permission or the role is higher than the bot's highest role."
        except Exception as e:
            print(f"[Discord] Multi-Server Role assignment error: {e}")
            return False, "An unexpected error occurred assigning the role."

    async def assign_sub_role_now(self, discord_id):
        # Fast instant assignment for the claim_key endpoint
        try:
            guild = self.get_guild(1383030583839424584)
            if not guild: return
            role = guild.get_role(1487326056682881044)
            if not role: return
            
            # Use fetch_member to guarantee retrieval even if cache misses
            member = await guild.fetch_member(int(discord_id))
            if member and role not in member.roles:
                await member.add_roles(role, reason="Instant key claim")
                print(f"[Discord] Instant sub role assigned to {discord_id}")
        except Exception as e:
            print(f"[Discord] Instant role assignment error: {e}")

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
    await interaction.response.send_message(f"**User**: {user['username']}\n**Linked HWID**: `{hwid_str}`")
    msg = await interaction.original_response()
    await msg.delete(delay=60)

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
    
    await interaction.response.send_message(f"**User**: {user['username']}\n**Status**: {status}\n**Type**: {user['duration']}\n**Expiry**: {expiry_str}")
    msg = await interaction.original_response()
    await msg.delete(delay=60)

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
    
    await interaction.response.send_message("✅ Your HWID has been reset. It will bind to the next device you use.")
    msg = await interaction.original_response()
    await msg.delete(delay=60)

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
    await interaction.response.send_message(f"### 🛒 Marketplace Models\n{model_list}\n\n*Purchase these on the dashboard!*")
    msg = await interaction.original_response()
    await msg.delete(delay=60)

def run_bot():
    if TOKEN:
        bot.run(TOKEN)
    else:
        print("[Discord] Skipping bot startup: DISCORD_TOKEN missing.")
