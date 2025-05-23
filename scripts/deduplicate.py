import argparse
import logging
import os
import sys
import time
import base64
import json
import re
from typing import Optional, List, Dict, Any, Union
from urllib.parse import urlparse, parse_qs, unquote
from hashlib import sha256 # اطمینان از ایمپورت شدن

import requests
import yaml

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- توابع دانلود و دیکود ---
def download_url(url: str, retries: int = 3, timeout: int = 10) -> Optional[str]:
    headers = {'User-Agent': 'Mozilla/5.0'}
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=timeout, headers=headers)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            logging.warning(f"Attempt {attempt + 1} failed for {url}: {e}")
            time.sleep(2)
    logging.error(f"Failed to download {url} after {retries} attempts.")
    return None

def safe_b64decode(s: str) -> bytes:
    s = s.replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding != 0:
        s += '=' * (4 - padding)
    return base64.b64decode(s)

def decode_content(content: str) -> List[str]:
    lines = []
    try:
        decoded_bytes = safe_b64decode(content)
        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
        lines = decoded_str.splitlines()
        logging.info("  Content decoded as Base64.")
    except Exception:
        lines = content.splitlines()
        logging.info("  Content treated as plain text.")
    return [line.strip() for line in lines if line.strip()]

# --- پارسر پیشرفته ---
def parse_proxy_link(link: str) -> Optional[Dict[str, Any]]:
    try:
        p = urlparse(link)
        config = {'protocol': p.scheme, 'remarks': unquote(p.fragment)}
        query_params = {k.lower(): v[0] for k, v in parse_qs(p.query).items()}
        config.update(query_params)

        if p.scheme == 'vless' or p.scheme == 'trojan':
            config['server'] = p.hostname
            config['port'] = p.port
            if p.scheme == 'vless': config['uuid'] = p.username
            elif p.scheme == 'trojan': config['password'] = p.username

        elif p.scheme == 'vmess':
            try:
                vmess_json_str = safe_b64decode(link[8:]).decode('utf-8')
                vmess_data = json.loads(vmess_json_str)
                config = {
                    'protocol': 'vmess',
                    'remarks': vmess_data.get('ps', ''),
                    'server': vmess_data.get('add', ''),
                    'port': int(vmess_data.get('port', 0)),
                    'uuid': vmess_data.get('id', ''),
                    'alterId': vmess_data.get('aid', '0'),
                    'security': vmess_data.get('scy', vmess_data.get('security', 'auto')),
                    'type': vmess_data.get('net', 'tcp'),
                    'host': vmess_data.get('host', ''),
                    'path': vmess_data.get('path', ''),
                    'tls': vmess_data.get('tls', 'none'),
                    'sni': vmess_data.get('sni', vmess_data.get('host', '')),
                }
            except Exception as e:
                logging.warning(f"  Failed to parse VMESS JSON: {link[:50]}... ({e})")
                return None

        elif p.scheme == 'ss':
            config['server'] = p.hostname
            config['port'] = p.port
            try:
                user_info_part = link.split('ss://')[1].split('@')[0]
                user_info = ""
                try: # Try Base64 first
                    user_info = safe_b64decode(unquote(user_info_part)).decode('utf-8')
                except: # If not Base64, assume plain text
                    user_info = unquote(user_info_part)

                if ':' in user_info:
                    config['method'], config['password'] = user_info.split(':', 1)
                else: # Handle cases where only method or password might be b64
                    logging.warning(f"  Could not determine SS method/password: {user_info_part}")
                    return None
            except Exception as e:
                 logging.warning(f"  Failed to parse SS link: {link[:50]}... ({e})")
                 return None

        elif p.scheme == 'ssr':
             try:
                 b64_part = link.split('ssr://')[1]
                 decoded = safe_b64decode(b64_part).decode('utf-8')
                 main_part, params_part = decoded.split('/?', 1) # Split only once
                 s, pt, pr, m, o, pw_b64 = main_part.split(':')
                 config.update({
                     'server': s, 'port': int(pt), 'protocol_ssr': pr,
                     'method': m, 'obfs': o,
                     'password': safe_b64decode(pw_b64).decode('utf-8')
                 })
                 params = parse_qs(params_part)
                 for k, v in params.items():
                     config[k] = safe_b64decode(v[0]).decode('utf-8')
                 config['protocol'] = 'ssr' # Set main protocol key
             except Exception as e:
                 logging.warning(f"  Failed to parse SSR link: {link[:50]}... ({e})")
                 return None

        elif p.scheme == 'hy2' or p.scheme == 'tuic':
            config['password'] = p.username
            config['server'] = p.hostname
            config['port'] = p.port
            config.setdefault('sni', query_params.get('sni', p.hostname))

        else:
            logging.warning(f"  Unsupported protocol scheme: {p.scheme}")
            return None

        if 'port' in config and config['port']:
            try: config['port'] = int(config['port'])
            except: logging.warning(f"  Invalid port in {link}"); return None
        return config

    except Exception as e:
        logging.warning(f"  Generic parsing error for {link}: {e}")
        return None

# --- توابع نرمال‌سازی و انگشت‌نگاری کامل ---
NON_DETERMINISTIC_FIELDS = ['timestamp', 'comment', 'remarks', 'fragment', 'ps', 'add_time', 'sub', 'tag', 'group']
UUID_FIELDS = ['id', 'uuid']

def load_defaults(defaults_path: str) -> Dict[str, Any]:
    try:
        with open(defaults_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logging.warning(f"Defaults file {defaults_path} not found. Continuing without defaults.")
        return {}

def sort_dict_keys(data: Any) -> Any:
    if isinstance(data, dict):
        return {k: sort_dict_keys(data[k]) for k in sorted(data.keys())}
    elif isinstance(data, list):
        return [sort_dict_keys(item) for item in data]
    else:
        return data

def normalize_config(config: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes a configuration dictionary fully."""
    def recursive_remove_and_lowercase(data: Any) -> Any:
        if isinstance(data, dict):
            return {
                k.lower(): recursive_remove_and_lowercase(v)
                for k, v in data.items()
                # Keep keys if not non-deterministic OR if value is not empty/None
                if k.lower() not in NON_DETERMINISTIC_FIELDS and v is not None and v != ""
            }
        elif isinstance(data, list):
            return [recursive_remove_and_lowercase(item) for item in data]
        elif isinstance(data, str):
            # Only lowercase UUIDs if they are actual UUIDs
            try:
                import uuid
                uuid.UUID(data)
                return data.lower()
            except ValueError:
                return data
        else:
            return data

    normalized = recursive_remove_and_lowercase(config)
    protocol = normalized.get('protocol')
    if protocol and protocol in defaults:
        for key, value in defaults[protocol].items():
            normalized.setdefault(key, value)
    return sort_dict_keys(normalized)


def get_identity_fields(config: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts key fields for fingerprinting, now protocol-specific."""
    protocol = config.get('protocol')
    identity = {'server': config.get('server'), 'port': config.get('port')}

    if protocol == 'vless' or protocol == 'vmess':
        identity['uuid'] = config.get('uuid')
        identity['type'] = config.get('type') # Network type
        identity['security'] = config.get('security') # TLS or None
        if config.get('type') in ['ws', 'grpc', 'http']:
            identity['host'] = config.get('host')
            identity['path'] = config.get('path')
        if config.get('security') == 'tls' or config.get('tls') == 'tls':
            identity['sni'] = config.get('sni')
    elif protocol == 'trojan':
        identity['password'] = config.get('password')
        identity['sni'] = config.get('sni')
    elif protocol == 'ss':
        identity['method'] = config.get('method')
        identity['password'] = config.get('password')
        identity['plugin'] = config.get('plugin')
    elif protocol == 'ssr':
        identity['method'] = config.get('method')
        identity['password'] = config.get('password')
        identity['protocol_ssr'] = config.get('protocol_ssr') # Use specific key
        identity['obfs'] = config.get('obfs')
    elif protocol == 'hy2' or protocol == 'tuic':
        identity['password'] = config.get('password') # or uuid
        identity['sni'] = config.get('sni')
        identity['insecure'] = config.get('insecure', config.get('allowinsecure'))

    # Return only keys with actual values for a consistent hash
    return {k: v for k, v in identity.items() if v is not None}

def fingerprint_config(config: Dict[str, Any]) -> str:
    identity = get_identity_fields(config)
    serialized = json.dumps(sort_dict_keys(identity), sort_keys=True, separators=(',', ':'))
    return sha256(serialized.encode('utf-8')).hexdigest()

# --- تابع main کامل ---
def main():
    parser = argparse.ArgumentParser(description="Download, parse, smartly deduplicate, and save proxy configs as raw strings.")
    parser.add_argument("--input", required=True, help="File with one URL per line.")
    parser.add_argument("--defaults", required=True, help="YAML file with protocol defaults.")
    parser.add_argument("--output-dir", required=True, help="Directory to save individual URL config files (as .txt).")
    args = parser.parse_args()

    if not os.path.exists(args.input) or os.path.getsize(args.input) == 0:
        logging.error(f"Input file not found or empty: {args.input}")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)
    defaults = load_defaults(args.defaults)
    url_counter = 0

    with open(args.input, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]

    for url in urls:
        url_counter += 1
        logging.info(f"Processing URL {url_counter}: {url}")
        content = download_url(url)
        if not content:
            logging.error(f"Skipping URL {url} due to download failure.")
            continue

        raw_configs = decode_content(content)
        if not raw_configs:
            logging.warning(f"No configs found or decoded for URL {url}.")
            continue

        unique_configs_for_this_url = {}  # fingerprint -> raw_string

        for raw_config in raw_configs:
            parsed = parse_proxy_link(raw_config)
            if parsed:
                normalized = normalize_config(parsed, defaults)
                fingerprint = fingerprint_config(normalized)
                if fingerprint not in unique_configs_for_this_url:
                    unique_configs_for_this_url[fingerprint] = raw_config
            else:
                logging.warning(f"  Skipping unparsable config: {raw_config[:60]}...")

        final_configs_for_url_file = list(unique_configs_for_this_url.values())

        if not final_configs_for_url_file:
            logging.warning(f"No parsable/unique configs found for URL {url}.")
            continue

        try:
            parsed_url = urlparse(url)
            output_filename = os.path.basename(parsed_url.path)
            if not output_filename or output_filename == '/':
                output_filename = f"{url_counter:04d}.txt"
                logging.warning(f"  URL has no filename, using {output_filename}.")

            output_filepath = os.path.join(args.output_dir, output_filename)

            if os.path.exists(output_filepath):
                logging.warning(f"  File {output_filename} already exists! It will be OVERWRITTEN by URL: {url}")

            with open(output_filepath, 'w', encoding='utf-8') as f_ind:
                for conf in final_configs_for_url_file:
                    f_ind.write(conf + '\n')
            logging.info(f"  Saved {len(final_configs_for_url_file)} unique configs from {url} to {output_filepath}")
        except Exception as e:
            logging.error(f"  Failed to determine filename or save file for {url}: {e}")

    logging.info(f"Processed {url_counter} URLs. Output saved in {args.output_dir}")

if __name__ == "__main__":
    main()