import argparse
import json
import logging
import os
import re
import sys
import time
from hashlib import sha256
from typing import Any, Dict, List, Optional, Tuple, Union

import requests
import yaml

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

NON_DETERMINISTIC_FIELDS = ['timestamp', 'comment', 'remarks']
UUID_FIELDS = ['id', 'uuid']  # Add more if needed

def load_defaults(defaults_path: str) -> Dict[str, Any]:
    """Loads default configurations from a YAML file."""
    try:
        with open(defaults_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logging.error(f"Defaults file not found: {defaults_path}")
        sys.exit(1)

def download_url(url: str, retries: int = 3, timeout: int = 10) -> Optional[str]:
    """Downloads content from a URL with retries."""
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            logging.warning(f"Attempt {attempt + 1} failed for {url}: {e}")
            time.sleep(2)  # Wait before retrying
    logging.error(f"Failed to download {url} after {retries} attempts.")
    return None

def parse_content(content: str) -> Optional[Dict[str, Any]]:
    """Parses content as JSON or YAML."""
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            logging.error(f"Failed to parse content as JSON or YAML: {e}")
            return None

def normalize_config(config: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes a configuration dictionary."""
    def recursive_remove_and_lowercase(data: Any) -> Any:
        if isinstance(data, dict):
            return {
                k: recursive_remove_and_lowercase(v)
                for k, v in data.items()
                if k.lower() not in NON_DETERMINISTIC_FIELDS
            }
        elif isinstance(data, list):
            return [recursive_remove_and_lowercase(item) for item in data]
        elif isinstance(data, str):
            # Attempt to check if it's a UUID and lowercase it
            try:
                import uuid
                uuid.UUID(data)
                return data.lower()
            except ValueError:
                return data
        else:
            return data

    normalized = recursive_remove_and_lowercase(config)

    # Apply defaults based on detected protocol
    protocol = detect_protocol(normalized)
    if protocol and protocol in defaults:
        for key, value in defaults[protocol].items():
            normalized.setdefault(key, value)

    return sort_dict_keys(normalized)

def detect_protocol(config: Dict[str, Any]) -> Optional[str]:
    """Detects the protocol based on characteristic keys."""
    if 'server' in config and 'server_port' in config and 'password' in config and 'method' in config:
        return 'shadowsocks'
    elif 'server' in config and 'server_port' in config and 'password' in config and 'protocol' in config:
        return 'shadowssr'
    elif 'server' in config and 'server_port' in config and 'password' in config and 'sni' in config:
        return 'trojan'
    elif 'server' in config and 'server_port' in config and 'uuid' in config and 'encryption' in config:
        return 'vless' # Simplified, might need refinement
    # Add more protocol detection logic here
    return None

def sort_dict_keys(data: Any) -> Any:
    """Recursively sorts dictionary keys."""
    if isinstance(data, dict):
        return {k: sort_dict_keys(data[k]) for k in sorted(data.keys())}
    elif isinstance(data, list):
        return [sort_dict_keys(item) for item in data]
    else:
        return data

def get_identity_fields(config: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts protocol-specific identity fields."""
    protocol = detect_protocol(config)
    identity = {}

    if protocol == 'shadowsocks':
        identity = {k: config.get(k) for k in ['server', 'server_port', 'password', 'method']}
    elif protocol == 'shadowssr':
        identity = {k: config.get(k) for k in ['server', 'server_port', 'password', 'protocol', 'obfs']}
    elif protocol == 'trojan':
        identity = {k: config.get(k) for k in ['server', 'server_port', 'password', 'sni']}
    elif protocol == 'vless':
        identity = {k: config.get(k) for k in ['server', 'server_port', 'uuid', 'encryption']}
    # Add more protocol identity fields here

    return identity

def fingerprint_config(config: Dict[str, Any]) -> str:
    """Generates a SHA-256 fingerprint for a configuration."""
    identity = get_identity_fields(config)
    serialized = json.dumps(sort_dict_keys(identity), sort_keys=True, separators=(',', ':'))
    return sha256(serialized.encode('utf-8')).hexdigest()

def main():
    parser = argparse.ArgumentParser(description="Deduplicate proxy configurations.")
    parser.add_argument("--input", required=True, help="File with one URL per line.")
    parser.add_argument("--defaults", required=True, help="YAML file with protocol defaults.")
    parser.add_argument("--output", required=True, help="Path to write deduplicated configs.")
    args = parser.parse_args()

    if not os.path.exists(args.input) or os.path.getsize(args.input) == 0:
        logging.error(f"Input file not found or empty: {args.input}")
        sys.exit(1)

    defaults = load_defaults(args.defaults)
    unique_configs = {}

    with open(args.input, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    if not urls:
        logging.error("No URLs found in the input file.")
        sys.exit(1)

    for url in urls:
        logging.info(f"Processing URL: {url}")
        content = download_url(url)
        if not content:
            sys.exit(1)

        config = parse_content(content)
        if not config:
            sys.exit(1)

        normalized = normalize_config(config, defaults)
        fingerprint = fingerprint_config(normalized)
        logging.info(f"  Fingerprint: {fingerprint}")

        if fingerprint not in unique_configs:
            unique_configs[fingerprint] = normalized
            logging.info(f"  Added as unique.")
        else:
            logging.info(f"  Duplicate found, skipping.")

    with open(args.output, 'w') as f:
        json.dump(list(unique_configs.values()), f, indent=2)

    logging.info(f"Wrote {len(unique_configs)} unique configs to {args.output}")

if __name__ == "__main__":
    main()
