#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netbox_ipam_scanner_init.py — bootstraps NetBox IPAM scanner

Author:     LiteBitIO
Version:    1.7.1
Date:       2025-06-25
License:    GNU GPLv3

Description:
    - Loads TOML config
    - Sets up logging and directories
    - Ensures required custom fields exist (creating missing ones)
    - Logs all parameters for existing required fields
"""

__author__ = "LiteBitIO"
__version__ = "1.7.1"
__license__ = "GNU GPLv3"
__status__ = "Production"

import os
import sys
import logging
import requests
import tomllib
import json
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Iterator, Optional, Any
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -----------------------------------------------------------------------------
# 1) CONFIGURATION DATACLASS
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Config:
    netbox_url: str
    netbox_token: str
    verify_ssl: bool
    page_size: int
    log_dir: Path
    log_file: str
    log_level: int
    nmap_dns: str
    nmap_dir: Path
    ext_mac_lookup: bool
    oui_db_file: Path
    oui_db_path: Path

# ----------------------------------------------------------------------------
# Load configuration
# ----------------------------------------------------------------------------


conf_path = Path(__file__).parent / "netbox_ipam_scanner_conf.toml"

conf = tomllib.loads(conf_path.read_text(encoding="utf-8"))

config = Config(
    netbox_url=conf["netbox"]["url"],
    netbox_token=conf["netbox"]["token"],
    verify_ssl=conf["netbox"]["verify_ssl"],
    # page_size default to 100 if not set
    page_size=conf["options"].get("page_size", 100),
    log_dir=Path(conf["logging"]["log_dir"]),
    log_file=conf["logging"]["log_file"],
    # default to INFO if not set
    log_level=getattr(logging, conf["logging"]["level"].upper(), logging.INFO),
    nmap_dns=conf["nmap"]["dns"],
    nmap_dir=Path(conf["nmap"]["output_dir"]),
    ext_mac_lookup=conf["options"].get("ext_mac_lookup", False),
    oui_db_file=Path(conf["mac_oui"]["oui_db_file"]),
    # If the TOML value is a non‐empty string, use it; otherwise use script dir
    oui_db_path=(
        Path(conf["mac_oui"]["oui_db_path"])
        if conf["mac_oui"]["oui_db_path"]
        else Path(__file__).parent
    ),



)

url_params = {"limit": config.page_size}


# ----------------------------------------------------------------------------
# Ensure directories exist
# ----------------------------------------------------------------------------
os.makedirs(config.nmap_dir, exist_ok=True)
os.makedirs(config.log_dir, exist_ok=True)


# -----------------------------------------------------------------------------
# LOGGING SETUP
# -----------------------------------------------------------------------------
# configure root logger only once
_root_logger = logging.getLogger()
_root_logger.setLevel(config.log_level)
# remove any existing handlers
for h in list(_root_logger.handlers):
    _root_logger.removeHandler(h)

_fmt = (
    '%(asctime)s [%(levelname)s] %(filename)s:%(lineno)d:'
    '%(funcName)s() - %(message)s'
)
formatter = logging.Formatter(_fmt)

# file handler
fh = logging.FileHandler(config.log_dir / config.log_file)
fh.setLevel(config.log_level)
fh.setFormatter(formatter)
_root_logger.addHandler(fh)

# console handler
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(config.log_level)
ch.setFormatter(formatter)
_root_logger.addHandler(ch)

# each module can now do:
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# HTTP SESSION + PAGINATION
# -----------------------------------------------------------------------------

session = requests.Session()
session.headers.update({
    "Authorization": f"Token {config.netbox_token}",
    "Accept":        "application/json",
    "Content-Type":  "application/json",
})
session.verify = config.verify_ssl


def paged_get(
    url: str, params: Optional[Dict[str, Any]] = None
) -> Iterator[Dict[str, Any]]:
    """
    Iterate all objects from a paginated NetBox list endpoint.
    """
    while url:
        response = session.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        # Debug output for GET request
        logging.debug(f"GET {url} response headers: {response.headers}")
        logging.debug(f"GET {url} response content: {response.text}")
        logging.debug(f"GET {url} response data: {data}")
        for obj in data.get("results", []):
            yield obj
        url = data.get("next")  # swap to the next page URL
        params = None       # don't re-send params on 'next'

# ----------------------------------------------------------------------------
# Conditionally load & index the OUI database
# ----------------------------------------------------------------------------


if config.ext_mac_lookup:
    # Determine where the OUI DB lives:
    logger.debug(f"Test {config.oui_db_path} for OUI DB {config.oui_db_file}")
    if config.oui_db_path and config.oui_db_path.exists():
        db_path = config.oui_db_path / config.oui_db_file

    else:
        # fall back to script directory
        db_path = Path(__file__).parent / config.oui_db_file

    try:
        with db_path.open("r") as f:
            _OUI_DB = json.load(f)
        logger.info(f"Loaded OUI DB from {db_path}")
    except Exception as e:
        logger.error(f"Failed to load OUI DB from {db_path}: {e}")
        sys.exit(1)

    def lookup_oui_vendor(mac: str) -> str:
        """
        Find the best-match vendor in the local OUI DB via longest-prefix rule.
        """
        mac_norm = mac.upper().replace("-", ":")
        best_len = 0
        vendor = ""
        for entry in _OUI_DB:
            prefix = entry.get("macPrefix", "").upper()
            if mac_norm.startswith(prefix) and len(prefix) > best_len:
                best_len = len(prefix)
                vendor = entry.get("vendorName", "")
        return vendor

else:
    # stub when disabled
    def lookup_oui_vendor(mac: str) -> str:
        return ""


# ----------------------------------------------------------------------------
# Custom field definitions
# ----------------------------------------------------------------------------
# Metadata for each required custom field
REQUIRED_CF: List[Dict[str, Any]] = [
    {
        "name": "cf_ipam_prefix_discoverscan", "label": "Discover Scan",
        "group_name": "1. Prefix Details", "type": "boolean",
        "content_types": ["ipam.prefix"],
    },
    {
        "name": "cf_ipam_ipaddress_ageoffline", "label": "Age Offline (days)",
        "group_name": "2. Discovery Info", "type": "integer",
        "content_types": ["ipam.ipaddress"],
    },
    {
        "name": "cf_ipam_ipaddress_ageonline", "label": "Age Online (days)",
        "group_name": "2. Discovery Info", "type": "integer",
        "content_types": ["ipam.ipaddress"],
    },
    {
        "name": "cf_ipam_ipaddress_lastseen", "label": "Last Seen",
        "group_name": "2. Discovery Info", "type": "date",
        "content_types": ["ipam.ipaddress"],
    },
    {
        "name": "cf_ipam_ipaddress_online", "label": "Online",
        "group_name": "1. IP Address Details", "type": "boolean",
        "content_types": ["ipam.ipaddress"],
    },
    {
        "name": "cf_ipam_ipaddress_firstseen", "label": "First Seen",
        "group_name": "2. Discovery Info", "type": "date",
        "content_types": ["ipam.ipaddress"],
    },
    {
        "name": "cf_ipam_ipaddress_nmapinfo", "label": "Nmap Reason",
        "group_name": "2. Discovery Info", "type": "text",
        "content_types": ["ipam.ipaddress"],
    },
    {
        "name": "cf_ipam_ipaddress_nofreeze", "label": "No Freeze",
        "group_name": "1. IP Address Details", "type": "boolean",
        "content_types": ["ipam.ipaddress"],
    },
    {
        "name": "cf_ipam_ipaddress_mac", "label": "Linked MAC",
        "group_name": "1. IP Address Details", "type": "object",
        "content_types": ["ipam.ipaddress"],
        "related_object_type": "dcim.macaddress",
    },
    {
        "name": "cf_ipam_ipaddress_scanner_info", "label": "Scanner Info",
        "group_name": "2. Discovery Info", "type": "text",
        "content_types": ["ipam.ipaddress"],
    },
    {
        "name": "cf_mac_ipaddress_ipam", "label": "Linked IP Address",
        "group_name": "1. MAC Address Details", "type": "object",
        "content_types": ["dcim.macaddress"],
        "related_object_type": "ipam.ipaddress",
    },
    {
        "name": "cf_dcim_mac_ageoffline", "label": "MAC Age Offline (days)",
        "group_name": "2. Discovery Info", "type": "integer",
        "content_types": ["dcim.macaddress"],
    },
    {
        "name": "cf_dcim_mac_ageonline", "label": "MAC Age Online (days)",
        "group_name": "2. Discovery Info", "type": "integer",
        "content_types": ["dcim.macaddress"],
    },
    {
        "name": "cf_dcim_mac_firstseen", "label": "MAC First Seen",
        "group_name": "2. Discovery Info", "type": "date",
        "content_types": ["dcim.macaddress"],
    },
    {
        "name": "cf_dcim_mac_lastseen", "label": "MAC Last Seen",
        "group_name": "2. Discovery Info", "type": "date",
        "content_types": ["dcim.macaddress"],
    },
    {
        "name": "cf_dcim_mac_vendor", "label": "MAC Vendor",
        "group_name": "1. MAC Address Details", "type": "text",
        "content_types": ["dcim.macaddress"],
    },
    {
        "name": "cf_dcim_mac_online", "label": "Online",
        "group_name": "1. MAC Address Details", "type": "boolean",
        "content_types": ["dcim.macaddress"],
    },
    {
        "name": "cf_dcim_mac_scanner_info", "label": "Scanner Info",
        "group_name": "2. Discovery Info", "type": "text",
        "content_types": ["dcim.macaddress"],
    },
]


# ----------------------------------------------------------------------------
# API operations for custom fields
# ----------------------------------------------------------------------------
def fetch_existing_custom_fields() -> List[str]:
    """
    Return list of all custom-field names currently in NetBox.
    """

    try:
        url = f"{config.netbox_url}/api/extras/custom-fields/"
        return list({cf["name"] for cf in paged_get(url, url_params)})
    except Exception as e:
        logger.error(f"Failed to fetch existing custom fields: {e}")
        sys.exit(1)


def create_custom_field(cf: Dict[str, Any]) -> None:
    """Create a custom field using NetBox extras API."""
    payload: Dict[str, Any] = {
        "name": cf["name"],
        "label": cf["label"],
        "group_name": cf.get("group_name", ""),
        "type": cf["type"],
        "object_types": cf["content_types"],
    }
    if cf["type"] == "object":
        payload["related_object_type"] = cf.get("related_object_type")
    url = f"{config.netbox_url}/api/extras/custom-fields/"
    try:
        response = session.post(url, json=payload)
        response.raise_for_status()
        logger.info(f"Created custom field '{cf['name']}'")
    except Exception as e:
        msg = getattr(e, "response", None) and e.response.text or str(e)
        logger.error(f"Error creating custom field {cf['name']}: {msg}")
        sys.exit(1)


def validate_custom_fields() -> None:
    """
    Create missing required custom fields and log parameters for existing ones,
    using paged_get() to walk through all pages.
    """
    url = f"{config.netbox_url}/api/extras/custom-fields/"

    # 1) Determine which names already exist
    try:
        existing_names = fetch_existing_custom_fields()
    except Exception:
        logger.error("Could not retrieve existing custom fields; aborting.")
        sys.exit(1)

    # 2) Create the missing ones
    missing = [
        cf for cf in REQUIRED_CF
        if cf["name"] not in existing_names
    ]
    if missing:
        logger.info(f"Creating {len(missing)} missing custom fields…")
        for cf in missing:
            create_custom_field(cf)
    else:
        logger.info("All required custom fields already exist.")

    # 3) Fetch + dump parameters for every required field
    try:
        for cf_obj in paged_get(url, params=url_params):
            if cf_obj.get("name") in {cf['name'] for cf in REQUIRED_CF}:
                logger.debug(f"CustomField '{cf_obj['name']}' parameters:")
                for key, val in cf_obj.items():
                    logger.debug(f"  {key}: {val}")
    except Exception as e:
        logger.error(f"Failed to fetch custom field parameters: {e}")
