#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netbox_ipam_scanner.py — IPAM scanning for NetBox

Author:     LiteBitIO
Version:    1.7.2
Date:       2025-04-25
License:    GNU GPLv3
Copyright:  (c) 2025 LiteBitIO

Description:
    Connects to a NetBox instance via its REST API,
    runs nmap scans when activated for a prefix,
    and update IPAM data and MAC addresses,
    as well as some meetadata (including custom fields).

How it works:
    It goes through all IPAM prefixes that have the custom field
        cf_ipam_prefix_discoverscan = true
    and for each prefix, the script will :
    1. Run an nmap (advanced) ping scan of the whole prefix/subnet,
        and outputs the scan results to nmapoutputxml_[subnet].xml.
    2. Parse the XML output to get ip, mac, hostname, .....
    3. For every host found in the scan:
        - If the IP does not exist in Netbox,
            creates it (with /32 mask) in IPAM > IP Address.
        - If the IP also has a MAC address from the scan,
            if the MAC address does not exist in Netbox,
            it will create the MAC address in DCIM > Mac Address
        - If the IP exists and its cf_ipam_ipaddress_nofreeze is "True"
            (or unset), the IP will be updated with details from the scan:
            - the ip will be marked online (as it responded to the scan)
            - age offline will be set to 0
            - (age online is not yet used.. don't know if this is useful)
            - the linked MAC address will be updated from DCIM > Mac Address
                (if the scan discovered a new Mac Address for this IP,
                it will add it to DCIM > Mac Address first)
            - the DNS name will be updated with the hostname or DNS name (FQDN)
                if available from the scan
    4. For every IP  in Netbox for the prefix that did not appear in the scan,
            - calculates the “age offline” (days since last seen)
        and marks the IP as offline.

    Additional updates include DNS name, MAC details (if available),
    and several custom fields that start with "cf_".

Requirements:
    - Python 3.12+
    - requests
    - nmap
    - xml.etree (stdlib)
    - ipaddress (stdlib)
    - netbox_ipam_scanner_init.py
    - netbox_ipam_scanner_conf.toml

Usage:
    $ source /opt/netbox/venv/bin/activate
    $ python3.12 netbox_ipam_scanner.py
or
    $ /opt/netbox/venv/bin/python3.12 /opt/netbox/scripts/netbox_ipam_scanner.py

ChangeLog:
    v1.7.0 (2025-04-27): Add link from MAC to IP through cf_mac_ipaddress_ipam
    v1.6.0 (2025-04-25): Clean up code and add comments
    v1.5.0 (2025-04-23): Add Mac vendor lookup in MAC OUI db using local db
        (wget -v -d https://maclookup.app/downloads/json-database/get-db -O mac_oui_db.json)
    v1.4.0 (2025-04-20): Validate and/or automatically create the required
        custom fields used by this scanner
    v1.3.0 (2025-04-10): Move config and init functions to separate files
    v1.2.0 (2025-03-21): Added MAC custom-field support
    v1.1.0 (2025-01-10): Improved SSL handling & error logging
    v1.0.0 (2024-12-15): Initial release

Planned:
 - use SNMP to complement ip/mac address data:
    snmpwalk -v 2c -c [community] [switch/router/fw] ipNetToPhysicalPhysAddress
 - add fingerprinting to get some extra basic info?
 - add custom field to device, to enable snmp scan
 - additional methods to get MAC address for IP's beyond the current subnet
"""

__author__ = "LiteBitIO"
__version__ = "1.7.2"
__license__ = "GNU GPLv3"
__status__ = "Production"


import os
import sys
import subprocess
import xml.etree.ElementTree as ET
import requests
import datetime
import ipaddress
import logging
from typing import Dict, Any, Optional, List, Set
from netbox_ipam_scanner_init import (
    session,
    config,
    url_params,
    logger,
    paged_get,
    validate_custom_fields,
    lookup_oui_vendor,
)

# to work around errors related to self signed certificates
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================================================
# Helper Functions
# =============================================================================


def fetch_prefixes_to_scan() -> List[Dict[str, Any]]:
    """
    Retrieve all prefixes from NetBox that have custom field
    cf_ipam_prefix_discoverscan set to True.

    :returns:
        List of prefix objects (dictionaries).
    """
    prefixes: List[Dict[str, Any]] = []
    url = f"{config.netbox_url}/api/ipam/prefixes/"
    try:
        for prefix in paged_get(url, params=url_params):
            cf = prefix.get("custom_fields", {})
            if cf.get("cf_ipam_prefix_discoverscan") is True:
                prefixes.append(prefix)
        logging.info(f"Found {len(prefixes)} prefix(es) for scanning.")
    except Exception as e:
        logging.error(f"Error fetching prefixes from NetBox: {e}")
    return prefixes


def exec_nmap_scan(subnet: str, output_file: str) -> bool:
    """
    Execute an nmap ping scan on the specified subnet.

    The command used is:
      nmap -sn -PR -PE -R -oX <output_file> <config.nmap_dns> <subnet>

    Args:
        subnet: The subnet (in CIDR notation) to scan.
        output_file: The path to the XML file that will store scan output.

    :returns:
        True if the scan completed successfully; otherwise, False.
    """
    cmd = [
        "nmap", "-sn", "-PR", "-PE", "-PM", "-PP", "-PO", "-PY", "-PU", "-R", "-oX", output_file
    ] + config.nmap_dns.split() + [subnet]
    logging.info(f"Running nmap scan: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logging.error(f"nmap scan failed for {subnet}: {result.stderr}")
            return False
        return True
    except Exception as e:
        logging.error(f"Exception while running nmap scan for {subnet}: {e}")
        return False


def parse_nmap_xml(file_path: str) -> Dict[str, Dict[str, Any]]:
    """
    Parse the nmap XML output file and extract details for each host.

    For each <host> record in the XML, extract:
      - IPv4 address (from <address addrtype="ipv4">)
      - MAC address and vendor (from <address addrtype="mac">, if present)
      - Hostname (from <hostname> inside <hostnames>, if present)
      - The 'reason' attribute from <status>

    Args:
        file_path: Path to the nmap XML output file.

    Returns:
        A dictionary keyed by IP address, with values containing a dict:
        { "hostname": <str>, "mac": <str>, "vendor": <str>, "reason": <str> }
    """
    scan_results = {}
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        for host in root.findall('host'):
            # Get status information (e.g. reason for up state)
            status = host.find('status')
            reason = status.get("reason") if status is not None else ""
            # Extract addresses (IPv4 and MAC)
            ip = None
            mac = None
            vendor = None
            for addr in host.findall('address'):
                addr_type = addr.get("addrtype")
                if addr_type == "ipv4":
                    ip = addr.get("addr")
                elif addr_type == "mac":
                    mac = addr.get("addr")
                    vendor = addr.get("vendor")
            # Extract hostname (if any)
            hostname = ""
            hostnames_elem = host.find("hostnames")
            if hostnames_elem is not None:
                hostname_elem = hostnames_elem.find("hostname")
                if hostname_elem is not None:
                    hostname = hostname_elem.get("name", "")
            if ip:
                scan_results[ip] = {
                    "hostname": hostname,
                    "mac": mac,
                    "vendor": vendor,
                    "reason": reason,
                }
        logging.info(f"Parsed {len(scan_results)} host(s) from {file_path}.")
    except Exception as e:
        logging.error(f"Error parsing nmap XML file {file_path}: {e}")
    return scan_results


def link_mac_to_ip(mac_id: int, ip_id: int) -> None:
    """
    Patch the mac-address object so cf_mac_ipaddress_ipam points at its IP.
    """
    url = f"{config.netbox_url}/api/dcim/mac-addresses/{mac_id}/"
    # fetch existing custom_fields so we don’t clobber the others
    mac = fetch_mac_address_from_netbox_by_id(mac_id)
    cf = mac.get("custom_fields", {})
    cf["cf_mac_ipaddress_ipam"] = ip_id
    logging.info(
        f"Linking MAC {mac_id} to IP {ip_id} in cf cf_mac_ipaddress_ipam"
    )

    session.patch(url, json={"custom_fields": cf})


def fetch_mac_address_from_netbox_by_id(mac_id: int) -> Dict[str, Any]:
    url = f"{config.netbox_url}/api/dcim/mac-addresses/{mac_id}/"
    response = session.get(url)
    response.raise_for_status()
    return response.json()


def fetch_ip_address_from_netbox(ip: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve an IP address object from NetBox matching the given IP.

    Args:
        ip: The IP address as a string.

    Returns:
        The IP address object (dict) if found; otherwise, None.
    """
    url = f"{config.netbox_url}/api/ipam/ip-addresses/"
    data_params = {"address": ip}

    try:
        response = session.get(url, params=data_params)
        logging.debug(f"GET {url}?address={ip} → {response.status_code}")
        logging.debug(f"GET {url} response headers: {response.headers}")
        logging.debug(f"GET {url} response content: {response.text}")
        response.raise_for_status()
        data = response.json()
        logging.debug(
            f"fetch_ip_address_from_netbox({ip}) response data: {data}"
        )
        results = data.get("results", [])
        if results:
            return results[0]
    except Exception as e:
        logging.error(f"Error fetching IP {ip} from NetBox: {e}")
    return None


def create_ip_address_in_netbox(
    ip: str, prefix: str, details: Dict[str, Any]
) -> bool:
    """
    Create a new IP address object in Netbox for a scanned host.

    The new IP address is created with:
      - Address in CIDR notation with the same mask as the prefix.
      - DNS name (if available)
      - Custom fields updated:
            cf_ipam_ipaddress_ageoffline = 0
            cf_ipam_ipaddress_lastseen = current datetime
            cf_ipam_ipaddress_online = True
            cf_ipam_ipaddress_firstseen = current datetime
            cf_ipam_ipaddress_nmapinfo = scan "reason"
            cf_ipam_ipaddress_nofreeze = True
      - If a MAC address is available, it is added to dcim.mac-addresses
        (if needed) and linked via custom fields.

    Args:
        ip: The IP address (without mask).
        prefix: The parent prefix in CIDR notation.
        details: Dictionary with scan details.

    Returns:
        True if creation succeeded; otherwise, False.
    """
    try:
        # Parse the provided prefix to extract the mask length.
        network = ipaddress.ip_network(prefix, strict=False)
        mask = network.prefixlen
    except Exception as e:
        logging.error(f"Error parsing prefix {prefix}: {e}")
        return False

    # Construct the address with the same mask as the prefix.
    address = f"{ip}/{mask}"
    now = datetime.datetime.now().isoformat()
    data = {
        "address": address,
        "dns_name": details.get("hostname") or "",
        "custom_fields": {
            "cf_ipam_ipaddress_ageoffline": 0,
            "cf_ipam_ipaddress_lastseen": now,
            "cf_ipam_ipaddress_online": True,
            "cf_ipam_ipaddress_firstseen": now,
            "cf_ipam_ipaddress_nofreeze": True,
            "cf_ipam_ipaddress_nmapinfo": details.get("reason") or "",
            "cf_ipam_ipaddress_scanner_info": (
                f"Nmap reason={details.get('reason')} "
                f"hostname={details.get('hostname')}"
            ),
        },
    }

    # If a MAC address is available, add its details.
    mac = details.get("mac")
    if mac:

        # Retrieve (or create) the MAC address object in Netbox.
        mac_obj = fetch_mac_address_from_netbox(mac)
        if not mac_obj:
            mac_obj = create_mac_address_in_netbox(
                mac, details.get("vendor") or ""
            )
        if mac_obj:
            # NOTE: The field name is now corrected to 'cf_ipam_ipaddress_mac'
            data["custom_fields"]["cf_ipam_ipaddress_mac"] = mac_obj.get("id")

    url = f"{config.netbox_url}/api/ipam/ip-addresses/"
    try:
        response = session.post(url, json=data)
        response.raise_for_status()
        logging.info(f"Created IP {ip} with address {address} in Netbox.")
        ip_obj = response.json()
        logging.info(f"Created IP {ip}/{mask} (id={ip_obj['id']}) in NetBox.")

        # → link the MAC back to this IP
        if mac_obj:
            link_mac_to_ip(mac_obj["id"], ip_obj["id"])
        return True
    except Exception as e:
        logging.error(f"Error creating IP {ip} in Netbox: {e}")
        if hasattr(e, "response") and e.response is not None:
            logging.error(f"Response Headers: {e.response.headers}")
            logging.error(f"Response Content: {e.response.text}")
        return False


def update_ip_address_in_netbox(
    ip_obj: Dict[str, Any], details: Dict[str, Any]
) -> bool:
    """
    Update an existing IP address object in Netbox with the details
    from the latest scan.

    This function updates the following fields:
      - DNS Name (from scan hostname)
      - cf_ipam_ipaddress_ageoffline (set to 0)
      - cf_ipam_ipaddress_lastseen (current datetime)
      - cf_ipam_ipaddress_online (True)
      - cf_ipam_ipaddress_firstseen (if empty, set to current datetime)
      - cf_ipam_ipaddress_nmapinfo (from scan reason)

    Additionally, if a MAC address is provided, it will:
      add the MAC address to dcim.mac-addresses (if not already present)
      it will link the IP address to the MAC address in NetBox.

    The update is only performed if the custom field
      cf_ipam_ipaddress_nofreeze
    is True. If that field is explicitly False, the update is skipped.

    Args:
        ip_obj: The existing IP object from Netbox.
        details: Dictionary with scan details.

    Returns:
        True if update succeeded or skipped by freeze; otherwise, False.
    """
    ip_id = ip_obj.get("id")
    if not ip_id:
        logging.error("IP object has no ID; cannot update.")
        return False

    cf = ip_obj.get("custom_fields", {})
    nofreeze = cf.get("cf_ipam_ipaddress_nofreeze")
    if nofreeze is False:
        logging.info(f"IP {ip_obj.get('address')} is frozen; skipping update.")
        return True  # Skip update but not an error
    # If not set, initialize to True
    if nofreeze is None:
        cf["cf_ipam_ipaddress_nofreeze"] = True

    now = datetime.datetime.now().isoformat()
    update_data = {
        "dns_name": details.get("hostname") or ip_obj.get("dns_name", ""),
        "custom_fields": cf,
    }
    update_data["custom_fields"]["cf_ipam_ipaddress_ageoffline"] = 0
    update_data["custom_fields"]["cf_ipam_ipaddress_lastseen"] = now
    update_data["custom_fields"]["cf_ipam_ipaddress_online"] = True
    if not cf.get("cf_ipam_ipaddress_firstseen"):
        update_data["custom_fields"]["cf_ipam_ipaddress_firstseen"] = now
    update_data["custom_fields"]["cf_ipam_ipaddress_nmapinfo"] = (
        details.get("reason") or ""
    )
    update_data["custom_fields"]["cf_ipam_ipaddress_scanner_info"] = (
        f"Nmap reason={details.get('reason')} "
        f"hostname={details.get('hostname')}"
    )

    mac = details.get("mac")
    if mac:
        mac_obj = fetch_mac_address_from_netbox(mac)
        if not mac_obj:
            mac_obj = create_mac_address_in_netbox(
                mac, details.get("vendor") or ""
            )
        if mac_obj:
            update_data["custom_fields"]["cf_ipam_ipaddress_mac"] = (
                mac_obj.get("id")
            )
            link_mac_to_ip(mac_obj["id"], ip_obj["id"])

    url = f"{config.netbox_url}/api/ipam/ip-addresses/{ip_id}/"
    try:
        response = session.patch(url, json=update_data)
        logging.debug(
            f"PATCH {url} with payload {update_data} response headers: "
            f"{response.headers}"
        )
        logging.debug(
            f"PATCH {url} with payload {update_data} response content: "
            f"{response.text}"
        )
        response.raise_for_status()
        logging.info(f"Updated IP {ip_obj.get('address')} in Netbox.")
        return True
    except Exception as e:
        logging.error(
            f"Error updating IP {ip_obj.get('address')} in Netbox: {e}"
        )
        if e.response is not None:
            logging.error(f"Response Headers: {e.response.headers}")
            logging.error(f"Response Content: {e.response.text}")
        return False


def fetch_all_ip_addresses_for_prefix(
    prefix_cidr: str
) -> List[Dict[str, Any]]:
    """
    Retrieve all IP address objects from NetBox within the given prefix.

    Since the API may not offer a direct filter by prefix,
    this function fetches all IP addresses and then locally filters them.

    Args:
        prefix_cidr: The prefix in CIDR notation (e.g. "10.0.2.0/24").

    Returns:
        A list of IP address objects (dict) that belong to the subnet.
    """
    ip_addresses: List[Dict[str, Any]] = []
    network = ipaddress.ip_network(prefix_cidr)

    url = f"{config.netbox_url}/api/ipam/ip-addresses/"

    try:
        for ip_obj in paged_get(url, url_params):
            # The stored address may include a mask (e.g. "10.0.2.40/32")
            addr_str = ip_obj.get("address", "").split("/")[0]
            try:
                if ipaddress.ip_address(addr_str) in network:
                    ip_addresses.append(ip_obj)
            except Exception:
                continue
        logging.info(
            f"Found {len(ip_addresses)} IP address(es) in NetBox for "
            f"prefix {prefix_cidr}."
        )
    except Exception as e:
        logging.error(
            (
                f"Error fetching IP addresses for prefix {prefix_cidr} "
                f"from NetBox: {e}"
            )
        )
    return ip_addresses


def process_mac_addresses(scan_results: Dict[str, Dict[str, Any]]) -> None:
    """
    Loop through all MAC addresses found in the nmap scan results and
    add or update them in dcim/mac-addresses in NetBox,
    irrespective of their connection with an IP address.

    For each MAC, if it
      - does not exist, create it with the custom fields filled in.
      - does exist, update its custom fields with latest scan details.

    Args:
        scan_results: Dictionary keyed by IP address with details
        (including "mac" and "vendor").
    """
    # Collect unique MAC addresses along with their vendor info.
    mac_dict = {}
    for details in scan_results.values():
        mac = details.get("mac")
        vendor = details.get("vendor")  # vendor info from the scan
        if mac:
            mac_dict[mac] = vendor  # Ensures uniqueness.

    for mac, vendor in mac_dict.items():
        mac_obj = fetch_mac_address_from_netbox(mac)
        if mac_obj is None:
            logging.info(f"MAC {mac} not found in NetBox, trying creation.")
            created_mac = create_mac_address_in_netbox(mac, vendor)
            if created_mac:
                logging.info(f"Successfully created MAC {mac} in NetBox.")
            else:
                logging.error(f"Failed to create MAC {mac} in NetBox.")
        else:
            logging.info(f"MAC {mac} already exists, updating custom fields.")
            update_mac_address_in_netbox(mac_obj, vendor)


def fetch_mac_address_from_netbox(mac: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a MAC address object from NetBox by querying for an exact match.

    Args:
        mac: The MAC address as a string.

    Returns:
        MAC address object (dict) if an exact match is found; otherwise, None.
    """
    url = f"{config.netbox_url}/api/dcim/mac-addresses/?mac_address={mac}"

    try:
        response = session.get(url)
        logging.debug(f"GET {url} response headers: {response.headers}")
        logging.debug(f"GET {url} response content: {response.text}")
        response.raise_for_status()
        data = response.json()
        logging.debug(
            f"fetch_mac_address_from_netbox({mac}) response "
            f"data: {data}"
        )
        results = data.get("results", [])
        for item in results:
            returned_mac = item.get("mac_address", "")
            if returned_mac.lower() == mac.lower():
                logging.info(
                    f"Found matching MAC: {returned_mac} for query {mac}"
                )
                return item
        logging.info(f"No exact match for MAC {mac} in results: {results}")
        return None
    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP error fetching MAC {mac} from NetBox: {e}")
        if e.response is not None:
            logging.error(f"Response Headers: {e.response.headers}")
            logging.error(f"Response Content: {e.response.text}")
    except Exception as e:
        logging.error(f"Error fetching MAC {mac} from NetBox: {e}")
    return None


def create_mac_address_in_netbox(
    mac: str, vendor: str
) -> Optional[Dict[str, Any]]:
    """
    Create a new MAC address object in NetBox with custom fields.

    The payload now includes custom fields:
      - cf_dcim_mac_ageoffline: 0
      - cf_dcim_mac_ageonline: 0
      - cf_dcim_mac_firstseen: current timestamp
      - cf_dcim_mac_lastseen: current timestamp
      - cf_dcim_mac_vendor: vendor from scan (or empty string if None)

    The description field is now sent as an empty string.

    Args:
        mac: The MAC address string.
        vendor: The vendor name (if available).

    Returns:
        The created MAC address object (dict) if successful; otherwise, None.
    """
    # Prevent duplicates by checking existence first
    existing = fetch_mac_address_from_netbox(mac)
    if existing:
        logger.info(
            f"MAC {mac} already exists with ID {existing.get('id')}; "
            "skipping creation."
        )
        return existing

    now = datetime.datetime.now().isoformat()

    # Gather scan‐ and OUI‐derived vendor names
    scan_vendor = vendor or ""
    db_vendor = lookup_oui_vendor(mac) if config.ext_mac_lookup else ""

    # Decide which vendor to write
    if config.ext_mac_lookup:
        chosen_vendor = db_vendor or "no OUI vendor"
    else:
        chosen_vendor = scan_vendor or "no NMAP vendor"

    # Always record both for auditing
    scanner_info = f"NMAP vendor: {scan_vendor or 'no NMAP vendor'} " \
                   f" - OUI vendor: {db_vendor or 'no OUI vendor'}"

    logger.info(
        f"MAC {mac}: scan_vendor='{scan_vendor}', "
        f"db_vendor='{db_vendor}' → chosen='{chosen_vendor}'"
    )
    # Create the MAC address object in NetBox

    data = {
        "mac_address": mac,
        "description": "",  # Do not update description.
        "custom_fields": {
            "cf_dcim_mac_ageoffline": 0,
            "cf_dcim_mac_ageonline": 0,
            "cf_dcim_mac_firstseen": now,
            "cf_dcim_mac_lastseen": now,
            "cf_dcim_mac_online": True,
            "cf_dcim_mac_vendor": chosen_vendor,
            "cf_dcim_mac_scanner_info": scanner_info,
        },
    }

#    if linked_ip_id:
#        # set the reverse link
#        data["custom_fields"]["cf_mac_ipaddress_ipam"] = linked_ip_id

    url = f"{config.netbox_url}/api/dcim/mac-addresses/"
    try:
        response = session.post(url, json=data)
        logging.debug(
            f"POST {url} with payload {data} response "
            f"headers: {response.headers}"
        )
        logging.debug(
            f"POST {url} with payload {data} response "
            f"content: {response.text}"
        )
        response.raise_for_status()
        logging.info(f"Created MAC {mac} in NetBox.")
        return response.json()
    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP error creating MAC {mac} in NetBox: {e}")
        if e.response is not None:
            logging.error(f"Response Headers: {e.response.headers}")
            logging.error(f"Response Content: {e.response.text}")
        return None
    except Exception as e:
        logging.error(f"Error creating MAC {mac} in NetBox: {e}")
        return None


def update_mac_address_in_netbox(mac_obj: Dict[str, Any], vendor: str) -> bool:
    """
    Update an existing MAC address object with the latest scan details.

    This function updates the following custom fields:
      - cf_dcim_mac_ageoffline: set to 0 (since the MAC is seen online)
      - cf_dcim_mac_ageonline: set to 0 (reset on new scan)
      - cf_dcim_mac_lastseen: current timestamp
      - cf_dcim_mac_firstseen: if not already set, update to current timestamp
      - cf_dcim_mac_vendor: updated to vendor from the discovery

    Args:
        mac_obj: The existing MAC address object (dict) from NetBox.
        vendor: The vendor name from the scan.

    Returns:
        True if the update succeeded; otherwise, False.
    """
    mac_id = mac_obj.get("id")
    if not mac_id:
        logging.error("MAC object has no ID; cannot update.")
        return False
    mac = mac_obj.get("mac_address")
    if not mac:
        logging.error("MAC address does not exist; cannot update.")
        return False

    now = datetime.datetime.now().isoformat()

    # Gather scan‐ and OUI‐derived vendor names
    scan_vendor = vendor or ""
    db_vendor = lookup_oui_vendor(mac) if config.ext_mac_lookup else ""

    # Decide which vendor to write
    if config.ext_mac_lookup:
        chosen_vendor = db_vendor or "no OUI vendor"
    else:
        chosen_vendor = scan_vendor or "no NMAP vendor"

    # Always record both for auditing
    scanner_info = f"NMAP vendor: {scan_vendor or 'no NMAP vendor'} " \
                   f" - OUI vendor: {db_vendor or 'no OUI vendor'}"

    logger.info(
        f"MAC id {mac_id} MAC {mac}: scan_vendor='{scan_vendor}', "
        f"db_vendor='{db_vendor}' → chosen='{chosen_vendor}'"
    )

    cf = mac_obj.get("custom_fields", {})

    logging.info(
        f"Testing MAC {mac} custom field f_mac_ipaddress_ipam: "
        f"{cf['cf_mac_ipaddress_ipam']}"
    )

    # To work around the problem that NetBox returns a full object in
    # cf_mac_ipaddress_ipam, but the API does not accept the same object in
    # PATCH, we need to get the ID from the object to use it again in the PATCH
    tmp_ip_id = None
    if cf["cf_mac_ipaddress_ipam"] and "id" in cf["cf_mac_ipaddress_ipam"]:
        # If the MAC address is already linked to an IP address, fetch its ID
        tmp_ip_id = cf["cf_mac_ipaddress_ipam"]["id"]
    cf["cf_dcim_mac_ageoffline"] = 0
    cf["cf_dcim_mac_ageonline"] = 0
    cf["cf_dcim_mac_lastseen"] = now
    cf["cf_dcim_mac_online"] = True
    if not cf.get("cf_dcim_mac_firstseen"):
        cf["cf_dcim_mac_firstseen"] = now
    cf["cf_dcim_mac_vendor"] = chosen_vendor
    cf["cf_dcim_mac_scanner_info"] = scanner_info
    cf["cf_mac_ipaddress_ipam"] = tmp_ip_id

    update_data = {"custom_fields": cf}
    logging.info(
        f"Updating MAC {mac} with custom fields: {update_data}"
    )
    url = f"{config.netbox_url}/api/dcim/mac-addresses/{mac_id}/"
    try:
        response = session.patch(url, json=update_data)
        response.raise_for_status()
        logging.info(f"Updated MAC {mac_obj.get('mac_address')} in NetBox.")
        return True
    except requests.exceptions.HTTPError as e:
        logging.error(
            f"HTTP error updating MAC {mac_obj.get('mac_address')} "
            f"in NetBox: {e}"
        )
        if e.response is not None:
            logging.error(f"Response Headers: {e.response.headers}")
            logging.error(f"Response Content: {e.response.text}")
        return False


def update_offline_ip_in_netbox(ip_obj: Dict[str, Any]) -> bool:
    """
    For an IP address that was NOT seen in the latest scan,
    update its status to offline.

    The function calculates the number of days since the last seen date
    (stored in cf_ipam_ipaddress_lastseen) and updates:
      - cf_ipam_ipaddress_ageoffline to that number
      - cf_ipam_ipaddress_online to False

    Args:
        ip_obj: The IP address object from NetBox.

    Returns:
        True if the update was successful; otherwise, False.
    """
    ip_id = ip_obj.get("id")
    if not ip_id:
        logging.error("IP object has no ID; cannot update offline status.")
        return False

    cf = ip_obj.get("custom_fields", {})
    lastseen_str = cf.get("cf_ipam_ipaddress_lastseen")
    if lastseen_str:
        try:
            lastseen = datetime.datetime.fromisoformat(lastseen_str)
            offline_days = (datetime.datetime.now() - lastseen).days
        except Exception as e:
            logging.error(
                f"Error parsing last seen date for "
                f"IP {ip_obj.get('address')}: {e}"
            )
            offline_days = 0
    else:
        offline_days = 0

    # Instead of sending the entire custom_fields dictionary,
    # update only the offline-related fields.
    update_data = {
        "custom_fields": {
            "cf_ipam_ipaddress_ageoffline": offline_days,
            "cf_ipam_ipaddress_online": False,
        }
    }

    url = f"{config.netbox_url}/api/ipam/ip-addresses/{ip_id}/"
    try:
        response = session.patch(url, json=update_data)
        response.raise_for_status()
        logging.info(
            f"Set IP {ip_obj.get('address')} offline "
            f"(age: {offline_days} day(s))."
        )
        return True
    except requests.exceptions.HTTPError as e:
        logging.error(
            f"Error updating offline status for "
            f"IP {ip_obj.get('address')}: {e}"
        )
        if e.response is not None:
            logging.error(f"Response Headers: {e.response.headers}")
            logging.error(f"Response Content: {e.response.text}")
        return False


def fetch_all_mac_addresses_from_netbox() -> List[Dict[str, Any]]:
    """Fetch every MAC‐Address object from NetBox."""
    url = f"{config.netbox_url}/api/dcim/mac-addresses/?limit=0"
    try:
        mac_list = list(paged_get(url, url_params))
        logger.info(f"Fetched {len(mac_list)} MAC address(es) from NetBox")
        return mac_list
    except Exception as e:
        logger.error(f"Error fetching MAC addresses from NetBox: {e}")
        return []


def update_offline_mac_in_netbox(mac_obj: Dict[str, Any]) -> bool:
    """
    For a MAC not seen in the latest scan, set cf_dcim_mac_online = False
    and cf_dcim_mac_ageoffline to days since last seen.
    """
    mac_id = mac_obj["id"]
    cf = mac_obj.get("custom_fields", {})
    lastseen = cf.get("cf_dcim_mac_lastseen")
    try:
        lastseen_dt = datetime.datetime.fromisoformat(lastseen)
        offline_days = (datetime.datetime.now() - lastseen_dt).days
    except:
        offline_days = 0

    payload = {
        "custom_fields": {
            "cf_dcim_mac_online": False,
            "cf_dcim_mac_ageoffline": offline_days,
        }
    }
    url = f"{config.netbox_url}/api/dcim/mac-addresses/{mac_id}/"
    try:
        response = session.patch(url, json=payload)
        response.raise_for_status()
        logger.info(
            f"Marked MAC {mac_obj['mac_address']} offline ({offline_days}d)"
        )
        return True
    except Exception as e:
        logger.error(
            f"Error setting MAC {mac_obj['mac_address']} offline: {e}"
        )
        return False


# =============================================================================
# Main Processing Functions
# =============================================================================


def process_prefix(prefix: Dict[str, Any]) -> Set[str]:
    """
    Process a single prefix from Netbox:
      1. Determine the subnet.
      2. Run an nmap scan on the subnet.
      3. Parse the XML results.
      4. For each host found in the scan, create or update IP object.
      5. For each IP address in Netbox that was not seen in the scan,
         update its offline status.
      6. Returns the set of MAC addresses seen in the scan of this prefix

    Args:
        prefix: A prefix object (dict) from Netbox.
    """
    prefix_cidr = prefix.get("prefix")
    if not prefix_cidr:
        logging.error("Prefix object missing the 'prefix' field.")
        return set()

    logging.info(f"Processing prefix: {prefix_cidr}")

    # Construct a safe output file name for the nmap XML scan.
    safe_prefix = prefix_cidr.replace("/", "-")
    output_file = os.path.join(
        config.nmap_dir, f"nmapoutputxml_{safe_prefix}.xml"
    )

    # Run the nmap scan.
    if not exec_nmap_scan(prefix_cidr, output_file):
        logging.error(f"nmap scan failed for prefix {prefix_cidr}")
        return set()

    # Parse the XML output.
    scan_results = parse_nmap_xml(output_file)
    seen: Set[str] = {
        details["mac"]
        for details in scan_results.values()
        if details.get("mac")
    }

    # Process MAC addresses first, irrespective of their connection with an IP.
    process_mac_addresses(scan_results)

    # Phase 1: For each IP address found in the scan,
    # create or update in Netbox.
    for ip, details in scan_results.items():
        ip_obj = fetch_ip_address_from_netbox(ip)
        if ip_obj:
            update_ip_address_in_netbox(ip_obj, details)
        else:
            create_ip_address_in_netbox(ip, prefix_cidr, details)

    # Phase 2: For each existing IP address in Netbox for this prefix,
    # if it was NOT seen in the scan, update its offline status.
    netbox_ips = fetch_all_ip_addresses_for_prefix(prefix_cidr)
    scanned_ips = set(scan_results.keys())
    for ip_obj in netbox_ips:
        # Extract the IP address part (without mask)
        ip_addr = ip_obj.get("address", "").split("/")[0]
        if ip_addr not in scanned_ips:
            update_offline_ip_in_netbox(ip_obj)

    return seen


def main():
    """
    Main entry point for the Netbox IPAM Scanner.
    """
    logging.info("Starting Netbox IPAM Scanner")
    validate_custom_fields()

    prefixes = fetch_prefixes_to_scan()
    if not prefixes:
        logging.info("No prefixes found for scanning; exiting.")
        sys.exit(0)

    total_seen_macs: Set[str] = set()

    for prefix in prefixes:
        seen = process_prefix(prefix)
        total_seen_macs |= seen

    # Now mark *all* DCIM MACs that weren’t seen as offline:
    for mac_obj in fetch_all_mac_addresses_from_netbox():
        if mac_obj["mac_address"] not in total_seen_macs:
            update_offline_mac_in_netbox(mac_obj)
            logging.info(f"Setting {mac_obj["mac_address"]} offline.")

    logging.info("IPAM Scanner: Netbox IPAM Scanner finished.")


if __name__ == "__main__":
    main()
