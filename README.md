# NetBox IPAM Scanner

The **NetBox IPAM** Scanner is a NetBox / Python script which uses NMAP to scan the IPAM prefixes for online ip addresses to check which ones are live, add newly found ip addresses to the IPAM module in NetBox, and collect some additional information for IPAM use.

I initially wanted to create a plugin for this, but as I'm not a seasoned Python dev, and to optimize the time I could spend on it, I decided to stick with a script. Also, because most activity would happen in the background anyway, I didn't see the big advantage of creating a plugin for it (except maybe for creating the necessary custom fields automatically)

I decided to use NMAP as the main scan tool, as it offers most flexibility now and future use.

I made this script for my use case, but decided to share it, in case it is useful for others.

# What does the NetBox IPAM scanner do

## Discovery & Update
The script will loop through all the defined Prefixes in the IPAM module. For each prefix where the custom field (CF) cf_ipam_prefix_discoverscan is True or not set, it will start a subnet scan with NMAP. 

(Update) It will update existing IP addresses with info from the scan.
(discovery) It will add IP addresses in the IPAM module if they do not exist.

I run the script every 15 minutes through cron.

## Experimental
It will also add the MAC address info from the scan into the DCIM (MAC address) module.
It will link the IP address to that MAC address, and the MAC address to that IP address.

*For the network engineers out there, we know that ARP information is only available in the vlan the server is connected to (and NMAP's MAC address info comes from ARP responses). Scans of other subnets across L3 (router) will not return MAC address information. There are other methods to get that MAC address info, but I didn't had the time to work on that yet.*

# How does it work
There are 3 files:
 - **netbox_ipam_scanner.toml** : file with the configuration variables
 - **netbox_ipam_scanner_init.py** : script doing all needed initialization (it is called from the main scanner script)
 - **netbox_ipam_scanner.py** : main scanner script

## Custom fields

The script needs a number of custom fields (CF) defined. To make it easy, these CF are checked and ***automatically created*** if missing by **netbox_ipam_scanner_init.py** on its first run, or when CF are accidentally renamed or removed. Check these CF before running the scripts, the make sure you don't have any conflicts.
They may not all be useful for everyone, but they are to me in my specific use case.

You can check the details for each CF in **netbox_ipam_scanner_init.py** 
name = name of the CF
label = label of the CF in the NetBox UI
type = type of CF
content_type = for which object/model the CF is created
related_object_type = for linked fields, the linked object
group_name = to organize the CF visibly in the NetBox UI 
(I used 2 groups: "Details" when the field leans more to additional details of the object; "Discovery Info" when the field leans more to discovery information)

### Here is the list of CF with their purpose:
**CF added to IPAM > Prefix**
- cf_ipam_prefix_discoverscan = Setting (true/false or on/off) to allow (or prevent) the prefix to be scanned. To set manually.

**CF added to IPAM > IP Address**
- cf_ipam_ipaddress_ageoffline = How many days has this IP been offline
- cf_ipam_ipaddress_ageonline = (not yet used) How many days has this IP been active 
- cf_ipam_ipaddress_lastseen = Date & time when this IP was last seen 
- cf_ipam_ipaddress_online = Was this IP active/online during the last (most recent) scan
- cf_ipam_ipaddress_firstseen = Date & time when this IP was first seen (= when was it discovered)
- cf_ipam_ipaddress_nmapinfo = To store extra info, or testing info from NMAP (I use it for testing)
- cf_ipam_ipaddress_scanner_info = Used to store other info from the scanner
- cf_ipam_ipaddress_nofreeze = If enabled (default), the script is allowed to update the info of this IP address. Disabling this should prevent the script from updating the IP information.
- cf_ipam_ipaddress_mac = Link to the MAC address (in DCIM > Mac Address) for this IP address

**CF added to DCIM > MAC Address**
- cf_mac_ipaddress_ipam = Link to the IP address (in IPAM > IP Address) for this MAC address
- cf_dcim_mac_ageoffline  = How many days has this MAC been offline
- cf_dcim_mac_ageonline = (not yet used) How many days has this MAC been active 
- cf_dcim_mac_firstseen = Date & time when this MAC was first seen (= when was it discovered)
- cf_dcim_mac_lastseen = Date & time when this MAC was last seen 
- cf_dcim_mac_vendor = MAC vendor (from the official OUI database)
- cf_dcim_mac_online = Was this MAC active/online during the last (most recent) scan
- cf_dcim_mac_scanner_info = Used to store other info from the scanner

## netbox_ipam_scanner.toml
Config file to set various options/variables to match you environment. Explanation for each setting is in the file itself.


## netbox_ipam_scanner_init.py
This script is called from the main script.

This script will
- Read the netbox_ipam_scanner.toml configuration file 
- Check CF and create missing CF 
- Initialize the logger
- 
 

 
<!--stackedit_data:
eyJoaXN0b3J5IjpbNzgxNzgxNTU5LDU5MTk1ODgwNywtNzI5ND
IxNDA5XX0=
-->