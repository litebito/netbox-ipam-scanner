# NetBox IPAM Scanner

The **NetBox IPAM** Scanner is a NetBox / Python script which uses NMAP to scan the IPAM prefixes for online ip addresses to check which ones are live, add newly found ip addresses to the IPAM module in NetBox, and collect some additional information for IPAM use.

I initially wanted to create a plugin for this, but as I'm not a seasoned Python dev, and to optimize the time I could spend on it, I decided to stick with a script. Also, because most activity would happen in the background anyway, I didn't see the big advantage of creating a plugin for it (except maybe for creating the necessary custom fields automatically)

I decided to use NMAP as the main scan tool, as it offers most flexibility now and future use.

I made this script for my use case, but decided to share it, in case it is useful for others.

**Warning**:
- ensure you have a NetBox data backup before using this script the first time (you should take a daily backup anyway)

### Prerequisites
- NetBox 4.2.5+ (script developed and tested from 4.2.5 and later) on a linux server
- Python 3.12+ (script developed and tested with Python 3.12, it may need some adaptation for 3.10 and 3.11)
- nmap installed
- the OUI database in JSON format from https://maclookup.app
- a NetBox API token with the correct permissions

## 1. What does the NetBox IPAM scanner do

### Discovery & Update
The script will loop through all the defined Prefixes in the IPAM module. For each prefix where the custom field (CF) cf_ipam_prefix_discoverscan is True or not set, it will start a subnet scan with NMAP. 

(Update) It will update existing IP addresses with info from the scan.
(discovery) It will add IP addresses in the IPAM module if they do not exist.

I run the script every 15 minutes through cron.

### Experimental
It will also add the MAC address info from the scan into the DCIM (MAC address) module.
It will link the IP address to that MAC address, and the MAC address to that IP address.

*For the network engineers out there, we know that ARP information is only available in the vlan the server is connected to (and NMAP's MAC address info comes from ARP responses). Scans of other subnets across L3 (router) will not return MAC address information. There are other methods to get that MAC address info, but I didn't had the time to work on that yet.*

## 2. How does it work
There are 3 files:
 - **netbox_ipam_scanner.toml** : file with the configuration variables
 - **netbox_ipam_scanner_init.py** : script doing all needed initialization (it is called from the main scanner script)
 - **netbox_ipam_scanner.py** : main scanner script

### 2.1 Custom fields

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

#### Here is the list of CF with their purpose:
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

### 2.2 netbox_ipam_scanner.toml
Config file to set various options/variables to match you environment. Explanation for each setting is in the file itself.


### 2.3 netbox_ipam_scanner_init.py
Called from the main script, do not run it directly
This script will
- Read the netbox_ipam_scanner.toml configuration file 
- Check CF and create missing CF 
- Initialize the logger
- Initialize the API session and a paged get function
- Load the OUI database
 
 ## netbox_ipam_scanner.py
 This script will:
 - Fetch the prefixes which are set to be scanned (cf_ipam_prefix_discoverscan)
 - For each fetched prefix, launch an nmap scan for the whole subnet
 - Parse the scan results
 - Create/update IP addresses from the scan in NetBox
	 - update first/last seen
	 - update days offline to 0
	 - update MAC address link
 - Create/update MAC addresses from the scan in NetBox
 	 - update first/last seen
	 - update days offline to 0
	 - update IP address link
- Process offline IP's
	- update days offline
- Process offline MAC's
	- update days offline

## 3. How to install
### 3.1 Create the NetBox API token and permissions
You need to prepare a few things in NetBox, before the script can run: you will need to create (in this order) a permissions set, a user_id, an API token
1. Logon in NetBox as an admin
2. go to Authentication > Permissions, create a permission set, for example ***perm_api_ipam_scanner*** and configure this as follows:
	-	Enabled: True
	-	Actions : Enable "Can View", "Can Add", "Can Change", "Can Delete"
	-	Select the following object types:
				-   DCIM | interface
				-   DCIM | device
				-   DCIM | MAC address
				-   IPAM | IP address
				-   IPAM | prefix
				-   IPAM | VLAN
				-   IPAM | IP range
				-   Extras | custom field
				-   Extras | custom field choice set
3. go to Authentication > Users, create a user, for example ***autom_ipam_scanner*** and configure the user as follows:
	-	Set status to "Active" and "Staff Active"
	-	In thee drop down "Permissions" select the permission set you just created (from the example above: perm_api_ipam_scanner)
4. go to Authentication > API, create a new token, and configure the token as follows:
	-	Select the user you just created (from the example above: autom_ipam_scanner) 
	-	Enable "Write Enabled"
	-	Set the allowed IP's to the IP (or subnet) of your server
	-	***IMPORTANT*** Copy the API token and save it somewhere, this is the only moment you will see the token

### 3.2 The basics
1. Copy the 2 script files and the toml file to the main script directory in your NetBox directory
	 - if you installed netbox in /opt/netbox, copy the files to /opt/netbox/scripts
2. Copy or download the mac_oui_db.json 
	-	the easiest is to put the file in the same directory as the scripts
	-	if you put it somewhere else, don't forget to update the path in the config file
3. Rename netbox_ipam_scanner_conf_DIST.toml to netbox_ipam_scanner_conf.toml
	- Update the netbox_ipam_scanner_conf file with your settings/options
4. Run the script manually the first time (check for errors):
```
/opt/netbox/venv/bin/python3.12 /opt/netbox/scripts/netbox_ipam_scanner.py
```
### 3.3 Schedule it
1. Schedule it via cron, for example:
	- create /etc/cron.d/netbox-scripts
```
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=""
# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed
*/15 * * * * root /opt/netbox/venv/bin/python3.12 /opt/netbox/scripts/netbox_ipam_scanner.py >> /var/log/netbox/netbox_ipam_scanner.cron.log 2>&1
```
-	this will make it run every 15 minutes (adapt to your needs)

### 3.4 The OUI database.
You can download the required database for free. In the directory where you want to store the db:
wget -v -d https://maclookup.app/downloads/json-database/get-db -O mac_oui_db.json


## Disclaimer
Use at your own risk, I'm not responsible for how the script reacts with or impacts your environment.
ALWAYS take a backup before trying community contributions

I'm not a Python developer, so the scripts may not be flawless. 
If you run into an issue, report them thr
<!--stackedit_data:
eyJoaXN0b3J5IjpbLTEwNjE1ODY1NDgsMzQzMDg3NDcwLC0xOD
I1NDEzMDkwLDk1NTcwNzU2OCwxMjg4NTY0NDY5LDU5MTk1ODgw
NywtNzI5NDIxNDA5XX0=
-->