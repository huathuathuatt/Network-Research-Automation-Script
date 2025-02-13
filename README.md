# Network-Research-Automation-Script

This is a Bash script designed to automate network research tasks and enhance user anonymity. It installs and verifies tools like TOR, NMAP, WHOIS, Geoip-bin, and NIPE to automate scans and information gathering. The script also checks if you’re anonymous and forces reconnection if not.

# Features:
- Package Verification & Installation: Automatically checks and installs Geoip-bin, sshpass, TOR, NIPE, and other essential tools.
- Anonymity Check: Ensures all traffic is routed through TOR using NIPE. If you’re not anonymous, the script terminates and prompts you to fix it.
- NMAP & WHOIS Automation: Runs NMAP and WHOIS scans for network discovery and metadata collection.
- File Transfer Options: Compares and demonstrates the use of SCP (secure) vs FTP (insecure) for file transfers.
- Error Handling & Logs: Handles errors and logs scan results to /var/log/nr.log.

#How to Use:
1. Clone this repo:
```bash
git clone https://github.com/yourusername/network-research.git
```
2. Make it executable:
```bash
chmod +x ProjectNR.sh
```
3. Run it:
```bash
    ./ProjectNR.sh
```

# The script will verify packages, check anonymity, and execute network scans based on the options you select.
```bash
Example Output:
[#] Checking packages...
[#] Geoip-bin is installed.
[#] TOR is not installed. Installing...
[*] Verifying TOR connection... You are anonymous.
[*] Running NMAP scan...
[*] Results saved to Nmap_scan.txt
```

# Tools Used:

- dpkg: For package verification and management
- Geoip-bin & Curl: For geolocation and IP lookup
- TOR & NIPE: To anonymize all traffic
- NMAP & WHOIS: For network scans and domain info gathering
- SSH & SCP: For secure file transfers

# Things to Note:
- TOR might slow down scans. It’s normal. Multiple relay hops impact speed.
- Security Warning: This script uses StrictHostKeyChecking=no for automation, which reduces security. Use SSH keys instead for production environments.
- Logs: All scan results are saved in /var/log/nr.log. Check them if something goes wrong.

# Documentation
- [Network Research Report](docs/NR_Report.pdf)
