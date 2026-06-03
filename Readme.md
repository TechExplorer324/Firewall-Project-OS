# Linux Kernel Firewall

This project provides a custom Linux kernel module built using Netfilter hooks to act as a lightweight firewall. It is capable of dropping network packets based on Source IP, Destination IP, Source Port, Destination Port, and basic DNS payload inspection for URL blocking.

The project includes a Bash wrapper script (`run_firewall.sh`) that automates compilation, module insertion, user interaction, and logging cleanup.

To compile and run this firewall, you need a Linux environment with the following packages installed:
    1) Root Privilege - to load and unload kernel modules
    2) Linux headers- You should run the following commands: 
    sudo apt update
    sudo apt install build-essential linux-headers-$(uname -r)
    3) Build Essentials: make and gcc


# Operate Using the Interactive Script

Operate the firewall is by using the provided `run_firewall.sh` script.

1. Go to root:
    su
    Enter password

2.  Make the script executable:
    chmod +x run_firewall.sh
    
3.  Run the script as root:
    sudo ./run_firewall.sh

3.  Follow the Interactive Menu:
    Once loaded, the script will present an interactive menu with 7 options:
    
    * 1) Block a Website Via IP Resolution: This option asks for a domain (e.g., `neverssl.com`). The script resolves the domain to an IP address in user-space using `dig` and instructs the kernel to drop packets destined for that IP. *Best for sites with a single, static IP.*
    * 2) Block a website via Packet Inspection: This option blocks sites by inspecting UDP packets on port 53 (DNS traffic). If a requested domain matches the blocked URL string, the DNS request is dropped. *Best for large sites like `cnn` that use many IPs.* When entering, do not enter cnn.com. Instead only enter cnn. Follow steps under BLOCKING_IN_FIREFOX to ensure that you are able to block the website. 
    * 3) Block a Destination IP: Manually block all outbound traffic to a specific IPv4 address.
    * 4) Block a Destination Port: Manually block all outbound traffic to a specific port (e.g., `443` for HTTPS or `53` for DNS).
    * 5) Block a Source IP: Manually block all incoming traffic from a specific IPv4 address.
    * 6) Block a Source Port: Manually block all incoming traffic from a specific port (e.g., `22` to block inbound SSH).
    * 7) End Session & Save Logs: This stops the firewall, unloads the kernel module (`rmmod`), and exports the kernel ring buffer logs for the session into a local file named `session_logs.txt`.


# BLOCKING_IN_FIREFOX 
    1) Disable DoH - 
        1) Open Firefox and go to Settings.
        2) Search for "DNS over HTTPS" in the settings search bar.
        3) Change the setting from "Default Protection" or "Increased Protection" to "Off".
    
    2) Clear browser cache
        1) Open a new tab in Firefox and type about:networking#dns in the URL bar.
        2) Click the "Clear DNS Cache" button.

    To test:
        1) Make sure firewall is running and you have blocked the website via entering website name (Ex: cnn)
        2) Try to navigate to cnn.com 



# View Real-Time Logs:
    Monitor blocked packets in real-time by checking the kernel log via the kernel ring buffer:

    dmesg | tail -n 2

    Alternatively, you can read `/var/log/kern.log` --> Command: cat /var/log/kern.log | grep "Firewall"



# Limitations 
* Maximum Rules: The firewall is hardcoded to support up to 100 blocks per category (100 source IPs, 100 destination IPs, etc.).
* URL Blocking Mechanism: The packet inspection feature specifically intercepts **UDP traffic on Port 53**. It searches the packet payload for a matching string. It will drop the DNS request, effectively preventing the user from resolving the IP of the restricted website.
* Persistence: The firewall rules are stored in memory (`kmalloc` array). They do not persist across reboots or after unloading the module. You must re-apply the rules every time the module is loaded.