#!/bin/bash

# Check script is running as root
if [ "$EUID" -ne 0 ]; then
  echo "Run as root. Cant run like this"
  exit
fi

echo "Starting Firewall Session"

# Clear the old kernel ring buffer from previous session
dmesg -c > /dev/null


make
insmod firewall.ko
echo "Firewall module loaded."

while true; do
    echo ""
    echo "Choose an option:"
    echo "1) Block a Website Via IP Resolution Ex: neverssl.com. Works on websites with only a single IP Adress"
    echo "2) Block a Website via Packet Inspection. Ex: cnn (will block websites on basis of its name)"
    echo "3) Block a Destination IP"
    echo "4) Block a Destination Port"
    echo "5) Block a Source IP"
    echo "6) Block a Source Port"
    echo "7) End Session & Save Logs"
    read -p "Selection (In between 1-7): " choice

    case $choice in
        1)
            #works by resolving to IP adress
            read -p "Enter website (e.g. example.com): [Do not enter https ]" domain
            ip=$(dig +short $domain | tail -n1) #here convertin domain name to ip adress happens in user space, rest all happen in kernel space
            if [ -n "$ip" ]; then
                echo "Resolved to $ip."
                echo "destination_ip $ip" > /proc/my_firewall/rules
            else
                echo "Could not resolve domain."
            fi
            ;;
        2) 
            read -p "Enter website url to block (ex: cnn.com). Enter only cnn (do not enter .com or https): " domain
            if [ -n "$domain" ]; then
                echo "block_url $domain" > /proc/my_firewall/rules
            else 
                echo "Invalid entry"
            fi
            ;;
        3)
            read -p "Enter Destination IP: " ip
            echo "destination_ip $ip" > /proc/my_firewall/rules
            ;;
        4)
            read -p "Enter Destination Port: " port
            echo "dest_port $port" > /proc/my_firewall/rules
            ;;
        5)
            read -p "Enter Source IP:" ip
            echo "source_ip $ip" > /proc/my_firewall/rules
            ;;
        6) 
            read -p "Enter Source Port: " port
            echo "source_port $port" > /proc/my_firewall/rules
            ;;
        7)
            echo "Ending session"
            # Unload the module
            rmmod firewall
            
            # Save the kernel logs from this session to a text file!
            echo "Saving logs to session_logs.txt"
            dmesg > session_logs.txt
            
            echo "Session complete. Check session_logs.txt for the audit trail."
            break
            ;;
        *)
            echo "Invalid option."
            ;;
    esac
done
