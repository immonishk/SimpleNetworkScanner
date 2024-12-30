import nmap

print("\n* Welcome to the Simple Network Scanner *")
print("⚠  Warning: This port scanner should only be used on networks and devices for which you have explicit permission. \n")

port_descriptions = {
    1: "TCP Port Service Multiplexer",
    2: "FTP Data Transfer Protocol",
    3: "Compression Protocol",
    5: "Remote Job Entry",
    7: "Echo Protocol",
    9: "Discard Protocol",
    11: "Active Users",
    13: "Daytime Protocol",
    17: "Quote of the Day",
    19: "Character Generator Protocol",
    20: "FTP Data Transfer",
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    24: "Privileged Port",
    25: "SMTP (Simple Mail Transfer Protocol)",
    33: "Display Support Protocol",
    37: "Time Protocol",
    42: "WINS (Windows Internet Name Service)",
    43: "WHOIS Protocol",
    49: "TACACS+ (Terminal Access Controller Access Control System)",
    50: "Remote Authentication Dial-In User Service (RADIUS)",
    53: "DNS (Domain Name System)",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "Trivial File Transfer Protocol (TFTP)",
    70: "Gopher Protocol",
    79: "Finger Protocol",
    80: "HTTP (Hypertext Transfer Protocol)",
    88: "Kerberos",
    102: "Microsoft-DS (Active Directory, SMB over TCP)",
    109: "POP3 (Post Office Protocol)",
    110: "POP3 (Post Office Protocol)",
    111: "Portmapper",
    113: "Authentication Service",
    115: "Simple File Transfer Protocol (SFTP)",
    119: "Network News Transfer Protocol (NNTP)",
    123: "NTP (Network Time Protocol)",
    135: "MS RPC (Microsoft Remote Procedure Call)",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP (Internet Message Access Protocol)",
    160: "NetWare Core Protocol (NCP)",
    161: "SNMP (Simple Network Management Protocol)",
    162: "SNMP Trap",
    179: "BGP (Border Gateway Protocol)",
    194: "IRC (Internet Relay Chat)",
    443: "HTTPS (Secure HTTP)",
    445: "Microsoft-DS (Active Directory, SMB over TCP)",
    465: "SMTP over SSL",
    514: "Syslog",
    515: "Printer Services (Line Printer Daemon)",
    520: "Routing Information Protocol (RIP)",
    587: "SMTP (Submission)",
    631: "Internet Printing Protocol (IPP)",
    636: "LDAP over SSL",
    993: "IMAPS (IMAP Secure)",
    995: "POP3S (POP3 Secure)",
    1080: "SOCKS Proxy",
    1433: "Microsoft SQL Server",
    1434: "Microsoft SQL Monitor",
    1521: "Oracle Database",
    1600: "Cisco TACACS+",
    1701: "L2TP (Layer 2 Tunneling Protocol)",
    1723: "PPTP (Point-to-Point Tunneling Protocol)",
    2869: "UPnP (Universal Plug and Play)",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop Protocol)",
    5040: "VPN (Virtual Private Network)",
    5357: "Web Services Discovery",
    5432: "PostgreSQL Database",
    5900: "VNC (Virtual Network Computing)",
    6379: "Redis",
    8080: "HTTP Alternative (commonly used for web servers)",
    8443: "HTTPS Alternative",
    9000: "Webmin",
    27017: "MongoDB",
    32768: "MS RPC",
    49152: "Dynamic/Private Ports",
    49664: "Dynamic/Private Port",
    49665: "Dynamic/Private Port",
    49666: "Dynamic/Private Port",
    49667: "Dynamic/Private Port",
    49668: "Dynamic/Private Port",
    49674: "Dynamic/Private Port",
    50131: "Dynamic/Private Port"
}

def list_devices_on_network():
    nm = nmap.PortScanner()
    print("Scanning the network for devices... This may take a moment.")
    nm.scan(hosts='192.168.1.0/24', arguments='-sn')
    print("\nDevices found on the network:")
    devices = []
    for host in nm.all_hosts():
        devices.append(host)
        print(f"IP: {host} ({nm[host].hostname() if nm[host].hostname() else 'N/A'})")
    return devices

def nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-65535')

    with open('scan_report.txt', 'w') as report:
        for host in nm.all_hosts():
            hostname = nm[host].hostname() if nm[host].hostname() else "N/A"
            report.write('Scan Report\n')
            report.write(f'Host: {host} ({hostname})\n')
            report.write(f'State: {nm[host].state()}\n')

            for proto in nm[host].all_protocols():
                report.write('~~~~~~~~~~~~~~~~~~~~~~~~~\n')
                report.write(f'Protocol: {proto}\n')
                lport = nm[host][proto].keys()
                lport = sorted(map(int, lport))

                for port in lport:
                    port_state = nm[host][proto][port]["state"]
                    description = port_descriptions.get(port, "No description available")
                    report.write(f'Port: {port}\tState: {port_state}\tService: {description}')
                    print(f'Port: {port}\tState: {port_state}\tService: {description}')
                    report.write('\n')

    print(f"\nScan complete! Report for IP {target} is saved to scan_report.txt")

devices = list_devices_on_network()

target = input("\nEnter the target IP for scanning: ")
print("\nScanning ports... This may take a while...")
nmap_scan(target)