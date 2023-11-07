#!/usr/bin/env python
"""
SYNOPSIS

    python port_scanner.py "destination ips delimited by commas" [-h,--help] [-v,--verbose] [-o,--open] [-c,--closed] [-f,--filtered] [-e,--error] [--version]

DESCRIPTION

    Run this program by running "python port_scanner.py "destination ips delimited by commas" [optional_flags]" in the terminal/powershell in the containing folder.
    Accepted IP formats are IPv4 dot notation addresses and domain names, including CIDR notation.

EXAMPLES

    Examples:
    python port_scanner.py "127.0.0.1" -o (Windows)
    sudo python3 port_scanner.py "www.google.com/30, 1.1.1.1/24" -v -o -f --version (Linux)

AUTHOR

    Kridtity Lawang <30082530@tafe.wa.edu.au>

LICENSE

    This script is the exclusive and proprietary property of
    TiO2 Minerals Consultants Pty Ltd. It is only for use and
    distribution within the stated organisation and its
    undertakings.

VERSION

    1.0
"""
# Import modules to be used: sys and scapy
from scapy.all import *
import sys

# Program version
version = 1.0

# Set help message
help_message = """
TiO2 Minerals Consultants Pty Ltd.

Port Scanner {} Help:
Run this program by running "python port_scanner.py "destination ips delimited by commas" [optional_flags]" in the terminal/powershell in the containing folder.
Accepted IP formats are IPv4 dot notation addresses and domain names, including CIDR notation.

Requirements:
Python3 and scapy to be installed on all systems.
libpcap to be installed on Unix-like systems or equivalent on host system (e.g. Npcap on Windows).
Run as sudo on linux and recommended to have admin access on Windows.
Note: if running python doesn't work try running as python3.

Flags:
Port Scanner {} includes several flags or switches that can be toggled for use during operation.

[-h,--help]
Displays this help screen

[-v,--verbose]
Set program mode to verbose

[--version]
Print program version

Examples:
    python port_scanner.py "127.0.0.1" (Windows)
    sudo python3 port_scanner.py "www.google.com/30, 1.1.1.1/24" -v --version (Linux)
""".format(
    version, version
)

# Define initial states of switches
help_switch = False
closed_ports = False
open_ports = False
filtered_ports = False
error_ports = False
verbosity = 0

# Set destination ports to be scanned and associated port names
dports = [21, 22, 23, 25, 53, 80, 110, 135, 137, 138, 139, 443, 1433, 1434, 8080]
port_names = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "Windows RPC",
    137: "Windows NetBIOS over TCP",
    138: "Windows NetBIOS over TCP",
    139: "Windows NetBIOS over TCP",
    443: "HTTPS",
    1433: "Microsoft SQL Server",
    1434: "Microsoft SQL Server",
    8080: "HTTP Alternative",
}

# Receive program inputs from sys CLI
cmd_input = sys.argv

# Change switch states according to cmd_input
if "-h" in cmd_input or "--help" in cmd_input:
    help_switch = True
if "-v" in cmd_input or "--verbose" in cmd_input:
    verbosity = 1

# Print program version if true
if "--version" in cmd_input:
    print("Version {}".format(version))

# Print help info if program is run in the presence of a debugger (i.e. not from cmd/bash), help flag is true, or mising too many arguments then exit
if help_switch or (sys.gettrace() != None) or (len(cmd_input) < 2):
    print(help_message)
    i = input("Press any key to exit")
    sys.exit()

""" Check if arg with quotes in cmd input (contains IP or list of IPs) found, clean IP input, and set destination IPs """
# Above method broke for an unknown reason, but it seems CMD, Bash etc. automatically strip quotes. Idk how I made that work before. Thus, the new method:
# If the second argument of argv contains a dot (".") it shall be considered a host target (domain names and IPv4 addresses contain dots)
# Not the cleanest method but it's the one that works for now
try:
    if "." in str(sys.argv[1]):
        dips = list(sys.argv[1].replace(" ", "").split(","))
    else:
        raise Exception("Host addresses not found, quitting...")
except Exception as e:
    print(e)
    i = input("Press any key to exit")
    sys.exit()

# Find IPs with subnet masks and expand them into IP ranges
new_dips = []

for ip in dips:
    if "/" in ip:
        network_ips = Net(ip)
        for net_ip in network_ips:
            new_dips.append(net_ip)
    else:
        new_dips.append(ip)

dips = new_dips

# Define empty list to hold scan results
results = []

# Proceed with scan only if IPs list is not empty
if dips != None:
    # Print scanning notification to console
    print("Scanning...")

    # Disable scapy outputs if verbosity is off
    if verbosity == 0:
        # Save object sys.stdout to variable as backup
        old_stdout = sys.stdout
        # Replace sys.stdout with nonexistent object to prevent scapy outputs
        sys.stdout = open(os.devnull, "w")

    # Run port scan
    for ip in dips:
        # Append current IP address to use as header later
        results.append(ip)

        for port in dports:
            pac = IP(dst=ip) / TCP(sport=RandShort(), dport=port, flags="S")
            response = sr1(pac, timeout=1.0, retry=1, verbose=verbosity)

            # Configure outputs for port scan
            # If port response is none or none: filtered, packet likely dropped or host down
            if (response == None) or (response == "None: Filtered"):
                # If verbose, print real-time output and additional port outputs
                if verbosity == 1:
                    print(
                        "Port {} for host {} filtered.".format(
                            pac[TCP].dport, pac[IP].dst
                        )
                    )
                    results.append(port_names[pac[TCP].dport])

                # Append port filtered results to results
                results.append(
                    "Port {} for host {} filtered.".format(pac[TCP].dport, pac[IP].dst)
                )

                # Check if firewall/ACL/router block etc.
                if pac.haslayer(ICMP):
                    # If verbose, print real-time output and additional port outputs
                    if verbosity == 1:
                        print("Packet likely dropped by firewall/ACL/router etc.")

                    # Append notice into results
                    results.append(
                        "Packet likely dropped by firewall/ACL/router etc."
                    )
            # If port responds with SYN-ACK, port is open and receiving
            elif response[TCP].flags == "SA":
                # If verbose, print real-time output and additional port outputs
                if verbosity == 1:
                    print(
                        "Port {} for host {} open.".format(pac[TCP].dport, pac[IP].dst)
                    )
                    results.append(port_names[pac[TCP].dport])

                # Append port open results to results
                results.append(
                    "Port {} for host {} open.".format(pac[TCP].dport, pac[IP].dst)
                )
            # If port responds RST or RST-ACK, host is up but port closed
            elif (response[TCP].flags == "R") or (response[TCP].flags == "RA"):
                # If verbose, print real-time output and additional port outputs
                if verbosity == 1:
                    print(
                        "Port {} for host {} closed.".format(
                            pac[TCP].dport, pac[IP].dst
                        )
                    )
                    results.append(port_names[pac[TCP].dport])

                # Append port closed results to results
                results.append(
                    "Port {} for host {} closed.".format(pac[TCP].dport, pac[IP].dst)
                )
            # Catch-all error default method
            else:
                # If verbose, print real-time output
                if verbosity == 1:
                    print(
                        "Encountered error for port {} for host {}.".format(
                            pac[TCP].dport, pac[IP].dst
                        )
                    )
                    error_ports.append(port_names[pac[TCP].dport])

                # Append error to results
                results.append(
                    "Encountered error for port {} for host {}.".format(
                        pac[TCP].dport, pac[IP].dst
                    )
                )

        # Add line break to list
        results.append("")


    # Restore sys.stdout for our own outputs
    if (verbosity == 0) and (sys.stdout != old_stdout):
        sys.stdout = old_stdout

# Print scan results
for result in results:
    print(result)

# Set wait for input method before exiting so user has time to see output before closing program
i = input("Press any key to exit")
sys.exit()
