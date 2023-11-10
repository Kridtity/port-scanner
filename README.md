# port-scanner

Simple port scanner built using the Python scapy module as part of a TAFE assessment (ICTPRG435 AT2)


# Help Information

TiO2 Minerals Consultants Pty Ltd.


## Port Scanner 1.0 Help:

Run this program by running "python port_scanner.py "destination_ips" [optional_flags]" in the terminal/powershell in the containing folder.

Accepted IP formats are IPv4 dot notation addresses and domain names, including CIDR notation.


## Requirements:

Python3 and scapy to be installed on all systems.

libpcap to be installed on Unix-like systems or equivalent on host system (e.g. Npcap on Windows).

Run as sudo on linux and recommended to have admin access on Windows.

Note: if running python doesn't work try running as python3.


## Flags:

Port Scanner 1.0 includes several flags or switches that can be toggled for use during operation.

`[-h,--help]`
Displays the help screen

`[-v,--verbose]`
Set program mode to verbose

`[--version]`
Print program version


Examples:

`python port_scanner.py "127.0.0.1" (Windows)`

`sudo python3 port_scanner.py "www.google.com/30, 1.1.1.1/24" -v --version (Linux)`
