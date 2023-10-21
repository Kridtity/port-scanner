# port-scanner

Simple port scanner built using the Python scapy module as part of a TAFE assessment (ICTPRG435 AT2)

# Help Information

TiO2 Minerals Consultants Pty Ltd.

## Port Scanner 1.0 Help:

Run this program by running "python port_scanner.py "destination_ips" [optional_flags]" in the terminal/powershell in the containing folder.

Accepted IP formats are IPv4 dot notation addresses and domain names, including CIDR notation.

## Requirements:

libpcap to be installed on Unix-like systems or equivalent on host system (e.g. Npcap on Windows).

## Flags:

Port Scanner 1.0 includes several flags or switches that can be toggled for use during operation.

`[-h,--help]`
Displays the help screen

`[-v,--verbose]`
Set program mode to verbose

`[--version]`
Print program version

`[-c,--closed]`
Output closed ports

`[-o,--open]`
Output open ports

`[-f,--filtered]`
Output filtered ports

`[-e,--error]`
Output ports encountering errors

Examples:

`python port_scanner.py "127.0.0.1" -o`

`python port_scanner.py "www.google.com/30, 1.1.1.1/24" -v -o -f --version`
