# Port-Scanner
Save this script as port_scanner.py. 

You can run it from the command line, specifying the target IP address or range and optional ports to scan. 

For example:
> python port_scanner.py 192.168.1.1/24 -p 80 443 8080 -o scan_results.json -f json
or
> python port_scanner.py 192.168.1.1/24 -p 80 443 8080 -o scan_results.txt -f txt

This will scan ports 80, 443, and 8080 on the target IP address 192.168.1.1. 

You can also specify an IP range using CIDR notation, like 192.168.1.0/24, to scan multiple hosts.

Features:
> Multithreading: multithreading to scan multiple hosts or ports concurrently, which can significantly speed up the scanning process, especially for large network ranges.
> Timeout Handling: more robust timeout handling to handle cases where connections take longer than expected or timeout unexpectedly.
> Service Identification: enhanced service identification by adding more detailed banner parsing or integrating with external service identification databases like nmap's service detection.
> Output Options: added options to save scan results to a file in various formats (e.g., CSV, JSON) for further analysis or reporting.
> IP Address Validation: validate the input IP address or range to ensure it's in a valid format before initiating the scan.
