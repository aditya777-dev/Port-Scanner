# Import necessary modules
import sys
import socket
import argparse
import json
import threading
from scapy.all import *

# Function to scan a single port
def scan_port(target_ip, port, result_dict):
    try:
        # Create a TCP socket and set a longer timeout
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        # Connect to the target IP and port
        result = sock.connect_ex((target_ip, port))
        # Check the connection result
        if result == 0:
            result_dict[port] = "open"  # Port is open
        else:
            result_dict[port] = "closed"  # Port is closed
        sock.close()  # Close the socket
    except Exception as e:
        result_dict[port] = "error"  # An error occurred

# Function to scan ports on a target IP
def scan_target(target_ip, ports):
    try:
        print(f"Scanning target: {target_ip}")
        result_dict = {}  # Dictionary to store scan results
        threads = []  # List to store threads
        # Create a thread for each port to scan
        for port in ports:
            thread = threading.Thread(target=scan_port, args=(target_ip, port, result_dict))
            threads.append(thread)
            thread.start()
        # Wait for all threads to finish
        for thread in threads:
            thread.join()
        # Print scan results for the target IP
        print(f"Scan results for {target_ip}:")
        for port, status in result_dict.items():
            print(f"Port {port}: {status}")
    except KeyboardInterrupt:
        print("\nExiting program.")
        sys.exit(1)

# Function to grab banner from a port
def grab_banner(target_ip, port):
    try:
        # Create a TCP socket and set a timeout
        banner_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        banner_socket.settimeout(2)
        # Connect to the target IP and port
        banner_socket.connect((target_ip, port))
        # Send an HTTP request to grab the banner
        banner_socket.send(b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target_ip).encode("utf-8"))
        # Receive the banner response
        banner = banner_socket.recv(1024)
        # Decode and return the banner
        return banner.decode("utf-8")
    except Exception as e:
        return str(e)

# Function to save scan results to a file
def save_scan_results(results, output_file):
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)

# Main function
def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("target", help="Target IP address or range (e.g., 192.168.1.1 or 192.168.1.1/24)")
    parser.add_argument("-p", "--ports", nargs="+", type=int, help="Ports to scan (e.g., 80 443 8080)")
    parser.add_argument("-o", "--output", help="Output file to save scan results (JSON format)")
    args = parser.parse_args()

    target = args.target  # Target IP address or range
    ports = args.ports if args.ports else range(1, 65535)  # Ports to scan (default: all ports)

    if "/" in target:  # If target is an IP range
        targets = [str(ip) for ip in IP(target)]
        scan_results = {}  # Dictionary to store scan results
        threads = []  # List to store threads
        # Create a thread for each target IP
        for t in targets:
            thread = threading.Thread(target=scan_target, args=(t, ports))
            threads.append(thread)
            thread.start()
        # Wait for all threads to finish
        for thread in threads:
            thread.join()
    else:
        scan_target(target, ports)  # Scan single target IP

    if args.output:  # If output file is specified
        save_scan_results(scan_results, args.output)  # Save scan results to file

# Execute main function if the script is run directly
if __name__ == "__main__":
    main()
