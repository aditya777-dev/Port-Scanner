import sys  # Import the sys module for system-specific parameters and functions
import socket  # Import the socket module for low-level networking interfaces
import argparse  # Import the argparse module for parsing command-line arguments
import json  # Import the json module for encoding and decoding JSON data
import threading  # Import the threading module for creating and managing threads
import ipaddress  # Import the ipaddress module for working with IP addresses and networks

from scapy.all import *  # Import all symbols from the scapy module

# Function to validate IP address
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)  # Attempt to create an IP address object
        return True  # Return True if IP address is valid
    except ValueError:
        return False  # Return False if IP address is invalid

# Function to validate IP address range
def validate_ip_range(ip_range):
    try:
        ipaddress.ip_network(ip_range, strict=False)  # Attempt to create an IP network object
        return True  # Return True if IP range is valid
    except ValueError:
        return False  # Return False if IP range is invalid

# Function to scan a single port
def scan_port(target_ip, port, result_dict):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
        sock.settimeout(2)  # Set a longer timeout
        result = sock.connect_ex((target_ip, port))  # Attempt to connect to the target IP and port
        if result == 0:
            result_dict[port] = "open"  # Update result dictionary if port is open
            # Grab banner if port is open
            banner = grab_banner(target_ip, port)
            if banner:
                print(f"Banner for port {port}: {banner}")  # Print banner if available
        else:
            result_dict[port] = "closed"  # Update result dictionary if port is closed
        sock.close()  # Close the socket
    except Exception as e:
        result_dict[port] = "error"  # Update result dictionary if an error occurs

# Function to scan ports on a target IP
def scan_target(target_ip, ports):
    try:
        print(f"Scanning target: {target_ip}")  # Print target IP being scanned
        result_dict = {}  # Dictionary to store scan results
        threads = []  # List to store threads
        # Create a thread for each port to scan
        for port in ports:
            thread = threading.Thread(target=scan_port, args=(target_ip, port, result_dict))
            threads.append(thread)
            thread.start()  # Start the thread
        # Wait for all threads to finish
        for thread in threads:
            thread.join()
        # Print scan results for the target IP
        print(f"Scan results for {target_ip}:")
        for port, status in result_dict.items():
            print(f"Port {port}: {status}")  # Print port status
    except KeyboardInterrupt:
        print("\nExiting program.")  # Print message if program is interrupted
        sys.exit(1)  # Exit the program

# Function to grab banner from a port
def grab_banner(target_ip, port):
    try:
        banner_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
        banner_socket.settimeout(2)  # Set a timeout
        banner_socket.connect((target_ip, port))  # Connect to the target IP and port
        banner_socket.send(b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target_ip).encode("utf-8"))  # Send HTTP request
        banner = banner_socket.recv(1024)  # Receive banner
        return banner.decode("utf-8")  # Decode and return banner
    except Exception as e:
        return str(e)  # Return error message if an exception occurs

# Function to save scan results to a file
def save_scan_results(results, output_file, output_format):
    if output_format == "json":
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)  # Save results as JSON format
    elif output_format == "txt":
        with open(output_file, "w") as f:
            for port, status in results.items():
                f.write(f"Port {port}: {status}\n")  # Save results as text format
    else:
        print("Error: Unsupported output format.")  # Print error message if output format is not supported
        return

# Main function
def main():
    parser = argparse.ArgumentParser(description="Port Scanner")  # Create ArgumentParser object
    parser.add_argument("target", help="Target IP address or range (e.g., 192.168.1.1 or 192.168.1.1/24)")
    parser.add_argument("-p", "--ports", nargs="+", type=int, help="Ports to scan (e.g., 80 443 8080)")
    parser.add_argument("-o", "--output", help="Output file to save scan results")
    parser.add_argument("-f", "--format", choices=["json", "txt"], default="json", help="Output format (default: json)")
    args = parser.parse_args()  # Parse command-line arguments

    # Validate target IP address or range
    if not validate_ip(args.target) and not validate_ip_range(args.target):
        print("Error: Invalid IP address or range.")  # Print error message if target IP address or range is invalid
        sys.exit(1)  # Exit the program

    target = args.target  # Target IP address or range
    ports = args.ports if args.ports else range(1, 65535)  # Ports to scan (default: all ports)

    if "/" in target:  # If target is an IP range
        targets = [str(ip) for ip in ipaddress.IPv4Network(target)]  # Extract all IP addresses from the range
        scan_results = {}  # Dictionary to store scan results
        threads = []  # List to store threads
        # Create a thread for each target IP
        for t in targets:
            thread = threading.Thread(target=scan_target, args=(t, ports))
            threads.append(thread)
            thread.start()  # Start the thread
        # Wait for all threads to finish
        for thread in threads:
            thread.join()
    else:
        scan_target(target, ports)  # Scan single target IP

    if args.output:  # If output file is specified
        save_scan_results(scan_results, args.output, args.format)  # Save scan results to file

# Execute main function if the script is run directly
if __name__ == "__main__":
    main()
