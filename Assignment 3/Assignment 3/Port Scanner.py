# Cybersecurity Programming Assignment


import socket
# Scan a computer for open ports
def port_scanner(target, start_port, end_port):

    print("\n===================================")
    print("       NETWORK PORT SCANNER")
    print("===================================")

    print("Target:", target)
    print("Scanning ports", start_port, "through", end_port)
    print("-----------------------------------")

    open_ports = []

    # Check each port in the selected range
    for port in range(start_port, end_port + 1):

        # Create a socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set connection timeout
        sock.settimeout(0.5)

        # Attempt to connect to the port
        result = sock.connect_ex((target, port))

        # Check if the port is open
        if result == 0:
            print("Port", port, "- OPEN")
            open_ports.append(port)

        # Close the connection
        sock.close()

    # Display scan results
    print("-----------------------------------")
    print("SCAN COMPLETE")

    if len(open_ports) > 0:
        print("Open ports found:", open_ports)
    else:
        print("No open ports found.")

    print("Total open ports:", len(open_ports))
    print("===================================")


# Main program
print("Welcome to the Network Port Scanner!")

target = input("Enter IP address or hostname to scan: ")

start_port = int(input("Enter starting port number: "))
end_port = int(input("Enter ending port number: "))

# Validate port range
if 1 <= start_port <= end_port <= 65535:

    port_scanner(target, start_port, end_port)

else:
    print("Invalid port range. Enter ports between 1 and 65535.")