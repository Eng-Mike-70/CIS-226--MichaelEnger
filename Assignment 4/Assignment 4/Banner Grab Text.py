import socket
import ssl

# -----------------------------------------
# CYBERSECURITY BANNER GRABBER
# -----------------------------------------

print("=" * 50)
print("          CYBERSECURITY BANNER GRABBER")
print("=" * 50)

# Ask for target
target = input("\nEnter IP address or hostname: ")

# Ports to examine
ports = [21, 22, 25, 80, 110, 143, 443, 445,
         3306, 3389, 8080]

timeout = 3


# -----------------------------------------
# IDENTIFY SERVICES
# -----------------------------------------

services = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP Alternate"
}


# -----------------------------------------
# BANNER GRABBING FUNCTION
# -----------------------------------------

def grab_banner(target, port):

    try:

        # Establish connection
        sock = socket.create_connection(
            (target, port), timeout=timeout
        )

    except ConnectionRefusedError:

        return "CLOSED", "Connection refused."

    except socket.timeout:

        return "TIMEOUT", "Connection attempt timed out."

    except OSError as error:

        return "ERROR", str(error)

    # Connection was successful
    try:

        sock.settimeout(timeout)

        # SMB requires protocol negotiation
        if port == 445:

            return "OPEN", (
                "SMB service detected by port number. "
                "Protocol negotiation is required "
                "to retrieve server information."
            )

        # HTTPS requires TLS encryption
        if port == 443:

            context = ssl.create_default_context()

            sock = context.wrap_socket(
                sock, server_hostname=target
            )

        # HTTP and HTTPS require a request
        if port in [80, 443, 8080]:

            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Connection: close\r\n\r\n"
            )

            sock.sendall(request.encode())

        # Receive service information
        banner = sock.recv(1024)

        if banner:

            # MySQL may return binary data
            if port == 3306:

                return "OPEN", (
                    "MySQL handshake data (hex): "
                    + banner.hex()
                )

            return "OPEN", banner.decode(
                "utf-8", errors="replace"
            ).strip()

        else:

            return "OPEN", "No banner information received."

    except socket.timeout:

        return "OPEN", (
            "Connection successful, but the service "
            "did not return banner information."
        )

    except ssl.SSLError as error:

        return "OPEN", f"TLS negotiation error: {error}"

    except OSError as error:

        return "OPEN", f"Communication error: {error}"

    finally:

        sock.close()


# -----------------------------------------
# SCAN TARGET
# -----------------------------------------

print("\nTarget:", target)
print("\nStarting Banner Grab...\n")

for port in ports:

    service = services.get(port, "Unknown")

    status, banner = grab_banner(target, port)

    print("-" * 50)

    print(f"Port: {port}")
    print(f"Service: {service}")
    print(f"Status: {status}")

    if status == "OPEN":

        print("Banner Information:")
        print(banner)

    print()


# -----------------------------------------
# SCAN COMPLETE
# -----------------------------------------

print("=" * 50)
print("                 SCAN COMPLETE")
print("=" * 50)