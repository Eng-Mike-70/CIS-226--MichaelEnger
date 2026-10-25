# My First Cybersecurity Python Script
# CIS 226 - Programming for Cybersecurity

# Import libraries to retrieve system information
import socket
import platform
from datetime import datetime


# Function 1: Display the welcome message
def welcome():
    print("=" * 45)
    print("    HELLO, CYBERSECURITY!")
    print("=" * 45)

    name = input("What is your name? ")

    # Variable containing the course name
    course_name = "CIS 226 - Programming for Cybersecurity"

    # Display the welcome message and fictional company name
    print(f"\nWelcome to CyberShield Solutions, {name}!")
    print("Your course is:", course_name)


# Function 2: Display system information
def system_information():
    print("\n--- SYSTEM INFORMATION ---")

    hostname = socket.gethostname()
    operating_system = platform.system()
    os_version = platform.release()
    current_time = datetime.now()

    print("Computer Name:", hostname)
    print("Operating System:", operating_system)
    print("OS Version:", os_version)
    print("Current Date/Time:", current_time)


# Function 3: Basic password length check
def password_checker():
    print("\n--- PASSWORD SECURITY CHECK ---")
    print("Use a fictional test password only.")

    password = input("Enter a test password: ")

    if len(password) >= 14:
        print("PASS: Password meets the 14-character lab rule.")
    else:
        print("WARNING: Password is shorter than 14 characters.")


# Main program
def main():
    welcome()
    system_information()
    password_checker()

    print("\nCybersecurity check completed!")
    print("Thank you for using Python.")


# Run the main program
if __name__ == "__main__":
    main()

