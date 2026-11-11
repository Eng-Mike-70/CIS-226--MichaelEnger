import win32evtlog
import csv
from datetime import datetime


# Available Windows Event Logs
EVENT_LOGS = {
    "1": "Application",
    "2": "System",
    "3": "Security",
    "4": "Setup",
    "5": "Windows PowerShell"
}


# Convert Windows event severity into readable text
def get_severity(event_type):

    severity = {
        1: "Error",
        2: "Warning",
        4: "Information",
        8: "Audit Success",
        16: "Audit Failure"
    }

    return severity.get(event_type, "Unknown")


# Display menu
def display_menu():

    print("\n==============================================")
    print("          WINDOWS EVENT LOG ANALYZER")
    print("==============================================")

    print("\nSelect an event log to analyze:\n")

    for number, log_name in EVENT_LOGS.items():
        print(f"{number}. {log_name}")

    print("6. All Event Logs")

    print("==============================================")


# Read selected event log
def read_event_log(log_name):

    events = []

    print(f"\nAnalyzing {log_name} Log...")
    print("-" * 60)

    try:

        # Open Windows Event Log
        handle = win32evtlog.OpenEventLog(None, log_name)

        flags = (
            win32evtlog.EVENTLOG_SEQUENTIAL_READ |
            win32evtlog.EVENTLOG_FORWARDS_READ
        )

        while True:

            records = win32evtlog.ReadEventLog(
                handle,
                flags,
                0
            )

            # Stop when there are no more events
            if not records:
                break

            for event in records:

                event_data = {
                    "Log Name": log_name,
                    "Timestamp": str(event.TimeGenerated),
                    "Event ID": event.EventID & 0xFFFF,
                    "Source": event.SourceName,
                    "Severity": get_severity(event.EventType),
                    "Computer Name": event.ComputerName
                }

                events.append(event_data)

                # Display event information
                print("\nTimestamp:", event_data["Timestamp"])
                print("Event ID:", event_data["Event ID"])
                print("Source:", event_data["Source"])
                print("Severity:", event_data["Severity"])
                print("Computer Name:", event_data["Computer Name"])
                print("-" * 60)

        win32evtlog.CloseEventLog(handle)

        print(f"\nSuccessfully processed {log_name} Log.")
        print(f"Total events found: {len(events)}")

    except Exception as error:

        print(f"\nUnable to access {log_name} Log.")
        print("Error:", error)

        print("Continuing with the next event log...")

    return events


# Export results to CSV
def export_to_csv(events):

    if not events:
        print("\nNo events available to export.")
        return

    filename = (
        "Event_Log_Report_"
        + datetime.now().strftime("%Y%m%d_%H%M%S")
        + ".csv"
    )

    try:

        with open(filename, "w", newline="", encoding="utf-8") as file:

            fieldnames = [
                "Log Name",
                "Timestamp",
                "Event ID",
                "Source",
                "Severity",
                "Computer Name"
            ]

            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames
            )

            writer.writeheader()
            writer.writerows(events)

        print("\n==============================================")
        print("             EXPORT COMPLETE")
        print("==============================================")

        print("File saved as:", filename)
        print("Total records exported:", len(events))

    except Exception as error:

        print("\nError exporting CSV file:", error)


# Main program
def main():

    display_menu()

    choice = input("\nEnter your selection (1-6): ").strip()

    all_events = []

    # Process selected event log
    if choice in EVENT_LOGS:

        selected_log = EVENT_LOGS[choice]

        all_events.extend(read_event_log(selected_log))

    # Process all five event logs
    elif choice == "6":

        for log_name in EVENT_LOGS.values():

            all_events.extend(read_event_log(log_name))

    else:

        print("\nInvalid selection. Please choose 1-6.")
        return

    # Export collected events
    export_to_csv(all_events)

    print("\nEvent Log Analysis Complete!")


# Run program
if __name__ == "__main__":
    main()