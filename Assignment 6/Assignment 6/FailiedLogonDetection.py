import pandas as pd
import csv
import os
from datetime import timedelta


# ==========================================
# PROJECT 1: FAILED LOGON DETECTION
# ==========================================

print("=" * 60)
print("       FAILED LOGON DETECTION AND ACCOUNT TRIAGE")
print("=" * 60)


# ==========================================
# STEP 1: CONFIGURATION
# ==========================================

REQUIRED_COLUMNS = [
    "Timestamp",
    "EventID",
    "Account",
    "SourceIP",
    "Computer"
]

# Default detection settings

threshold = 5
time_window = 10

print("\nDetection Settings")
print("-" * 40)

try:
    threshold = int(input("Enter failed logon threshold (default 5): ") or 5)

    time_window = int(input("Enter time window in minutes (default 10): ") or 10)

    if threshold < 1 or time_window < 1:
        raise ValueError("Values must be greater than zero.")

except ValueError as error:
    print("Invalid settings:", error)
    print("Using default settings.")
    threshold = 5
    time_window = 10


# ==========================================
# STEP 2: LOAD CSV FILE
# ==========================================

print("\nLoading Authentication Log...")

script_folder = os.path.dirname(os.path.abspath(__file__))

filename = os.path.join(
    script_folder,
    "windows_authentication_1000_events.csv"
)

try:

    df = pd.read_csv(filename)

    print("CSV file loaded successfully.")

except Exception as error:

    print("Unable to load CSV file:", error)
    raise SystemExit


# ==========================================
# STEP 3: VALIDATE CSV FILE
# ==========================================

print("\nValidating CSV File...")
print("-" * 40)

missing_columns = [
    column for column in REQUIRED_COLUMNS
    if column not in df.columns
]

if missing_columns:

    print("ERROR: Required columns are missing:")
    print(missing_columns)

    raise SystemExit

if df.empty:

    print("ERROR: CSV file contains no records.")
    raise SystemExit

# Convert timestamps

df["Timestamp"] = pd.to_datetime(
    df["Timestamp"],
    errors="coerce"
)

# Validate timestamps

if df["Timestamp"].isna().any():

    print("ERROR: Invalid or missing timestamps detected.")
    raise SystemExit

# Validate Event IDs

df["EventID"] = pd.to_numeric(
    df["EventID"],
    errors="coerce"
)

if df["EventID"].isna().any():

    print("ERROR: Invalid Event IDs detected.")
    raise SystemExit

if not df["EventID"].isin([4624, 4625, 4634]).all():

    print("ERROR: Unexpected Event IDs detected.")
    raise SystemExit

# Validate required values

for column in ["Account", "SourceIP", "Computer"]:

    if df[column].isna().any() or (
        df[column].astype(str).str.strip() == ""
    ).any():

        print("ERROR: Missing values detected in", column)
        raise SystemExit

print("CSV validation successful.")

print("Total Records:", len(df))


# ==========================================
# STEP 4: FILTER EVENT TYPES
# ==========================================

print("\nAnalyzing Authentication Events...")
print("-" * 40)

successful_logons = df[df["EventID"] == 4624]

failed_logons = df[df["EventID"] == 4625]

logoffs = df[df["EventID"] == 4634]

print("Successful Logons:", len(successful_logons))

print("Failed Logons:", len(failed_logons))

print("Logoffs:", len(logoffs))


# ==========================================
# STEP 5: DETECT REPEATED FAILED LOGONS
# ==========================================

print("\nSearching for Repeated Failed Logons...")
print("-" * 40)

failed_logons = failed_logons.sort_values("Timestamp")

review_records = []

# Group failures by account and source IP

grouped = failed_logons.groupby(
    ["Account", "SourceIP"]
)

for (account, source_ip), group in grouped:

    group = group.sort_values("Timestamp").reset_index(drop=True)

    timestamps = group["Timestamp"].tolist()

    flagged_rows = {}

    # Sliding time window

    for start in range(len(group)):

        window_end = timestamps[start] + timedelta(
            minutes=time_window
        )

        matching_rows = [
            index
            for index in range(start, len(group))
            if timestamps[index] <= window_end
        ]

        failure_count = len(matching_rows)

        # Check whether threshold is reached

        if failure_count >= threshold:

            for index in matching_rows:

                if index not in flagged_rows:

                    flagged_rows[index] = {
                        "Window Start": timestamps[start],
                        "Window End": window_end,
                        "Failure Count": failure_count
                    }

                elif failure_count > flagged_rows[index]["Failure Count"]:

                    flagged_rows[index] = {
                        "Window Start": timestamps[start],
                        "Window End": window_end,
                        "Failure Count": failure_count
                    }

    # Add flagged events to review queue

    for index, details in flagged_rows.items():

        review_records.append({

            "Timestamp": group.loc[index, "Timestamp"],

            "EventID": 4625,

            "Account": account,

            "SourceIP": source_ip,

            "Computer": group.loc[index, "Computer"],

            "Window Start": details["Window Start"],

            "Window End": details["Window End"],

            "Failure Count": details["Failure Count"],

            "Analyst Interpretation":
                "Repeated failed logons meet the configured "
                "threshold. Further investigation recommended.",

            "Status": "Requires Review"

        })


# Create review queue

review_queue = pd.DataFrame(review_records)

print("Repeated Failure Events Identified:", len(review_queue))


# ==========================================
# STEP 6: MANAGEMENT SUMMARY
# ==========================================

print("\nGenerating Management Summary...")
print("-" * 40)

summary = pd.DataFrame([{

    "Total Events Analyzed": len(df),

    "Successful Logons": len(successful_logons),

    "Failed Logons": len(failed_logons),

    "Logoffs": len(logoffs),

    "Failed Logon Threshold": threshold,

    "Time Window Minutes": time_window,

    "Flagged Failure Events": len(review_queue),

    "Accounts Requiring Review":
        review_queue["Account"].nunique()
        if not review_queue.empty else 0,

    "Source IPs Requiring Review":
        review_queue["SourceIP"].nunique()
        if not review_queue.empty else 0,

    "Analyst Assessment":
        "Review required; no malicious activity determined."

}])


print(summary.to_string(index=False))


# ==========================================
# STEP 7: INDEPENDENT VERIFICATION
# ==========================================

print("\nIndependent Verification")
print("-" * 40)

# Read original CSV using Python's built-in CSV module.
# This provides a separate method from Pandas.

with open(filename, "r", newline="", encoding="utf-8-sig") as file:

    reader = csv.DictReader(file)

    independent_rows = list(reader)


# Compare first five source records

print("\nComparing First Five Source Records:")

verification_passed = True

for index in range(min(5, len(df))):

    pandas_record = df.iloc[index]

    csv_record = independent_rows[index]

    pandas_timestamp = pandas_record["Timestamp"].strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    csv_timestamp = pd.to_datetime(
        csv_record["Timestamp"]
    ).strftime("%Y-%m-%d %H:%M:%S")

    match = (

        pandas_timestamp == csv_timestamp

        and int(pandas_record["EventID"]) ==
        int(csv_record["EventID"])

        and str(pandas_record["Account"]) ==
        csv_record["Account"]

        and str(pandas_record["SourceIP"]) ==
        csv_record["SourceIP"]

    )

    print(
        f"Row {index + 1}: "
        f"{'PASS' if match else 'FAIL'}"
    )

    if not match:
        verification_passed = False


# Independently count Event IDs

independent_counts = {

    event_id: sum(
        int(row["EventID"]) == event_id
        for row in independent_rows
    )

    for event_id in [4624, 4625, 4634]

}


# Compare aggregate counts

print("\nComparing Aggregate Event Counts:")

for event_id, pandas_count in {

    4624: len(successful_logons),

    4625: len(failed_logons),

    4634: len(logoffs)

}.items():

    independent_count = independent_counts[event_id]

    match = pandas_count == independent_count

    print(
        f"Event {event_id}: "
        f"Pandas={pandas_count}, "
        f"Independent={independent_count}, "
        f"{'PASS' if match else 'FAIL'}"
    )

    if not match:
        verification_passed = False


print("\nOverall Verification:",
      "PASSED" if verification_passed else "FAILED")


if not verification_passed:

    print("WARNING: Verification discrepancies detected.")


# ==========================================
# STEP 8: EXPORT RESULTS
# ==========================================

print("\nExporting Results...")
print("-" * 40)

summary_file = os.path.join(
    script_folder,
    "Management_Summary.csv"
)

queue_file = os.path.join(
    script_folder,
    "Detailed_Review_Queue.csv"
)

# Export management summary

summary.to_csv(
    summary_file,
    index=False
)

# Export detailed review queue

review_queue.to_csv(
    queue_file,
    index=False
)

print("Management Summary:", summary_file)

print("Detailed Review Queue:", queue_file)


# ==========================================
# PROGRAM COMPLETE
# ==========================================

print("\n" + "=" * 60)

print("FAILED LOGON ANALYSIS COMPLETE")

print("=" * 60)

print("\nRemember:")
print("Flagged events require analyst investigation.")
print("A flagged account or IP is NOT automatically malicious.")
