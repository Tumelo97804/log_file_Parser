import re
import win32evtlog #gives access to Windows Event Log API (from pywin32 package).
import win32con  #contains Windows constants (like error codes)
from pathlib import Path
from datetime import datetime
import csv              # For generating CSV reports


def get_Error_Logs(server="localhost", log_types=None):
    """
    Reads Windows Event Logs and returns a list of error events.
    """
    if log_types is None:
        log_types = ['System', 'Application', 'Security', 'Setup', 'Forwarded Events']

    error_logs = []

    for log_type in log_types:
        print(f"--- Searching for errors in '{log_type}' log ---")
        try:
            # Open a handle to the event log
            hand = win32evtlog.OpenEventLog(server, log_type)
            # Read flags:
            # EVENTLOG_BACKWARDS_READ: start from the most recent event
            # EVENTLOG_SEQUENTIAL_READ: read sequentially
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            events_read = 1  # Start with a non-zero number to enter the loop
            while events_read > 0:
                # Read a batch of events from the log
                events = win32evtlog.ReadEventLog(hand,flags,0)
                if not events:
                    break # stops if there are no more events
                events_read = len(events) # number of events reads

                for event in events:
                    # Check if the event type is an error
                    if event.EventType == win32con.EVENTLOG_ERROR_TYPE:
                        # Add event details to the list as a dictionary
                        error_logs.append({
                            "LogType": log_type,
                            "EventID": event.EventID,
                            "Source": event.SourceName,
                            "Time": event.TimeGenerated.Format(),
                            "Message": " ".join(event.StringInserts) if event.StringInserts else ""
                        })

        except Exception as e:
            print(f"Could not read '{log_type}' log. Error: {e}")
        finally:
            # Always close the log handle to free resources
            if 'hand' in locals():

                win32evtlog.CloseEventLog(hand)

    return error_logs



def generate_report(error_logs, report_file="error_file.csv"):
    """
    Writes the error logs into a CSV report.
    """
    #prints message if there is no errors in event logs
    if not error_logs:
        print("No errors found in the Event Logs.")
        return

    try:
        with open(report_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["LogType", "EventID", "Source", "Time", "Message"])
            writer.writeheader()
            writer.writerows(error_logs)

        print(f"CSV report generated: {Path(report_file).resolve()}")

    except Exception as e:
        # Handle any error that occurs while creating the CSV
        print(f"Failed to generate report: {e}")

if __name__ == "__main__":
    logs = get_Error_Logs(server="localhost", log_types=["System", "Application"])
    generate_report(logs, report_file=r"C:\Users\DS4Y Cohort 4\Desktop\logs\error_file.csv")