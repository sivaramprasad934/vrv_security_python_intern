import re
import csv
from collections import defaultdict, Counter

def log_parser(log_path, login_fail_limit=10):
    """
    Parses a log file to analyze request counts, find popular endpoints,
    and detect potential suspicious activities.

    Parameters:
    - log_path: Path to the log file.
    - login_fail_limit: Maximum failed login attempts before flagging an IP.

    Outputs analysis to the terminal and saves results to a CSV file.
    """

    # Data storage for analysis
    ip_tracker = Counter()
    url_tracker = Counter()
    failed_logins = defaultdict(int)

    # Regex patterns to parse log data
    ip_regex = r"^(\d+\.\d+\.\d+\.\d+)"
    url_regex = r"\"(?:GET|POST) (/[^\s]*)"
    failed_login_regex = r"\"POST /login HTTP/1.1\" 401"

    # Process each log entry
    with open(log_path, "r") as logfile:
        for log_entry in logfile:
            # Capture IP address
            ip_match = re.match(ip_regex, log_entry)
            if ip_match:
                ip_address = ip_match.group(1)
                ip_tracker[ip_address] += 1

            # Capture endpoint (URL)
            url_match = re.search(url_regex, log_entry)
            if url_match:
                endpoint = url_match.group(1)
                url_tracker[endpoint] += 1

            # Check for failed logins
            if re.search(failed_login_regex, log_entry) and ip_match:
                failed_logins[ip_address] += 1

    # Identify the most accessed endpoint
    popular_url = url_tracker.most_common(1)
    top_url = popular_url[0] if popular_url else ("None", 0)

    # Filter flagged IPs for failed logins
    suspicious_ips = {ip: attempts for ip, attempts in failed_logins.items() if attempts > login_fail_limit}

    # Display analysis results
    display_results(ip_tracker, top_url, suspicious_ips)

    # Save results to a CSV file
    export_to_csv(ip_tracker, top_url, suspicious_ips)


def display_results(ip_tracker, top_url, flagged_ips):
    """
    Displays the analysis results in a user-friendly format in the terminal.

    Parameters:
    - ip_tracker: Counter object tracking requests per IP.
    - top_url: Tuple with the most accessed endpoint and its count.
    - flagged_ips: Dictionary of suspicious IPs with failed login attempts.
    """
    print("\nRequests Per IP Address:")
    print(f"{'IP Address':<20}{'Requests':<10}")
    for ip, count in ip_tracker.most_common():
        print(f"{ip:<20}{count:<10}")

    print("\nMost Accessed Endpoint:")
    print(f"{top_url[0]} (Accessed {top_url[1]} times)")

    print("\nSuspicious IP Addresses:")
    if flagged_ips:
        print(f"{'IP Address':<20}{'Failed Logins':<15}")
        for ip, count in flagged_ips.items():
            print(f"{ip:<20}{count:<15}")
    else:
        print("No suspicious activity detected.")


def export_to_csv(ip_tracker, top_url, flagged_ips):
    """
    Saves the analysis results to a CSV file.

    Parameters:
    - ip_tracker: Counter object tracking requests per IP.
    - top_url: Tuple with the most accessed endpoint and its count.
    - flagged_ips: Dictionary of suspicious IPs with failed login attempts.
    """
    with open("log_analysis.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)

        # Section 1: Requests Per IP
        writer.writerow(["Requests Per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_tracker.most_common():
            writer.writerow([ip, count])

        # Section 2: Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(top_url)

        # Section 3: Suspicious IPs
        writer.writerow([])
        writer.writerow(["Suspicious IP Addresses"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in flagged_ips.items():
            writer.writerow([ip, count])


# Main execution
if __name__ == "__main__":
    log_file_path = "sample.log"  # Replace with the actual path to the log file
    log_parser(log_file_path)
