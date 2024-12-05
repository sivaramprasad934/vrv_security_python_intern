Log Analysis Script Description
The submitted Python script is a comprehensive solution for analyzing server log files. It fulfills the requirements of the assignment by providing key insights such as request counts per IP address, identifying the most frequently accessed endpoint, and detecting suspicious login activity. Below is a detailed description of its functionality:

Core Functionalities
Count Requests Per IP Address:

The script parses the log file to extract IP addresses using regex and tracks the number of requests made by each IP.
The results are sorted in descending order and displayed in a tabular format in the terminal.
Identify Most Frequently Accessed Endpoint:

The script extracts all endpoints (URLs) accessed in the log file and counts their occurrences.
The most accessed endpoint and its access count are identified and displayed in a user-friendly format.
Detect Suspicious Activity:

The script detects failed login attempts by identifying log entries with HTTP status code 401 for the /login endpoint.
IPs exceeding a configurable threshold of failed login attempts (default: 10) are flagged as suspicious, and their failed login counts are displayed.
Save Results to CSV:

The analysis results are saved in a CSV file named log_analysis.csv, organized into three sections:
Requests per IP: IP addresses and their respective request counts.
Most Accessed Endpoint: The top endpoint and its access count.
Suspicious IPs: Flagged IPs and their failed login counts.
Technical Details
File Handling:
The log file is read line by line for efficient processing.
Regex Matching:
Patterns are used to extract IP addresses, endpoints, and failed login attempts from log entries.
Data Structures:
Counter from the collections module is used to count occurrences of IPs and endpoints.
defaultdict is used to track failed login attempts per IP.
Output:
Results are printed in a clear format in the terminal and saved in the CSV file for further review or sharing.
Script Structure
log_parser:

The main function orchestrating the log analysis process.
Calls helper functions for processing, displaying, and saving results.
display_results:

Handles terminal output, formatting data for easy interpretation.
export_to_csv:

Saves the analysis results to a structured CSV file with proper headings.
Highlights
Customizable Threshold: The script allows users to configure the failed login attempt threshold for suspicious activity detection.
Modularity: Functions are well-structured and independent, ensuring maintainability and readability.
Scalability: The script can handle large log files efficiently due to its use of optimized data structures and regex parsing.
