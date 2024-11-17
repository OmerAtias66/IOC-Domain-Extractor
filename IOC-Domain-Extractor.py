# =============================================================================
# IOC Domain Extractor Script
# Developed by: Omer Atias, SecOps Engineer
# Purpose: Extracts domain indicators of compromise (IOCs) from publicly available
#          threat intelligence feeds or other sources.
# =============================================================================

import requests
import re
import os
import csv
import json
from urllib.parse import urlparse


def get_user_input():
    """Get filename and path from user"""
    while True:
        fname = input("Enter CSV filename (e.g., domains.csv): ").strip()
        if not fname:
            print("Filename cannot be empty")
            continue
        if not fname.endswith('.csv'):
            fname += '.csv'

        fpath = input("Enter path to save the file (e.g., Documents/IOCs): ").strip()
        if not fpath:
            print("Path cannot be empty")
            continue

        # Remove leading/trailing slashes
        fpath = fpath.strip('/')

        # Create full path for validation
        full_path = os.path.join(os.path.expanduser('~'), fpath)

        try:
            # Create directory if it doesn't exist
            os.makedirs(full_path, exist_ok=True)
            # Test if we can write to this location
            test_file = os.path.join(full_path, "test.txt")
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
            return fname, fpath
        except Exception as e:
            print(f"Error with the specified path: {e}")
            print("Please try again")


# URLs for IOC (Indicator of Compromise) Databases
urls = {
    "csv": 'https://urlabuse.com/public/data/data_csv.txt',
    "json": 'https://urlabuse.com/public/data/data.json',
    "malware": 'https://urlabuse.com/public/data/malware_url.txt',
    "phishing": 'https://urlabuse.com/public/data/phishing_url.txt',
    "hacked": 'https://urlabuse.com/public/data/hacked_url.txt',
    "dumps": 'https://urlabuse.com/public/data/dumps'
}


def is_valid_domain(domain):
    """
    Check if a string is a valid domain name.
    Returns False for numbers, dump files, and invalid domains.
    """
    if not domain:
        return False

    # Check if the string is just numbers
    if domain.replace('.', '').isdigit():
        return False

    # Check for dump files and other invalid patterns
    invalid_patterns = [
        r'dumps_\d{4}-\d{2}-\d{2}',  # dumps_YYYY-MM-DD
        r'<a href=',  # HTML links
        r'\.gz$',  # .gz files
        r'^[0-9\s]+$',  # Just numbers and spaces
        r'^$'  # Empty strings
    ]

    for pattern in invalid_patterns:
        if re.search(pattern, domain):
            return False

    # Check for valid domain pattern
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    return bool(re.match(domain_pattern, domain))


def extract_domain_from_url(url):
    """Extract clean domain from URL"""
    try:
        # Remove any protocol specification if exists
        if not url.startswith('http'):
            url = 'http://' + url.strip()
        parsed = urlparse(url)
        # Get domain without 'www.' if exists
        domain = parsed.netloc.replace('www.', '')

        # Verify it's a valid domain
        if is_valid_domain(domain):
            return domain
        return None
    except Exception:
        return None


def extract_domains(url, data_format="text"):
    domains = set()  # Use a set to avoid duplicates

    try:
        response = requests.get(url)
        if response.status_code == 200:
            if data_format == "csv":
                # Handle CSV data from data_csv.txt
                content = response.text.splitlines()
                for line in content:
                    if line:
                        try:
                            # Split by comma and get the URL field
                            fields = line.split(',')
                            if len(fields) > 0:
                                url_field = fields[0].strip()
                                # Extract and validate domain
                                domain = extract_domain_from_url(url_field)
                                if domain and is_valid_domain(domain):
                                    domains.add(domain)
                        except Exception:
                            continue  # Skip problematic lines

            elif data_format == "json":
                # Handle JSON data
                content = response.json()
                for item in content:
                    if 'url' in item:
                        domain = extract_domain_from_url(item['url'])
                        if domain and is_valid_domain(domain):
                            domains.add(domain)

            elif data_format == "text":
                # Handle plain text data (URL list)
                content = response.text.splitlines()
                for line in content:
                    if line:
                        domain = extract_domain_from_url(line)
                        if domain and is_valid_domain(domain):
                            domains.add(domain)

        else:
            print(f"Failed to fetch data from {url}. Status Code: {response.status_code}")

    except Exception as e:
        print(f"Error fetching data from {url}: {e}")

    return domains


def gather_all_domains():
    """Gather domains from all sources"""
    all_domains = set()
    total_domains = 0

    # Fetch data from all URLs with progress indicators
    for source, url in urls.items():
        print(f"\nFetching domains from {source}...")
        current_domains = extract_domains(url, data_format="csv" if source == "csv" else
        "json" if source == "json" else "text")
        print(f"Found {len(current_domains)} valid domains")
        all_domains.update(current_domains)
        total_domains += len(current_domains)

    print(f"\nTotal domains found: {total_domains}")
    print(f"Unique domains: {len(all_domains)}")
    return all_domains


def write_to_csv(domains, filename, filepath):
    """Write domains to CSV file"""
    full_path = os.path.join(os.path.expanduser('~'), filepath)
    file_path = os.path.join(full_path, filename)

    print(f"\nSaving file to: {file_path}")

    try:
        # Create directory if it doesn't exist
        os.makedirs(full_path, exist_ok=True)

        # Write domains to CSV
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["Domain"])  # Header
            for domain in sorted(domains):
                writer.writerow([domain])

        print(f"\nFile {filename} has been created successfully")
        print(f"Total unique domains saved: {len(domains)}")
        print(f"File location: {file_path}")

    except Exception as e:
        print(f"Error saving the file: {e}")


def main():
    """Main function"""
    print("Welcome to the Domain Collection Tool\n")

    # Get user input for file name and path
    fname, fpath = get_user_input()

    print("\nStarting domain collection...")
    unique_domains = gather_all_domains()

    # Write results to CSV
    write_to_csv(unique_domains, fname, fpath)


if __name__ == "__main__":
    main()