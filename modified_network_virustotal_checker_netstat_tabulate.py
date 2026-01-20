import time
import re
import requests
import subprocess
import socket
import logging
from tabulate import tabulate

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

logging.info('Starting Network Virustotal Checker using netstat...')

def list_connections():
    logging.debug('Listing network connections using netstat command...')
    # Change from ss to netstat
    result = subprocess.run(['netstat', '-tun'], stdout=subprocess.PIPE)
    logging.debug('Network connections listed.')
    return result.stdout.decode()

def extract_ip_addresses(netstat_output):
    logging.debug('Extracting IP addresses from netstat output...')
    # Find all IP addresses in netstat output
    lines = netstat_output.splitlines()[2:]  # skip header
    ip_addresses = []
    for line in lines:
        fields = line.split()
        if len(fields) >= 5:
            local_addr, foreign_addr = fields[3], fields[4]
            foreign_ip = foreign_addr.split(':')[0]
            if foreign_ip not in ['127.0.0.1', '0.0.0.0']:
                ip_addresses.append(foreign_ip)
    found_ips = set(ip_addresses)
    logging.info(f'Extracted external IPs: {found_ips}')
    return found_ips


def resolve_domain_from_ip(ip_addresses):
    logging.debug('Resolving domain names for IP addresses...')
    domains = {}
    for ip in ip_addresses:
        if not ip or ip.isspace():
            continue  # Skip invalid IPs
        try:
            resolved_names = socket.gethostbyaddr(ip)
            if len(resolved_names) > 1:
                logging.warning(f'IP {ip} resolved to multiple addresses: {resolved_names}')
            
            main_hostname = resolved_names[0]
            aliases = resolved_names[1]
            domains[ip] = resolved_names[0]  # Use the first resolved name
            logging.debug(f'Domain resolved for {ip}: {domains[ip]}')
        except socket.herror:
            domains[ip] = None
            logging.warning(f'No domain resolved for {ip}')
    return domains

    logging.debug('Resolving domain names for IP addresses...')
    domains = {}
    for ip in ip_addresses:
        if not ip or ip.isspace():
            continue  # Skip invalid IPs
        try:
            domains[ip] = socket.gethostbyaddr(ip)[0]
            logging.debug(f'Domain resolved for {ip}: {domains[ip]}')
        except socket.herror:
            domains[ip] = None
            logging.warning(f'No domain resolved for {ip}')
    return domains

def virustotal_lookup(api_key, items):
    logging.debug('Performing VirusTotal Lookup...')
    url_ip = "https://www.virustotal.com/api/v3/ip_addresses/"
    url_domain = "https://www.virustotal.com/api/v3/domains/"
    headers = {"x-apikey": api_key}
    results = {}
    for item in items:
        domain = items[item]
        if domain:
            logging.debug(f'Looking up domain: {domain}')
            response = requests.get(url_domain + domain, headers=headers)
            if response.status_code == 200:
                data = response.json()
                votes = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                score = f'Malicious: {votes.get("malicious", 0)}, Harmless: {votes.get("harmless", 0)}'
            else:
                score = f'Error {response.status_code}'
            results[item] = score
        else:
            logging.debug(f'Looking up IP: {item}')
            response = requests.get(url_ip + item, headers=headers)
            if response.status_code == 200:
                data = response.json()
                votes = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                score = f'Malicious: {votes.get("malicious", 0)}, Harmless: {votes.get("harmless", 0)}'
            else:
                score = f'Error {response.status_code}'
            results[item] = score
    return results

def main(api_key):
    netstat_output = list_connections()
    external_ips = extract_ip_addresses(netstat_output)
    if not external_ips:
        logging.info("No external IP addresses found.")
        return
    resolved_domains = resolve_domain_from_ip(external_ips)
    external_ips = [ip for ip in external_ips if ip]  # Remove empty IPs
    results = virustotal_lookup(api_key, resolved_domains)
    time.sleep(5)  # Add a delay of 5 seconds between requests
    # Prepare data for tabular output
    table_data = [(ip, resolved_domains[ip] or '-', results.get(ip, 'Unknown')) for ip in external_ips]
    # Print table
    print(tabulate(table_data, headers=["Foreign Address", "Resolved Domain", "VirusTotal Scores"], tablefmt="grid"))

# Replace 'YOUR_API_KEY_HERE' with your actual VirusTotal API key
main('f5de8518c0d6a97c0c430b1cc274cf0e9d9746df86122db2f4d63ae0152034c1')

logging.info('Network Virustotal Checker using netstat completed.')
