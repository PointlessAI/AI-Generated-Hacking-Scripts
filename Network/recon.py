#!/usr/bin/env python3

import os
import subprocess
import argparse
import logging
import ipaddress

# Make sure Sublist3r is installed:
# pip install sublist3r
try:
    from sublist3r import Sublist3r
except ImportError:
    Sublist3r = None


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


def run_command(command):
    """
    Runs a shell command securely and logs its output and errors.
    Returns the command's STDOUT on success or a string with error details on failure.
    """
    logging.debug(f"Executing command: {command}")
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=True
        )
        # Log any stderr output
        if result.stderr.strip():
            logging.error(f"Command produced error output: {result.stderr.strip()}")
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{command}' failed with error:\n{e.stderr}")
        return f"Error: {e.stderr.strip()}"


def subdomain_enum(domain):
    """
    Use Sublist3r (a Python-based tool) to enumerate subdomains.
    Returns a string containing the discovered subdomains or an error message if Sublist3r not available.
    """
    if Sublist3r is None:
        return "Sublist3r not installed. Please install via 'pip install sublist3r'."
    try:
        logging.info(f"Enumerating subdomains for {domain} with Sublist3r...")
        subdomains = Sublist3r.main(domain, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False)
        return "\n".join(subdomains)
    except Exception as e:
        logging.error(f"Subdomain enumeration failed: {e}")
        return f"Error enumerating subdomains: {str(e)}"


def attempt_zone_transfer(domain):
    """
    Attempt a DNS zone transfer for the domain by querying each authoritative nameserver.
    Return the consolidated result of all zone transfer attempts.
    """
    results = []
    # First, get the nameservers
    logging.info(f"Attempting to retrieve nameservers for zone transfer of {domain}...")
    ns_output = run_command(f"dig NS {domain} +short")
    if "Error:" in ns_output:
        return ns_output  # Contains the error message

    nameservers = ns_output.splitlines()

    # Try AXFR from each NS
    for ns in nameservers:
        ns = ns.strip()
        if not ns:
            continue
        logging.info(f"Trying zone transfer from NS: {ns}")
        zone_result = run_command(f"dig axfr {domain} @{ns}")
        if "Transfer failed." in zone_result or "XFR size" not in zone_result:
            results.append(f"Zone transfer from {ns} failed or returned no data.")
        else:
            results.append(f"Zone transfer successful from {ns}:\n{zone_result}")

    return "\n\n".join(results)


def whois_lookup(target):
    return run_command(f"whois {target}")


def domain_info(domain):
    """
    Gather domain-related information.
    """
    logging.info(f"Gathering domain info for {domain}...")
    results = {
        "whois": whois_lookup(domain),
        "nslookup": run_command(f"nslookup {domain}"),
        "host": run_command(f"host {domain}"),
        "dig_any": run_command(f"dig ANY {domain}"),
        "dig_ns": run_command(f"dig {domain} NS"),
        "dig_mx": run_command(f"dig {domain} MX"),
        "dig_txt": run_command(f"dig {domain} TXT"),
        "zone_transfer": attempt_zone_transfer(domain),
        "traceroute": run_command(f"traceroute {domain}"),
        "nmap": run_command(f"nmap -Pn -p 1-1000 {domain}"),
        "curl_headers": run_command(f"curl -I https://{domain}"),
        "subdomain_enum": subdomain_enum(domain),
        # Additional network recon for a domain (web apps):
        "whatweb": run_command(f"whatweb {domain}"),
        "nikto_scan": run_command(f"nikto -host https://{domain}")
    }
    return results


def network_info(ip):
    """
    Gather network-related information for a given IP.
    Including a /24 subnet scan to show other live hosts.
    """
    logging.info(f"Gathering network info for {ip}...")

    # Attempt to build the /24 network for scanning
    # If 'ip' is already a single IP, we create the network (e.g., 192.168.1.0/24).
    # If ipaddress parsing fails, fallback to a direct approach or skip.
    try:
        address_obj = ipaddress.ip_address(ip)
        network_addr = ipaddress.ip_network(f"{address_obj}/24", strict=False)
        subnet = str(network_addr)
    except ValueError:
        # Fallback if the user didn't provide a plain IP or if there's an error
        # You might skip or do some naive string manipulation
        # For safety, let's skip the /24 if we can't parse properly
        subnet = ip  # fallback

    results = {
        "whois": whois_lookup(ip),
        # We can still keep fping, which is a good quick approach:
        "fping_subnet_scan": run_command(f"fping -a -g {subnet} 2>/dev/null"),
        # Alternatively, you can do an nmap ping scan:
        "nmap_subnet_scan": run_command(f"nmap -sn {subnet}"),
        "reverse_dns": run_command(f"dig -x {ip}"),
        "traceroute": run_command(f"traceroute {ip}"),
        "nmap_common_ports": run_command(f"nmap -Pn -p 22,80,443 {ip}"),
        "curl_headers": run_command(f"curl -I https://{ip}"),
    }
    return results


def port_scan(ip):
    """
    Perform a comprehensive port scan.
    """
    logging.info(f"Performing port scans on {ip}...")
    results = {
        "basic_ping": run_command(f"ping -c 3 {ip}"),
        "basic_nmap": run_command(f"nmap -Pn {ip}"),
        "common_ports": run_command(f"nmap -p 1-1000 {ip}"),
        "full_ports": run_command(f"nmap -p- {ip}"),
        "service_detection": run_command(f"nmap -sV {ip}"),
        "os_detection": run_command(f"nmap -O {ip}"),
        "banner_grabbing": run_command(f"nmap --script banner {ip}"),
        "vulnerability_scan": run_command(f"nmap --script vuln {ip}"),
    }
    return results


def save_results(target, results):
    """
    Save the scan results to a file.
    """
    filename = f"scan_results_{target}.txt"
    logging.info(f"Saving results to {filename}...")
    try:
        with open(filename, "w") as f:
            for section, output in results.items():
                f.write(f"\n[{section.upper()}]\n")
                f.write(output + "\n" + "-" * 50 + "\n")
        logging.info(f"Results saved to {filename}")
    except Exception as e:
        logging.error(f"Failed to save results to {filename}: {e}")


def main():
    logging.info("Starting the Comprehensive Domain & Network Scanner...")
    parser = argparse.ArgumentParser(description="Comprehensive Domain & Network Scanner")
    parser.add_argument("target", help="Domain name or IP address to scan")
    args = parser.parse_args()

    target = args.target
    results = {}

    # Simple heuristic: if the target has any alphabetic character, assume it's a domain.
    if any(c.isalpha() for c in target):
        logging.info(f"Target '{target}' appears to be a domain.")
        results = domain_info(target)
    else:
        logging.info(f"Target '{target}' appears to be an IP address.")
        # Perform network recon
        results.update(network_info(target))
        # Also do port scans
        results.update(port_scan(target))

    # Finally, save results to file
    save_results(target, results)
    logging.info("Scanning completed.")


if __name__ == "__main__":
    main()
