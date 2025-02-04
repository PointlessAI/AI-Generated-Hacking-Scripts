#!/usr/bin/env python3

import argparse
import logging
import subprocess
import ipaddress
import os
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

# Initialize OpenAI client with the API key from environment variables
client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY"),
)

# ----------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------
# Default timeouts (in seconds) for various commands.
TIMEOUT_SHORT = 5
TIMEOUT_MEDIUM = 10
TIMEOUT_LONG = 30
TIMEOUT_VERY_LONG = 60

# ----------------------------------------------------
# LOGGING SETUP
# ----------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ----------------------------------------------------
# HELPER FUNCTIONS
# ----------------------------------------------------
def run_command(command, timeout=TIMEOUT_SHORT):
    """
    Runs a shell command with a configurable timeout.
    Logs and returns the STDOUT on success.
    On error or timeout, returns an error string.
    """
    logging.debug(f"Executing command: {command} (timeout={timeout}s)")
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        # If the command returned a non-zero code, handle it
        if result.returncode != 0:
            err = result.stderr.strip()
            if not err:
                err = "Unknown error or no stderr."
            logging.error(f"Command '{command}' failed with return code {result.returncode}: {err}")
            return f"Error: {err}"
        
        # Log any stderr output, even if return code was 0
        if result.stderr.strip():
            logging.warning(f"Command produced stderr: {result.stderr.strip()}")
        return result.stdout.strip()

    except subprocess.TimeoutExpired:
        msg = f"Error: Command timed out after {timeout}s"
        logging.error(msg)
        return msg
    except Exception as e:
        msg = f"Error: {str(e)}"
        logging.error(msg)
        return msg


def whois_lookup(target):
    # Whois can hang; use a medium timeout
    return run_command(f"whois {target}", timeout=TIMEOUT_MEDIUM)


def is_behind_aws_or_cloudflare(target):
    """
    Uses whois output to determine if a domain or IP
    is hosted behind AWS or Cloudflare. If so,
    returns True; otherwise False.
    """
    logging.info(f"Checking if {target} is behind AWS or Cloudflare...")
    w = whois_lookup(target)
    w_lower = w.lower()
    # Simple heuristic checks
    if "amazon" in w_lower or "aws" in w_lower or "cloudflare" in w_lower:
        logging.info(f"Detected AWS/Cloudflare references in WHOIS for {target}.")
        return True
    return False


# ----------------------------------------------------
# DOMAIN SCANS
# ----------------------------------------------------
def attempt_zone_transfer(domain, timeout=TIMEOUT_SHORT):
    """
    Attempt a DNS zone transfer for the domain by querying its
    authoritative nameservers. Returns the consolidated result.
    Applies a short timeout to each dig attempt.
    """
    results = []

    logging.info(f"Attempting to retrieve nameservers for zone transfer of {domain}...")
    ns_output = run_command(f"dig NS {domain} +short", timeout=timeout)
    if "Error:" in ns_output:
        return ns_output  # Contains the error message

    nameservers = ns_output.splitlines()
    if not nameservers:
        return "No NS records found or unable to retrieve NS."

    for ns in nameservers:
        ns = ns.strip()
        if not ns:
            continue
        logging.info(f"Trying zone transfer from NS: {ns}")
        zone_result = run_command(f"dig axfr {domain} @{ns}", timeout=timeout)
        zr_lower = zone_result.lower()
        if any(err in zr_lower for err in ["transfer failed", "failed", "denied"]) or "xfr size" not in zr_lower:
            results.append(f"Zone transfer from {ns} failed or returned no data.")
        else:
            results.append(f"Zone transfer successful from {ns}:\n{zone_result}")

    return "\n\n".join(results).strip()


def domain_info(domain):
    """
    Gather domain-related information with timeouts and minimal scanning.
    """
    logging.info(f"Gathering domain info for {domain}...")

    # Check if domain is behind AWS or Cloudflare
    behind_aws_or_cf = is_behind_aws_or_cloudflare(domain)

    results = {
        "whois": whois_lookup(domain),
        "nslookup": run_command(f"nslookup {domain}", timeout=TIMEOUT_SHORT),
        "host": run_command(f"host {domain}", timeout=TIMEOUT_SHORT),
        "dig_any": run_command(f"dig ANY {domain}", timeout=TIMEOUT_SHORT),
        "dig_ns": run_command(f"dig {domain} NS", timeout=TIMEOUT_SHORT),
        "dig_mx": run_command(f"dig {domain} MX", timeout=TIMEOUT_SHORT),
        "dig_txt": run_command(f"dig {domain} TXT", timeout=TIMEOUT_SHORT),
    }

    # Skip zone transfer if behind AWS or Cloudflare (almost always blocked)
    if behind_aws_or_cf:
        results["zone_transfer"] = "Skipped - Domain behind AWS/Cloudflare"
    else:
        results["zone_transfer"] = attempt_zone_transfer(domain)

    # traceroute can sometimes hang longer, give it a bit more time
    results["traceroute"] = run_command(f"traceroute {domain}", timeout=TIMEOUT_MEDIUM)

    # Basic nmap. Keep the port range limited for quicker runs
    results["nmap"] = run_command(f"nmap -Pn -p 1-1000 {domain}", timeout=TIMEOUT_LONG)

    # Check basic headers with a short timeout
    results["curl_headers"] = run_command(f"curl -I https://{domain}", timeout=TIMEOUT_SHORT)

    return results


# ----------------------------------------------------
# IP SCANS
# ----------------------------------------------------
def network_info(ip):
    """
    Gather network-related information for an IP. Minimal scans to reduce hang risk.
    """
    logging.info(f"Gathering network info for {ip}...")

    # Attempt to parse the IP for potential /24. (We won't do a big subnet scan here.)
    try:
        ipaddress.ip_address(ip)  # Validate
    except ValueError:
        pass  # We'll just assume it's an IP we can handle

    # Check AWS/Cloudflare
    behind_aws_or_cf = is_behind_aws_or_cloudflare(ip)

    results = {
        "whois": whois_lookup(ip),
        "reverse_dns": run_command(f"dig -x {ip}", timeout=TIMEOUT_SHORT),
        "traceroute": run_command(f"traceroute {ip}", timeout=TIMEOUT_MEDIUM),
        "nmap_common_ports": run_command(f"nmap -Pn -p 22,80,443 {ip}", timeout=TIMEOUT_LONG),
        "curl_headers": run_command(f"curl -I https://{ip}", timeout=TIMEOUT_SHORT),
    }

    # If behind AWS/CF, skip attempts that are often blocked or moot.
    if behind_aws_or_cf:
        results["notes"] = "IP belongs to AWS or Cloudflare; skipping advanced scans."

    return results


def port_scan(ip):
    """
    Perform a more comprehensive port scan with short or medium timeouts.
    """
    logging.info(f"Performing port scans on {ip}...")
    results = {
        "basic_ping": run_command(f"ping -c 3 {ip}", timeout=TIMEOUT_SHORT),
        "basic_nmap": run_command(f"nmap -Pn {ip}", timeout=TIMEOUT_LONG),
        "common_ports": run_command(f"nmap -p 1-1000 {ip}", timeout=TIMEOUT_LONG),
        "full_ports": run_command(f"nmap -p- {ip}", timeout=TIMEOUT_VERY_LONG),
        "service_detection": run_command(f"nmap -sV {ip}", timeout=TIMEOUT_LONG),
        "os_detection": run_command(f"nmap -O {ip}", timeout=TIMEOUT_LONG),
    }
    return results


# ----------------------------------------------------
# CHATGPT REQUESTS
# ----------------------------------------------------
def chatgpt_request(scan_results):
    """
    Sends the user's content to OpenAI Chat API in the required messages format.
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4",  # or "gpt-3.5-turbo"
            messages=[{"role": "system", "content": "Produce a detailed red team network recon report based on the provided output."},{"role": "user", "content": scan_results}]
        )
        return response.choices[0].message.content
    except Exception as e:
        logging.error(f"OpenAI API request failed: {str(e)}")
        return f"Error from OpenAI API: {str(e)}"


# ----------------------------------------------------
# SAVING RESULTS
# ----------------------------------------------------
def save_results(target, results):
    """
    Save the scan results to a file, then generate and save AI-processed results.
    """
    filename = f"scan_results_{target}.txt"
    ai_filename = f"ai_scan_results_{target}.md"

    logging.info(f"Saving results to {filename}...")

    try:
        # Write raw scan results to filename
        with open(filename, "w", encoding="utf-8") as f:
            for section, output in results.items():
                f.write(f"\n[{section.upper()}]\n")
                f.write((output or "") + "\n" + "-" * 50 + "\n")

        # Read the saved results
        with open(filename, "r", encoding="utf-8") as f:
            file_content = f.read()

        # Process the file content using the ChatGPT request
        ai_proc_file = chatgpt_request(file_content)

        # Write AI-processed results to ai_filename
        with open(ai_filename, "w", encoding="utf-8") as f:
            f.write(ai_proc_file)

        logging.info(f"AI-processed results saved to {ai_filename}")

    except Exception as e:
        logging.error(f"Failed to save results to {filename}: {e}")


# ----------------------------------------------------
# MAIN
# ----------------------------------------------------
def main():
    logging.info("Starting the (Less Hanging) Comprehensive Scanner...")
    parser = argparse.ArgumentParser(description="Comprehensive Domain & Network Scanner (Reduced Hang Version)")
    parser.add_argument("target", help="Domain name or IP address to scan")
    args = parser.parse_args()

    target = args.target
    results = {}

    # Simple heuristic: if the target has any alphabetic character, assume domain
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