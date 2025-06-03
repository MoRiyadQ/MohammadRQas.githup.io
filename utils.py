import subprocess
import platform
import xml.etree.ElementTree as ET
import json
import os
import shutil
import re
from docx import Document
from io import BytesIO
from docx.shared import Inches, RGBColor 
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from functools import wraps
from flask import abort 
from flask_login import current_user

# Set constants for wordlists
EXPLOIT_DB_PATH = "/usr/share/exploitdb/exploits/"
WORDLIST_PATH_GOBUSTER = "/usr/share/wordlists/dirb/big.txt"
WORDLIST_PATH_WFUZZ = "/usr/share/wordlists/seclists/Discovery/directory-list-2.3-big.txt"
WORDLIST_PATH_FFUF = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
WORDLIST_PATH_AMASS = "/usr/share/wordlists/seclists/Discovery/DNS/common-subdomains.txt"

def is_target_up(target):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, "2", target]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        print(f"Error checking target: {e}")
        return False

def run_nmap_scan(target):
    try:
        command = ["nmap", "-sS", "-sV", "-Pn", "-O", "-oX", "-", target]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError:
        return None

def parse_os(nmap_output):
    try:
        root = ET.fromstring(nmap_output)
        os_match = root.find(".//os/osmatch")
        return os_match.attrib.get("name", "Unknown OS").split()[0].lower() if os_match is not None else "unknown"
    except ET.ParseError:
        return "unknown"

def parse_nmap_services(nmap_output):
    services = []
    try:
        root = ET.fromstring(nmap_output)
        for host in root.findall(".//host"):
            for port in host.findall(".//port"):
                service = port.find(".//service")
                if service is not None:
                    name = service.attrib.get("name", "unknown")
                    version = service.attrib.get("version", "")
                    product = service.attrib.get("product", "")
                    extrainfo = service.attrib.get("extrainfo", "")
                    service_string = f"{product} {version} {extrainfo}".strip()
                    if service_string:
                        services.append((port.attrib.get("portid", "unknown"), service_string))
    except ET.ParseError:
        return []
    return services

def search_exploits(service, os_name):
    try:
        command = ["searchsploit", "--json", service]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout
        try:
            exploit_data = json.loads(output)
            filtered_exploits = []
            for exploit in exploit_data.get("RESULTS_EXPLOIT", []):
                exploit_path = exploit.get("Path", "").lower()
                if any(os_type in exploit_path for os_type in ["linux", "unix", "ubuntu"]):
                    filtered_exploits.append(exploit)
            return filtered_exploits
        except json.JSONDecodeError:
            return []
    except subprocess.CalledProcessError:
        return []

def execute_exploit(exploit_path, target):
    full_exploit_path = os.path.join(EXPLOIT_DB_PATH, exploit_path)
    if not os.path.exists(full_exploit_path):
        return

    exploit_copy = f"./{os.path.basename(exploit_path)}"
    shutil.copy(full_exploit_path, exploit_copy)
    os.chmod(exploit_copy, 0o755)

    if exploit_copy.endswith(".py"):
        command = ["python3", exploit_copy, target]
    elif exploit_copy.endswith(".pl"):
        command = ["perl", exploit_copy, target]
    elif exploit_copy.endswith(".sh"):
        command = ["bash", exploit_copy, target]
    elif exploit_copy.endswith(".c"):
        compile_cmd = ["gcc", exploit_copy, "-o", "compiled_exploit"]
        subprocess.run(compile_cmd, check=True)
        command = ["./compiled_exploit", target]
    else:
        return
    
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError:
        return

def run_vuln_scan(target):
    try:
        command = ["nmap", "-sV", "--script", "vulners", "-T4", target, "-oX", "-"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError:
        return None

def parse_vuln_scan(vuln_scan_output):
    cves = []
    try:
        root = ET.fromstring(vuln_scan_output)
        for host in root.findall(".//host"):
            for port in host.findall(".//port"):
                service = port.find(".//service")
                if service is not None:
                    cve_list = []
                    for script in port.findall(".//script"):
                        if 'vulners' in script.attrib.get('id', ''):
                            output = script.attrib.get("output", "")
                            cve_entries = [line for line in output.splitlines() if "CVE" in line]
                            cve_list.extend(cve_entries)
                    
                    cleaned_cves = []
                    for cve in cve_list:
                        parts = cve.split()
                        if len(parts) >= 2:
                            cve_id = parts[0].replace('CVE-', '')
                            severity = parts[1]
                            cleaned_cves.append(f"{cve_id} {severity}")
                    
                    if cleaned_cves:
                        cves.append({"service": service.attrib.get("name", "unknown"), "cves": cleaned_cves[:7]})
    except ET.ParseError:
        return []
    return cves

def validate_hash(hash_value):
    """
    Validate the hash format (MD5, SHA1, SHA256).
    """
    return bool(
        re.match(r"^[a-fA-F0-9]{32}$", hash_value) or  # MD5
        re.match(r"^[a-fA-F0-9]{40}$", hash_value) or  # SHA1
        re.match(r"^[a-fA-F0-9]{64}$", hash_value)      # SHA256
    )
def parse_hashcat_output(hashcat_output):
    """
    Parses hashcat output to extract hash:password pairs in raw format.
    Returns a list of strings in 'hash:password' format.
    """
    cracked_pairs = []
    
    if not hashcat_output:
        return cracked_pairs
    
    for line in hashcat_output.split('\n'):
        if ':' in line and not line.startswith('$'):
            parts = line.split(':', 1)
            if len(parts) == 2:
                # Remove any extra whitespace and return raw hash:password pair
                cracked_pairs.append(f"{parts[0].strip()}:{parts[1].strip()}")
    
    return cracked_pairs

def classify_severity(severity_score):
    """
    Classify the CVE severity based on the score
    """
    if 0 <= severity_score <= 3:
        return "Low"
    elif 4 <= severity_score <= 6:
        return "Medium"
    elif 7 <= severity_score <= 8:
        return "High"
    elif 9 <= severity_score <= 10:
        return "Critical"
    return "Unknown"  # If severity doesn't fall into any category

def classify_cves_by_severity(cves):
    """
    Classifies CVEs based on their severity and returns them in categorized lists.
    """
    classified_cves = {
        "Low": [],
        "Medium": [],
        "High": [],
        "Critical": [],
        "Unknown": []  # Add an "Unknown" category to handle unclassified CVEs
    }

    for entry in cves:
        for cve in entry["cves"]:
            # Safely handle the severity as a float and handle potential errors
            try:
                severity_score = float(cve.split()[1]) if len(cve.split()) > 1 else 0
            except ValueError:
                severity_score = 0  # Default to 0 if there's an issue with conversion

            severity = classify_severity(severity_score)
            # Ensure the severity is one of the defined categories
            if severity in classified_cves:
                classified_cves[severity].append(cve)
            else:
                classified_cves["Unknown"].append(cve)  # Handle CVEs with undefined severity

    return classified_cves

def set_cell_background(cell, fill):
    """Set background color for a table cell"""
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shading = OxmlElement('w:shd')
    shading.set(qn('w:fill'), fill)
    shading.set(qn('w:val'), 'clear')
    shading.set(qn('w:color'), 'auto')
    tcPr.append(shading)

