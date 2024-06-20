import subprocess
import re
import time

def run_nmap(command):
    subprocess.run(command, shell=True)

def parse_overzicht(file_path):
    targets = []
    current_target = None
    with open(file_path, "r") as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith("IP addresses for"):
                current_target = line.strip().split(":")[1].strip()
            elif line.strip() != "":
                domain_ip_pair = re.match(r'^(.*?)\s+-\s+(\d+\.\d+\.\d+\.\d+)', line.strip())
                if domain_ip_pair:
                    domain = domain_ip_pair.group(1)
                    ip = domain_ip_pair.group(2)
                    targets.append((domain, ip))
                else:
                    domain = line.strip()
                    targets.append((domain, None))
    return targets

def scan_services(target, ip):
    if ip:
        target_str = ip
    else:
        target_str = target
    
    # Scan for services on all ports
    service_scan_file = f"service_scan_{target_str.replace('.', '_')}.txt"
    command = f"nmap -oN {service_scan_file} {target_str}"
    print(f"Scanning services for {target}: {command}")
    run_nmap(command)
    return service_scan_file

def scan_open_ports(target, ip, service_scan_file):
    if ip:
        target_str = ip
    else:
        target_str = target
    
    # Extract open ports from the service scan results
    open_ports = set()
    with open(service_scan_file, "r") as f:
        lines = f.readlines()
        for line in lines:
            port_match = re.match(r'^(\d+)/tcp\s+open', line.strip())
            if port_match:
                port = port_match.group(1)
                open_ports.add(port)
    
    # Convert open ports to comma-separated list for nmap
    ports_to_scan = ",".join(open_ports)
    
    # Scan specific open ports for detailed analysis
    if ports_to_scan:
        detailed_scan_file = f"detailed_scan_{target_str.replace('.', '_')}.txt"
        command = f"nmap -sV -Pn -p {ports_to_scan} -oN {detailed_scan_file} {target_str}"
        print(f"Scanning detailed ports for {target}: {command}")
        run_nmap(command)
    else:
        print(f"No open ports found for {target}. Skipping detailed scan.")

if __name__ == "__main__":
    overzicht_file = "overzicht.txt"
    targets = parse_overzicht(overzicht_file)

    for target, ip in targets:
        service_scan_file = scan_services(target, ip)
        time.sleep(60)  # Voeg een vertraging van 5 seconden toe tussen scans
        scan_open_ports(target, ip, service_scan_file)

    print("Scans completed successfully.")
