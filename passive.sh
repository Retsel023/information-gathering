#!/bin/bash

# Define file paths
DOMAINS_FILE="domains.txt"
SUBDOMAINS_FILE="subdomains.txt"
DNSRECON_FILE="dnsrecon.txt"
DNSRECON_FILTERED_FILE="dnsreconfiltered.txt"
OVERVIEW_FILE="overzicht.txt"

# Create files if they do not exist
touch $DOMAINS_FILE
touch $SUBDOMAINS_FILE
touch $DNSRECON_FILE
touch $DNSRECON_FILTERED_FILE
touch $OVERVIEW_FILE

# Clear previous output files
> $SUBDOMAINS_FILE
> $DNSRECON_FILE
> $DNSRECON_FILTERED_FILE
> $OVERVIEW_FILE

# Function to perform Sublist3r scan
perform_sublist3r() {
    local domain=$1
    echo "Running Sublist3r for domain: $domain"
    sublist3r -d $domain -o temp_subdomains.txt
    echo "Subdomains for $domain:" >> $SUBDOMAINS_FILE
    cat temp_subdomains.txt >> $SUBDOMAINS_FILE
    echo "" >> $SUBDOMAINS_FILE
    echo "----------------------------------------------------"
}

# Function to perform DNSRecon scan
perform_dnsrecon() {
    local target=$1
    echo "Running DNSRecon for target: $target"
    echo "----- DNSRecon results for $target -----" >> $DNSRECON_FILE
    dnsrecon -d $target >> $DNSRECON_FILE
    echo "" >> $DNSRECON_FILE
    echo "----------------------------------------" >> $DNSRECON_FILE
    echo "" >> $DNSRECON_FILE
}

# Read domains from DOMAINS_FILE and perform Sublist3r scan for each domain
while IFS= read -r domain; do
    perform_sublist3r $domain
    # Also add the main domain to the subdomains list
    echo "Subdomains for $domain:" >> $SUBDOMAINS_FILE
    echo $domain >> $SUBDOMAINS_FILE
    echo "" >> $SUBDOMAINS_FILE
done < $DOMAINS_FILE

# Remove duplicates from SUBDOMAINS_FILE while maintaining order and grouping
awk '!seen[$0]++' $SUBDOMAINS_FILE > temp_subdomains.txt && mv temp_subdomains.txt $SUBDOMAINS_FILE

# Perform DNSRecon for each domain and subdomain
while IFS= read -r target; do
    perform_dnsrecon $target
done < <(grep -E 'Subdomains for|^[^[:space:]]' $SUBDOMAINS_FILE | sed '/^Subdomains for/d')

# Extract domain and IP information from DNSRecon output
echo "Extracting domain and IP information"
grep -E "\[\*\]\s+A\s" $DNSRECON_FILE | awk '{print $3, $4}' | sort -u > temp_overview.txt

# Organize overview by domain
echo "Organizing overview by domain"
> $OVERVIEW_FILE
while IFS= read -r domain; do
    echo "IP addresses for $domain:" >> $OVERVIEW_FILE
    grep -E "$domain\s" temp_overview.txt | while read -r line; do
        subdomain=$(echo $line | awk '{print $1}')
        ip=$(echo $line | awk '{print $2}')
        echo "$subdomain - $ip" >> $OVERVIEW_FILE
    done
    echo "" >> $OVERVIEW_FILE
done < <(cat $DOMAINS_FILE; grep -E 'Subdomains for' $SUBDOMAINS_FILE | awk '{print $3}')

# Generate dnsreconfiltered.txt by excluding scans with no DNS records
echo "Filtering DNSRecon results"
awk 'BEGIN { RS="\n----------------------------------------\n"; FS="\n"; OFS="\n"; ORS="\n----------------------------------------\n" } { if ($0 !~ /No SRV Records Found/) print $0 }' $DNSRECON_FILE > $DNSRECON_FILTERED_FILE

# Clean up temporary files
rm -f temp_subdomains.txt temp_overview.txt

echo "Process completed. Check $OVERVIEW_FILE for the list of domains and their IPs, and $DNSRECON_FILTERED_FILE for filtered DNSRecon results."
