passive.sh
creates files. In domain.txt type je de hoofddomains
deze file wordt uitgelezen en zoekt de subdomains bij de hoofddomains met sublist3r.
de output van sublist3r wordt in een mooi lijstje opgeslagen in subdomains.txt
subdomains.txt wordt uitgelezen en vervolgens wordt dnsrecon uitgevoerd voor ieder subdomain en domain.
output van dnsrecon wordt opgeslagen in dnsrecon.txt.
in dnsreconfiltered.txt filter ik alle output weg zonder dnsrecords en houd ik alleen nuttige informatie over.
in overzicht.txt wordt een lijstje gemaakt van domains/subdomain met bijbehorende IP's. De IP's zijn opgehaald van de A records van de dnsrecon scan.

nmapscript.py voert nmap -O (os-detection) uit voor ieder subdomain/ip in overzicht.txt.
Vervolgens wordt er naar de output gekeken welke openports er gescanned zijn en voor deze ports specifiek wordt nmap -sV -Pn -p uitgevoerd om de service achter de poorten te achterhalen.
De tijd tussen de scans in kan worde aangepast om ddos protection te omzeilen.
