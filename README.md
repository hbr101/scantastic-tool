# scantastic-tool

## It's bloody scantastic

 - Dependencies: (DIY - I ain't supportin shit)
 - Masscan - https://github.com/robertdavidgraham/masscan
 - Nmap - https://nmap.org/download.html
 - MariaDB


This tool can be used to store masscan or nmap data in database.

It allows performs distributed directory brute-forcing. 

All your base are belong to us. I might maintain or improve this over time. MIGHT.

## Quickstart

### Example usage
Scan local home /24 network
```
./scantastic.py -ns -H 192.168.0.0/24 -p 80,443 -x homescan.xml -w subdomains-100.txt -t 10
```

