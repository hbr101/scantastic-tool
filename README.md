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

Run and import a scan of home /24 network

```
./scantastic.py -s -H 192.168.1.0/24 -p 80,443 -x homescan.xml (with masscan) - doesn't work
./scantastic.py -ns -H 192.168.1.0/24 -p 80,443 -x homescan.xml (with nmap)
```

Export homescan to a list of urls

```
./scantastic.py -eurl -x homescan.xml > urlist (with masscan) - doesn't work
./scantastic.py -nurl -x homescan.xml > urlist (with nmap)
```

Brute force the url list using wordlist and put results into index homescan
using 10 threads (By default it uses 1 thread)

```
./scantastic.py -d -u urlist -w some_wordlist -i homescan -t 10
```

```
root@ubuntu:~/scantastic-tool# ./scantastic.py -h
usage: scantastic.py [-h] [-v] [-d] [-s] [-sl] [-in] [-e] [-eurl]
                     [-del] [-H HOST] [-p PORTS] [-x XML] [-w WORDS] [-u URLS]
                     [-t THREADS]
                     [-a AGENT]

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         Version information
  -d, --dirb            Run directory brute force. Requires --urls & --words
  -s, --scan            Run masscan on single range. Specify --host & --ports
                        & --xml
  -ns, --nmap           Run Nmap on a single range specify -H & -p
  -sl, --scanlist       Run masscan on a list of ranges. Requires --host &
                        --ports & --xml
  -nsl, --nmaplist      Run Nmap on a list of ranges -H & -p & -x
  -eurl, --exporturl    Export urls to scan from XML file. Requires --xml
  -nurl, --exportnmap   Export urls from nmap XML, requires -x
  -del, --delete        Specify an index to delete.
  -H HOST, --host HOST  Scan this host or list of hosts
  -p PORTS, --ports PORTS
                        Specify ports in masscan format. (ie.0-1000 or
                        80,443...)
  -x XML, --xml XML     Specify an XML file to store output in
  -w WORDS, --words WORDS
                        Wordlist to be used with --dirb
  -u URLS, --urls URLS  List of Urls to be used with --dirb
  -t THREADS, --threads THREADS
                        Specify the number of threads to use.
  -a AGENT, --agent AGENT
                        Specify a User Agent for requests
```
