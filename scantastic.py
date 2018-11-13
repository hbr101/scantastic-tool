#!/usr/bin/env python

import multiprocessing
import argparse
import sys
import requests
import string
import database
import mysql.connector
import logging
import time
import random
from datetime import datetime
from time import sleep
from elasticsearch import Elasticsearch
from netscan import Masscan
from netscan import Nmap
from xmltourl import Xml2urls
from xmltourl import Xml2urls2
from numpy import array_split

requests.packages.urllib3.disable_warnings()
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %H:%M:%S:', filename='/var/log/scantastic/scan.log', level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

def version_info():
	VERSION_INFO = 'Scantastic v2.0'
	AUTHOR_INFO = 'Author: Ciaran McNally - https://makthepla.net'
	print '                 _           _   _'
	print ' ___ ___ ___ ___| |_ ___ ___| |_|_|___'
	print '|_ -|  _| .\'|   |  _| .\'|_ -|  _| |  _|'
	print '|___|___|__,|_|_|_| |__,|___|_| |_|___|'
	print '======================================='
	print VERSION_INFO
	print AUTHOR_INFO

def start_dirbuster(raw_words, num_threads, agent):
        try:
#            with open(args.urls) as f:
#                urls = f.read().splitlines()
	# Open word list
            with open('/var/log/scantastic/'+raw_words) as f:
                words = f.read().splitlines()
        except IOError:
            logging.info("File not found {}. Exiting..".format(raw_words))
            exit(0)

	# Create list from url_links table
	urls = db_get_links()
        threads = []
        splitlist = list(split_urls(urls, num_threads))

        for word in words:
            # Disable this when in prod
            logging.info(("Word: {}").format(word))
            for i in range(0, len(splitlist)):
                p = multiprocessing.Process(target=requestor,
                                            args=(
                                                list(splitlist[i]), word, agent))
                threads.append(p)
            try:
                for p in threads:
                    p.start()
                for p in threads:
                    p.join()
            except KeyboardInterrupt:
                print 'Killing Threads...'
                for p in threads:
                    p.terminate()
                sys.exit(0)
            threads = []

# Split the list of urls into chunks for threading
def split_urls(u, t):
    logging.info('Number of URLS: ' + str(len(u)))
    logging.info('Threads: ' + str(t))
    logging.info('URLS in each split: ' + str(len(u) / t))
    logging.info('=========================')
    sleep(1)
    return array_split(u, t)


def returnIPaddr(u):
    ip = ""
    if u.startswith('http://'):
        remainhttp = u[7:]
        ip = string.split(remainhttp, '/')[0]
    if u.startswith('https://'):
        remainhttps = u[8:]
        ip = string.split(remainhttps, '/')[0]
    return ip


def returnTitle(content):
    t1 = ''
    t2 = ''
    if '<title>' in content:
        t1 = string.split(content, '<title>')[1]
        t2 = string.split(t1, '</title>')[0]
    return t2

# Check if dirbuster result is already in DB
def db_check_duplicate(data, cursor):
	ret = True
	stmt = "SELECT ip FROM dirb_scan WHERE ip = %s AND link = %s"
	res = cursor.execute(stmt, (data['ip'], data['link'],))
        rows = cursor.fetchall()
        count = cursor.rowcount
        if count > 0:
                logging.info("Dir in db {}. Returning..".format(data['link']))
                pass
        else:
                logging.info("Dir {} not found.".format(data['link']))
		ret = False
	return ret

# Insert dirbuster results to DB
def db_insert_dirb(data, cursor, cnx):
	cursor = cnx.cursor(prepared=True)
	stmt = "INSERT INTO dirb_scan (ip, status,content_length, content, title, link, directory) VALUES (%s, %s, %s, %s, %s, %s, %s);"
	res = cursor.execute(stmt, (data['ip'], data['status'], data['content-length'], data['content'], data['title'], data['link'], data['directory'],))
	cnx.commit()

def db_get_links():
	list = []
	cnx = mysql.connector.connect(user=database.db_user, password=database.db_passwd,host=database.db_host,database=database.db_name)
	cursor = cnx.cursor(prepared=True)
	stmt = "SELECT link FROM url_links"
	res = cursor.execute(stmt)
	# link is bytearray and we need to encode it
	for (link) in cursor:
		list.append(link[0].decode('utf-8'))
	cursor.close()
	cnx.close()
	return list

# Make requests
def requestor(urls, dirb, agent):
    data = {}
    user_agent = {'User-agent': agent}
    # init db connector
    cnx = mysql.connector.connect(user=database.db_user, password=database.db_passwd,host=database.db_host,database=database.db_name)
    cursor = cnx.cursor(prepared=True)
    for url in urls:
	# Calc random number
	randomint = random.randint(1,10)
        sleep(randomint)
	# and pray that we do not get blacklisted
        urld = url + dirb
        try:
            r = requests.get(urld, timeout=10, headers=user_agent, verify=False)
            stat = r.status_code
            time = datetime.utcnow()
            cont_len = len(r.content)
            title = returnTitle(r.content)
            if len(r.content) >= 500:
                content = r.content[0:500]
            else:
                content = r.content
            ip = returnIPaddr(url)
            if 'image' in r.headers['content-type']:
                content = 'image'
            if r.status_code == 200:
                logging.info(urld + ' - ' + str(r.status_code) + ':' + str(len(r.content)))
		pass
        except requests.exceptions.Timeout:
            # print urld+' - Timeout'
            stat = -1
        except requests.exceptions.ConnectionError:
            # print url+dirb+' - Connection Error!'
            stat = -2
        except requests.exceptions.TooManyRedirects:
            # print urld+' - Too many redirects!'
            stat = -3
        except:
            stat = 0

        if stat > 0:
            data = {
                'timestamp': time,
                'ip': ip,
                'status': stat,
                'content-length': cont_len,
                'content': content,
                'title': title,
                'link': url + dirb,
                'directory': dirb
            }
            try:
                if data['status'] == 200:
                    if db_check_duplicate(data, cursor) == True:
                        pass
                    else:
                        db_insert_dirb(data, cursor, cnx)
                else:
                    pass
            except:
                data['title'] = 'Unicode Error'
                data['content'] = 'Unicode Error'
                if data['status'] == 200:
                    if db_check_duplicate(data, cursor) == True:
                        pass
                    else:
                        db_insert_dirb(data, cursor, cnx)
                else:
                    pass

    cursor.close()
    cnx.close()

# Run regular masscan on specified range - DOESN't WORK
def scan(host, ports, xml, index, eshost, esport, noin):
    ms = Masscan(host, 'xml/' + xml, ports)
    ms.run()
    if noin == False:
        ms.import_es(index, eshost, esport)
        print ms.output


# Run masscan on file of ranges - DOESN't WORK
def scanlst(hostfile, ports, xml, index, eshost, esport, noin):
    ms = Masscan(hostfile, 'xml/' + xml, ports)
    ms.runfile()
    if noin == False:
        ms.import_es(index, eshost, esport)
        print ms.output


# Run regular nmap scan on specified range
def nscan(host, ports, xml, raw_words, num_threads, agent):
    ms = Nmap(host, '/var/log/scantastic/' + xml, ports)
    ms.run()
    ms.import_db()
    logging.info("Starting to parse XML file...")
    x = Xml2urls2(xml)
    x.run()
    logging.info("Parsing should be completed...")
    logging.info("Starting dirbuster...")
    start_dirbuster(raw_words, num_threads, agent)
    logging.info("Dirbuster done..Exiting")
    exit(0)

# Run nmap scan on file of ranges
def nscanlst(hostfile, ports, xml, raw_words, num_threads, agent):
    ms = Nmap(hostfile, '/var/log/scantastic/' + xml, ports)
    ms.runfile()
    ms.import_db()
    logging.info("Starting to parse XML file...")
    x = Xml2urls2(xml)
    x.run()
    logging.info("Parsing should be completed...")
    logging.info("Starting dirbuster...")
    start_dirbuster(raw_words, num_threads, agent)
    logging.info("Dirbuster done..Exiting")
    exit(0)

def export_xml(xml, index, eshost, esport):
    ms = Masscan('x', 'xml/' + xml, 'y')
    ms.import_es(index, eshost, esport)

def nexport_xml(xml):
    ms = Nmap('x', 'xml/' + xml, 'y')
    ms.import_db()

def delete_index(dindex, eshost, esport):
    url = 'http://' + eshost + ':' + str(esport) + '/' + dindex
    print 'deleting index: ' + url
    r = requests.delete(url)
    print r.content


def export_urls(xml):
    x = Xml2urls(xml)
    x.run()

def nexport_urls(xml):
    x = Xml2urls2(xml)
    x.run()

if __name__ == '__main__':
    parse = argparse.ArgumentParser()
    parse.add_argument('-v', '--version', action='store_true', default=False,
                       help='Version information')
    parse.add_argument('-d', '--dirb', action='store_true', default=False,
                       help='Run directory brute force. Requires --urls & --words')
    parse.add_argument('-s', '--scan', action='store_true', default=False,
                       help='Run masscan on single range. Specify --host & --ports & --xml')
    parse.add_argument('-ns', '--nmap', action='store_true', default=False,
			help='Run Nmap on a single range specify -H & -p')
    parse.add_argument('-noes', '--noelastics', action='store_true', default=False,
                       help='Run scan without elasticsearch insertion')
    parse.add_argument('-sl', '--scanlist', action='store_true', default=False,
                       help='Run masscan on a list of ranges. Requires --host & --ports & --xml')
    parse.add_argument('-nsl', '--nmaplist', action='store_true', default=False, 
			help='Run Nmap on a list of ranges -H & -p & -x')
    parse.add_argument('-in', '--noinsert', action='store_true', default=False,
                       help='Perform a scan without inserting to elasticsearch')
    parse.add_argument('-e', '--export', action='store_true', default=False,
                       help='Export a scan XML into elasticsearch. Requires --xml')
    parse.add_argument('-eurl', '--exporturl', action='store_true', default=False,
                       help='Export urls to scan from XML file. Requires --xml')
    parse.add_argument('-nurl', '--exportnmap', action='store_true', default=False,
			help='Export urls from nmap XML, requires -x')
    parse.add_argument('-del', '--delete', action='store_true', default=False,
                       help='Specify an index to delete.')
    parse.add_argument('-H', '--host', type=str, help='Scan this host or list of hosts')
    parse.add_argument('-p', '--ports', type=str,
                       default='21,22,80,443,8000,8080,8443,2080,2443,9090,6000,8888,50080,50443,5900',
                       help='Specify ports in masscan format. (ie.0-1000 or 80,443...)')
    parse.add_argument('-x', '--xml', type=str, default='scan.xml',
                       help='Specify an XML file to store output in')
    parse.add_argument('-w', '--words', type=str, default='words',
                       help='Wordlist to be used with --dirb')
    parse.add_argument('-u', '--urls', type=str, default='urls',
                       help='List of Urls to be used with --dirb')
    parse.add_argument('-t', '--threads', type=int, default=1,
                       help='Specify the number of threads to use.')
    parse.add_argument('-esh', '--eshost', type=str, default=u'127.0.0.1',
                       help='Specify the elasticsearch host')
    parse.add_argument('-esp', '--port', type=int, default=9200,
                       help='Specify ElasticSearch port')
    parse.add_argument('-i', '--index', type=str, default='scantastic',
                       help='Specify the ElasticSearch index')
    parse.add_argument('-a', '--agent', type=str, default='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0',
                       help='Specify a User Agent for requests')
    args = parse.parse_args()

    if len(sys.argv) <= 1:
        parse.print_help()
        sys.exit(0)

    if args.version:
        version_info()

    if args.scan and (args.host is not None):
        scan(args.host, args.ports, args.xml, args.index, args.eshost,
             args.port, args.noinsert)
    elif args.nmap and (args.host is not None):
	nscan(args.host, args.ports, args.xml, args.words, args.threads, args.agent)

    if args.scanlist and (args.host is not None):
        scanlst(args.host, args.ports, args.xml, args.index, args.eshost,
                args.port, args.noinsert)
    elif args.nmaplist and (args.host is not None):
	nscanlst(args.host, args.ports, args.xml, args.words, args.threads, args.agent)

    if args.export:
        export_xml(args.xml, args.index, args.eshost, args.port)

    if args.delete:
        delete_index(args.index, args.eshost, args.port)

    if args.exporturl:
        export_urls(args.xml)
    elif args.exportnmap:
	nexport_urls(args.xml)
'''    if args.dirb:
        try:
#            with open(args.urls) as f:
#                urls = f.read().splitlines()
	# Open word list
            with open('/var/log/scantastic/'+args.words) as f:
                words = f.read().splitlines()
        except IOError:
            logging.info("File not found {}. Exiting..".format(args.words))
            exit(0)

	# Create list from url_links table
	urls = db_get_links()
	print urls[0]
        threads = []
        splitlist = list(split_urls(urls, args.threads))

        for word in words:
            print 'Word: ' + word
            for i in range(0, len(splitlist)):
                p = multiprocessing.Process(target=requestor,
                                            args=(
                                                list(splitlist[i]), word, args.agent))
                threads.append(p)
            try:
                for p in threads:
                    p.start()
                for p in threads:
                    p.join()
            except KeyboardInterrupt:
                print 'Killing Threads...'
                for p in threads:
                    p.terminate()
                sys.exit(0)
            threads = []
'''
