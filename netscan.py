#!/usr/bin/env python
# A class to run masscan and import the results to ES

import subprocess
import socket
import xmltodict
import database
import mysql.connector
from elasticsearch import Elasticsearch
from datetime import datetime


class Masscan:
    # Initialize with range, output, ports

    def __init__(self, ip_r, xml_o, ps):
        self.ip_range = ip_r
        self.xml_output = xml_o
        self.ports = ps

    def run(self):
        self.args = ("masscan", "-sS", "-Pn", self.ip_range,
                     "-oX", self.xml_output, "--rate=15000", "-p",
                     self.ports, "--open")
        popen = subprocess.Popen(self.args, stdout=subprocess.PIPE)
        popen.wait()
        self.output = popen.stdout.read()
        print "Scan completed!"

    def runfile(self):
        self.args = ("masscan", "-sS", "-Pn", "-iL", self.ip_range,
                     "-oX", self.xml_output, "--rate=15000", "-p", self.ports,
                     "--open")
        popen = subprocess.Popen(self.args, stdout=subprocess.PIPE)
        popen.wait()
        self.output = popen.stdout.read()
        print "Scan completed!"

    def import_es(self, es_index, host, port):
        es = Elasticsearch([{u'host': host, u'port': port}])
        try:
            with open(self.xml_output, "r") as xmlfile:
                data = xmlfile.read().replace('\n', '')
            xml = xmltodict.parse(data)
            nmaprun = xml['nmaprun']
            host = nmaprun['host']
        except:
            print "IO Error"

        for entry in host:
            port = entry['ports']['port']
            try:
                name, alias, addrlist = socket.gethostbyaddr(entry['address']['@addr'])
            except socket.herror:
                name = entry['address']['@addr']
            dataentry = {
                'ip': entry['address']['@addr'],
                'port': port['@portid'],
                'name': name,
                'link': 'http://' + name + '/'
            }
            result = es.index(index=es_index, doc_type='hax', body=dataentry)


class Nmap:
    # Initialize with range, output, ports

    def __init__(self, ip_r, xml_o, ps):
        self.ip_range = ip_r
        self.xml_output = xml_o
        self.ports = ps

    def run(self):
        self.args = ("nmap", "-sS", "-Pn", self.ip_range,
                     "-oX", self.xml_output, "-p", self.ports, "--open")
        popen = subprocess.Popen(self.args, stdout=subprocess.PIPE)
        popen.wait()
        self.output = popen.stdout.read()
        print "Scan completed!"

    def runfile(self):
        self.args = ("nmap", "-sS", "-Pn", "-iL", self.ip_range,
                     "-oX", self.xml_output, "-p", self.ports, "--open")
        popen = subprocess.Popen(self.args, stdout=subprocess.PIPE)
        popen.wait()
        self.output = popen.stdout.read()
        print "Scan completed!"

    def toDB(self, address, ports, cursor, stmt, cnx):
        try:
                name, alias, addrlist = socket.gethostbyaddr(address)
        except socket.herror:
                name = address
        link = 'http://' + name + '/'

	res = cursor.execute(stmt, (address, ports, link,))
        rows = cursor.fetchall()
        count = cursor.rowcount
	if count > 0:
		print "Already in db {}. Returning..".format(link)
		return
	else:
		print "Address {} not found. Inserting to DB..".format(link)

	stmt = "INSERT INTO nmap_scan (name, ip, port, link) VALUES (%s, %s, %s, %s);"
	res = cursor.execute(stmt, (name, address, ports, link,))
	cnx.commit()
	print "INSERT to DB successful: {}".format(link)

    def import_db(self):
        cnx = mysql.connector.connect(user=database.db_user, password=database.db_passwd,host=database.db_host,database=database.db_name)
        cursor = cnx.cursor(prepared=True)
        stmt = "SELECT ip, port, link FROM nmap_scan WHERE ip = %s AND port = %s AND link = %s"
        try:
            with open(self.xml_output, "r") as xmlfile:
                data = xmlfile.read().replace('\n', '')
            xml = xmltodict.parse(data)
            nmaprun = xml['nmaprun']
            scanhost = nmaprun['host']
            for i in scanhost:
                address = i['address']['@addr']
#                address = i['address'][0]['@addr']
                port1 = dict(i)
                try: #if one result
                        if int(port1['ports']['port']['@portid']) > 0:
                                port2 = port1['ports']['port']['@portid']
                                self.toDB(address, str(port2), cursor, stmt, cnx)
                except: #if multiple
                        port2 = i['ports']['port']#[0]['@portid']
                        for z in port2:
                                x = z['@portid']
                                self.toDB(address, str(x), cursor, stmt, cnx)
        except IOError, e:
            print e
	cursor.close()
	cnx.close()
