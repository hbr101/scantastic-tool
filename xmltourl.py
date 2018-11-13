#!/usr/bin/env python
# Generate URLS from scanfile
# ===============================

import xmltodict
import logging
import mysql.connector
import database
import os

# Check if link is already in DB
def db_check_duplicate_2(data, cursor):
        ret = True
        stmt = "SELECT link FROM url_links WHERE link = %s"
        res = cursor.execute(stmt, (data,))
        rows = cursor.fetchall()
        count = cursor.rowcount
        if count > 0:
                logging.info("Link in db {}. Returning..".format(data))
                pass
        else:
                logging.info("Link {} not found.".format(data))
                ret = False
        return ret

# Insert link to DB
def db_insert_link(data, cursor, cnx):
        cursor = cnx.cursor(prepared=True)
        stmt = "INSERT INTO url_links (link) VALUES (%s);"
        res = cursor.execute(stmt, (data,))
        cnx.commit()


class Xml2urls:
    def __init__(self, xmlfile):
        self.xmlf = xmlfile
        self.data = ''
        try:
            with open('xml/' + self.xmlf) as myf:
                self.data = myf.read().replace('\n', '')
        except IOError:
            print 'File IO Error'
        self.xml = xmltodict.parse(self.data)


    def run(self):
        nmaprun = self.xml['nmaprun']
        host = nmaprun['host']

        for entry in host:
            port = 0
#            port = entry['ports']['port']
            if int(port['@portid']) == 80:
                name = entry['address']['@addr']
                print 'http://' + name + '/'
            elif int(port['@portid']) == 443:
                name = entry['address']['@addr']
                print 'https://' + name + '/'
            elif int(port['@portid']) == 21:
                name = entry['address']['@addr']
                print 'ftp://' + name + '/'
            else:
                name = entry['address']['@addr']
                print 'http://' + name + ':' + str(port['@portid']) + '/'

class Xml2urls2:
	def __init__(self, xmlfile):
		self.xmlf = xmlfile
		self.data = ''
		try:
			with open('/var/log/scantastic/' + self.xmlf) as myf:
				self.data = myf.read().replace('\n', '')
		except IOError:
			print 'File IO Error'
		self.xml = xmltodict.parse(self.data)

	def run(self):
		nmaprun = self.xml['nmaprun']
		scanhost = nmaprun['host']
		# init DB connector and cursor
		cnx = mysql.connector.connect(user=database.db_user, password=database.db_passwd,host=database.db_host,database=database.db_name)
		cursor = cnx.cursor(prepared=True)
		for i in scanhost:
			link = ""
			address = i['address']['@addr']
			port1 = dict(i)
			try:
				if int(port1['ports']['port']['@portid']) > 0:
					port2 = port1['ports']['port']['@portid']
					if port2 == '80':
						link = 'http://'+address+'/'
					elif port2 == '443':
						link = 'https://'+address+'/'
					else:
						link = 'http://'+address+':'+port2+'/'
			except:
				port2 = i['ports']['port']
				for z in port2:
					x = z['@portid']
					if x == '80':
						link = 'http://'+address+'/'
					elif x == '443':
						link = 'https://'+address+'/'
					else:
						link = 'http://'+address+':'+x+'/'
					# Check if link is already in DB
					if db_check_duplicate_2(link, cursor) == True:
						pass
					else:
						# Insert to DB
						db_insert_link(link, cursor, cnx)
			# Check if link is already in DB
			if db_check_duplicate_2(link, cursor) == True:
				pass
			else:
				# Insert to DB
				db_insert_link(link, cursor, cnx)
		# Remove xml file
		try:
    			os.remove('/var/log/scantastic/'+self.xmlf)
		except OSError:
    			pass

