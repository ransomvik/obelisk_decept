#!/usr/bin/env python
# -*- coding: utf-8 -*-
##########################################################################################################################
##
##          Script:         optiv_decept.py
##
##          Language:       Python
##
##          Version:        1.40
##
##          Original Date:  07-24-2016
##
##          Author:         Derek Arnold
##
##          Company:        Optiv Security
##
##          Purpose:        Listen on multiple network ports and write data to a file to detect indicators of compromise.
##
##          Syntax:         python ./optiv_decept.py
##
##          Copyright (C):  2016 Derek Arnold (ransomvik)
##
##          License:        This program is free software: you can redistribute it and/or modify
##                          it under the terms of the GNU General Public License as published by
##                          the Free Software Foundation, either version 3 of the License, or
##                          any later version.
##
##                          This program is distributed in the hope that it will be useful,
##                          but WITHOUT ANY WARRANTY; without even the implied warranty of
##                          MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##                          GNU General Public License for more details. See <http://www.gnu.org/licenses/>
##
##          Change Log:     07-24-2016 DPA      Created.
##                          09-29-2016 DPA      Fixed logging.
##                          01-23-2017 DPA      Changed file rotation and tcp connection timeout
##                          02-06-2017 DPA      Added a udp handler
##                          02-18-2017 DPA      Added an SSH/telnet username and password collector
##                          02-22-2017 DPA      Added CEF Logging as an option
##
##########################################################################################################################

import socket
import select
import time
import sys
import logging
import re
import threading
import subprocess
import os

from logging.handlers import RotatingFileHandler

class DeceptSystem:

    AUTHOR = 'Derek Arnold'
    VERSION = '1.40'
    ORGANIZATION = 'Optiv Security'
    PROGRAM_NAME = 'Optiv Decept'
    YEAR = '2017'

    enable_cef_logging = False

    decept_home = '/opt/optiv_decept/logs'
    log_name = 'optiv_decept.log'

    #log_path = os.path.join(decept_home, 'logs', log_name)
    log_path = decept_home + '/' + log_name

    tcp_port_list = [20,21,22,23,25,
                 53,69,80,110,118,
                 137,139,143,194,389,
                 443,445,465,514,587,636,
                 993,1080,1194,1433,1604,
                 1723,3128,3306,3389,5900,
                 6000,8080,8888]

    udp_port_list = [53,115,118,123,137,139,143,389,514,
                 1080,1194,1433,1512,2049,3306]


    tcpservers = []
    udpservers = []
    #logger = logging.getLogger('decept')
    this_decept_system_ip_address = str(socket.gethostbyname(socket.gethostname()))


    #def __init__(self, num_tcp_connections=0, num_udp_connections=0,mylogdir=log_path, mytcp_port_list=tcp_port_list,myudp_port_list=udp_port_list,done=False, my_decept_system_ip_address=this_decept_system_ip_address,num_good_tcp_binds = 0,num_bad_tcp_binds = 0,num_good_udp_binds = 0,num_bad_udp_binds = 0,dest_portnum = '0',tcpservers=tcpservers,udpservers=udpservers):
    def __init__(self, num_tcp_connections=0, num_udp_connections=0,mylogdir=log_path, mytcp_port_list=tcp_port_list,myudp_port_list=udp_port_list,done=False, my_decept_system_ip_address=this_decept_system_ip_address,num_good_tcp_binds = 0,num_bad_tcp_binds = 0,num_good_udp_binds = 0,num_bad_udp_binds = 0,dest_portnum = '0'):
        self.num_tcp_connections = num_tcp_connections
        self.num_udp_connections = num_udp_connections
        self.mylogdir=mylogdir
        self.mytcp_port_list=mytcp_port_list
        self.myudp_port_list=myudp_port_list
        self.done=done
	self.my_decept_system_ip_address=my_decept_system_ip_address
	self.num_good_tcp_binds=num_good_tcp_binds
	self.num_good_udp_binds=num_good_udp_binds
	self.num_bad_tcp_binds=num_bad_tcp_binds
	self.num_bad_udp_binds=num_bad_udp_binds
	self.dest_portnum=dest_portnum
	#self.tcpservers=tcpservers
	#self.udpservers=udpservers
        self.tcpservers = []
        self.udpservers = []
	print "in init()"
        self.logger=logging.getLogger('decept')
        self.run()

    def parse_tcp_connection(self,addr,conn):

                        #global num_tcp_connections
        self.num_tcp_connections += 1

        src_ip = "0.0.0.0"
        dest_ip = "0.0.0.0"
        src_port = 0
        dest_port = 0
        address_str = str(addr)
        connection_str = str(conn)

        src_ip_search = re.search('\(\'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\'',address_str)

        if src_ip_search:
            src_ip = src_ip_search.group(1)

            src_port_search = re.search('\(\'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\',\s(\d{1,5})',address_str)
            if src_port_search:
                src_port = src_port_search.group(1)

                dest_ip_search = re.search('\(\'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\'',connection_str)
                if dest_ip_search:
                    dest_ip = dest_ip_search.group(1)

                    dest_port_search = re.search('\(\'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\',\s(\d{1,5})',connection_str)
                    if dest_port_search:
                        dest_port = dest_port_search.group(1)

        self.logger.info('TCP Connection #' + str(self.num_tcp_connections) + " detected: Source: " + src_ip + ":" + str(src_port) +
                                                " Destination: " + dest_ip + ":" + str(dest_port) + " proto: tcp Severity: medium")

        return 0

    def handle_udp_accept(self,conn,dest_portnum,timeout=10):

			#global num_udp_connections
	self.num_udp_connections+=1

    	conn.setblocking(0)
    	data=''
    	begin=time.time()
    	total_data=[]
    	bytes_in = 0

	while True:
	    if total_data and time.time()-begin>timeout:
    		break
    	    elif time.time()-begin>timeout:
		break
	    try:
		(client_data, client_address) = conn.recvfrom(1024)
		self.logger.info('UDP Connection #' + str(self.num_udp_connections) + " detected: Source: " + str(client_address[0]) + ":" + str(client_address[1]) +
			    " Destination: " + self.my_decept_system_ip_address + ":" + str(dest_portnum) + " proto: udp Severity: medium")

		client_data = client_data.replace("\n", " ")
		bytes_in = len(client_data)
		self.logger.info("Bytes in: " + str(bytes_in) + " Data received: ^^^\'"+str(client_data)+"\'^^^")

		begin=time.time()

		break
	    except:
		time.sleep(0.5)

	    return 0


		#Handle an incoming TCP connection and log the payload
    def handle_tcp_accept(self,conn,dest_portnum,timeout=10):

	self.logger.info('Attempting to receive TCP data. Timeout=' + str(timeout))

	sleep_interval = int(0.5)

	conn.setblocking(0)
	bytes_in = int(0)
	total_data=[]
	data=''
	begin=time.time()
	wait_for_response = False
	first_level_response = False
	second_level_response = False

	while 1:
			#if you got some data, then break after wait sec
	    if total_data and time.time()-begin>timeout:
		break
			#if you got no data at all, wait a little longer
	    elif time.time()-begin>timeout:
		break
	    try:
                data2=''
		if (int(dest_portnum)==22 or int(dest_portnum)==23) and wait_for_response is False:
		    wait_for_response = True

		    sleep_interval = int(15)
		    timeout=60
					#handle_port_22(conn)

		    message = "\nlogin as: "
		    conn.send(message)
		    #time.sleep(15)
		    data2 = conn.recv(25)
		    data2 = data2.replace("\n", "")
		    data += data2 + "\n"
		    time.sleep(15)

		    #if data2 and first_level_response is False:
                    if data2:
			self.logger.info("received username: " + str(data2))
			bytes_in += len(data2)
		        first_level_response = True
			message = str(data2) + "@" + self.my_decept_system_ip_address + "'s password: "

			conn.send(message)
			time.sleep(15)
			data3=conn.recv(25)
			data3 = data3.replace("\n", "")
		        data += data3 + "\n"
			time.sleep(15)

			if data3 and second_level_response is False:
			    self.logger.info("received password: " + data3 )
			    bytes_in += len(data3)
			    second_level_response = True
			    message = "Permission denied, please try again.\n"

			    conn.send(message)


		else:
		    data=conn.recv(1024)
		    bytes_in = len(data)

		if (bytes_in > 1):
		    data = data.replace("\n", " ")
		    self.logger.info("Bytes in: " +str(bytes_in)+ " Data received: ^^^\'"+str(data)+"\'^^^")
		    total_data.append(data)
		    begin=time.time()
	    except:
	        time.sleep(0.5)


	self.logger.info("Closing connection.")

	return 0

    def run(self):

        print "in run()"
        AUTHOR = 'Derek Arnold'
        VERSION = '1.40'
        ORGANIZATION = 'Optiv Security'
        PROGRAM_NAME = 'Optiv Decept'
        YEAR = '2017'
        #if not os.path.exists(self.mylogdir):
        #    os.mkdir(self.mylogdir)

        handler = RotatingFileHandler(self.mylogdir, mode='a', maxBytes=955555, backupCount=5, encoding=None, delay=0)

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

        self.logger.addHandler(handler)

	self.logger.setLevel(logging.INFO)

	self.logger.info('Starting program.')

    	self.logger.info("\n"+
			"   *_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*\n"+
			"      "+PROGRAM_NAME+" Version " + str(VERSION)+ "\n"
			"      Author: "+AUTHOR+" Year " + str(YEAR) + "\n"
			"      "+ORGANIZATION +"\n"+
			"   *_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*")


    	self.logger.info("Binding to ports in 30 seconds.")
    	self.logger.info("This decept system IP address is: " + self.my_decept_system_ip_address + ".")
    	time.sleep(30)


	for port in self.mytcp_port_list:
	    time.sleep(1)

	    ds = ("0.0.0.0", port)
	    self.logger.info("Attempting to bind to tcp port: " + str(port))

	    try:

	        self.tcpservers.append(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
		self.tcpservers[-1].setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.tcpservers[-1].bind(ds)
	    	self.tcpservers[-1].listen(10)
	    	self.logger.info('Successfully bound to tcp port: ' + str(port))
		self.num_good_tcp_binds += 1

	    except socket.error , msg:
		self.logger.warn( 'Could not bind to tcp port ' + str(port) + " Error Code : " + str(msg[0]) + " Message " + msg[1])
		self.num_bad_tcp_binds += 1
		if self.tcpservers[-1]:
		    self.tcpservers[-1].close()
		    self.tcpservers = self.tcpservers[:-1]

	self.logger.info("Successful tcp port binds: " + str(self.num_good_tcp_binds) + ", Unsuccessful tcp port binds: " + str(self.num_bad_tcp_binds))

        for port in self.udp_port_list:
    	    time.sleep(1)

	    ds = ('',port)
	    self.logger.info("Attempting to bind to udp port: " + str(port))

	    try:
	        self.udpservers.append(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
	        self.udpservers[-1].setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	        self.udpservers[-1].bind(ds)
	        self.logger.info('Successfully bound to udp port: ' + str(port))
	        self.num_good_udp_binds += 1

	    except socket.error , msg:
	        self.logger.warn( 'Could not bind to udp port ' + str(port) + " Error Code : " + str(msg[0]) + " Message " + msg[1])
	        self.num_bad_udp_binds += 1
	        if self.udpservers[-1]:
	            self.udpservers[-1].close()
	            self.udpservers = self.udpservers[:-1]

	self.logger.info("Successful udp port binds: " + str(self.num_good_udp_binds) + ", Unsuccessful udp port binds: " + str(self.num_bad_udp_binds))

	while True:
            #self.logger.info("in True loop")
	    try:
	    	inputready, outputready, exceptready = select.select(self.tcpservers, [], [],10)
	    except select.error, e:
	        self.logger.warn("Select error: " + e)

				   #logger.info("done with select statement")

	    for conn in inputready:
	        for tcp_item in self.tcpservers:
		    if conn == tcp_item:
							#logger.info("in tcp try loop")
			connection, address = conn.accept()

                        print "debug: address=" + str(address) + " connection=" + str(connection.getsockname())

			self.parse_tcp_connection(address,connection.getsockname())
		    	if tcp_item.getsockname()[1]:
			    if len(str(tcp_item.getsockname()[1])) > 0:
			      	dest_portnum = str(tcp_item.getsockname()[1])
			self.handle_tcp_accept(connection,dest_portnum)
                        print "debug: close conn"
			connection.close()

	    try:
		inputready, outputready, exceptready = select.select(self.udpservers, [], [],10)
	    except select.error, e:
		self.logger.warn("Select error: " + e)

	    for conn in inputready:
		for udp_item in self.udpservers:
		    if conn == udp_item:

		    	if udp_item.getsockname()[1]:
			    if len(str(udp_item.getsockname()[1])) > 0:
				dest_portnum = str(udp_item.getsockname()[1])
			self.handle_udp_accept(conn,dest_portnum)

        return 0


		#Closes this program
def __del___(self):
			#global tcpservers
			#global udpservers

    self.logger.warn('Program is shutting down NOW!')
    for close_socket in self.tcpservers:

	self.logger.info("closing a socket in close_program")

	close_socket.close()

    for close_socket in self.udpservers:
	self.logger.info("closing a socket in close_program")

    	close_socket.close()

	self.tcpservers = []
	self.udpservers = []

    sys.exit(0)
    return 0

def closeprog(self):

    self.logger.warn('Program is shutting down NOW!')
    for close_socket in self.tcpservers:

        self.logger.info("closing a socket in close_program")

        close_socket.close()

    for close_socket in self.udpservers:
        self.logger.info("closing a socket in close_program")

        close_socket.close()

        self.tcpservers = []
        self.udpservers = []

    sys.exit(0)
    return 0

#############
    #while splunk_is_still_running:


    #return 0

if __name__ == '__main__':
   #main()
    print "this is the module. you need to import it"


#EOF
