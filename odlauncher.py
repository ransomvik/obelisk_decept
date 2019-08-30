#!/usr/bin/env python

import argparse
import os
import sys
import signal
import socket
import logging
from decept import DeceptSystem

if __name__ == '__main__':
    start_here = "start_here"

    enable_cef_logging = False

    decept_home = '/opt/obelisk_decept/logs'
    log_name = 'obelisk_decept.log'
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
   # logger = logging.getLogger('decept')
    this_decept_system_ip_address = str(socket.gethostbyname(socket.gethostname()))


    try:
        print "starting"
        ods = DeceptSystem.DeceptSystem(num_tcp_connections=0, num_udp_connections=0,mylogdir=log_path, mytcp_port_list=tcp_port_list,myudp_port_list=udp_port_list,done=False, my_decept_system_ip_address=this_decept_system_ip_address,num_good_tcp_binds = 0,num_bad_tcp_binds = 0,num_good_udp_binds = 0,num_bad_udp_binds = 0,dest_portnum = '0')

        print "done"

    except KeyboardInterrupt:
        print '\r[!] Keyboard Ctrl-C.  Exiting...'
        ods.closeprog()

    except Exception as e:
        print e
