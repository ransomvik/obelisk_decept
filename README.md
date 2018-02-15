---
title:  "Introducing Obelisk Decept"
date:   2017-11-04 11:39:58 -0500

---

<center><img src="https://www.honeypot.io/images/honeypot_big_logo-c551a80e.png" width="500" height="357"></center>

# <i class="fa fa-lock fa-2x" aria-hidden="true"></i> Introducing Obelisk Decept

Many times, it can take large enterprises hundreds of days to detect security breaches. Worse yet, with in several recent instances, organizations have been notified of a breach by government agencies, or other third parties. Where does SIEM fit in as a detective control?

A deception system is designed to confuse, misdirect, and delay an attacker by incorporating ambiguity and misinformation. Very few organizations that I have consulted over the last year are using a deception system in their defense in depth model.

Obelisk Decept System, written by myself, is an open source project that monitors for unauthorized and/or malicious activity on your organizational network. By placing several honeypots that listen on many ports at strategic locations, we can detect early stage attacks. The app can provide increased visibility to potentially malicious activity going on in the organization.

Once we are collecting data from honeypots, we have the ability to search and correlate data.

The goal of SIEM, in addition to compliance and hunting activities, ought to be to lower the time to detect a potential security incident. Think of it as a way of innovating and rethinking SIEM to improve the efficacy of the tools we implement.

I invite you to download and use Obelisk Decept System for free today.

## <i class="fa fa-check-circle-o fa-2x" aria-hidden="true"></i> Features
+ Listen on several common tcp ports and report unauthorized activity to the app.
+ Capture keystrokes and network traffic from potentially malicious hosts.
+ Low system requirements and easy install.

## <i class="fa fa-eye fa-2x" aria-hidden="true"></i> Prerequisites
+ Linux Operating System
+ Install this app on a standalone system that serves no other function or business purpose. If other apps are installed that the organization uses, the false positive rate may increase.
+ Place one or more of the app in strategic network zones or aggregation points.
    + Examples: Corporate data center, PCI zone, DMZ

## <i class="fa fa-info-circle fa-2x" aria-hidden="true"></i> System Requirements
+ 2 CPU cores
+ 2GB RAM
+ 20GB hard drive
+ Operating Systems tested:
   + CentOS 7.4 64 bit
   + Ubuntu 14.04.1 LTS
+ Disable iptables or firewalld, or open the ports used by the app.


<br><br><br>

## <i class="fa fa-cloud-download fa-2x" aria-hidden="true"></i> Download

The app can be downloaded on <i class="fa fa-github fa-3x"></i> <a href="https://github.com/ransomvik/obelisk_decept">GitHub</a> 


<br><br><br>

## <i class="fa fa-file-text-o fa-2x" aria-hidden="true"></i> Sample Logs

```
    TCP Connection #1634 detected: Source: 94.77.209.23:4432 Destination: 64.137.242.189:1433 proto: tcp Severity: medium
    Attempting to receive TCP data. Timeout=10
    Bytes in: 41 Data received: ^^^')U?!'^^^
    Closing connection.
    TCP Connection #1635 detected: Source: 128.73.224.185:60450 Destination: 64.137.242.189:445 proto: tcp Severity: medium
    Attempting to receive TCP data. Timeout=10
    Bytes in: 137 Data received: ^^^'??SMBrS???@bPC NETWORK PROGRAM 1.0LANMAN1.0Windows for Workgroups 3.1aLM1.2X002LANMAN2.1NT LM 0.12'^^^
    Closing connection.
    TCP Connection #1636 detected: Source: 94.77.209.23:4948 Destination: 64.137.242.189:1433 proto: tcp Severity: medium
    Attempting to receive TCP data. Timeout=10
    Bytes in: 41 Data received: ^^^')U?!'^^^
    Closing connection.
    TCP Connection #1638 detected: Source: 66.33.212.121:54601 Destination: 64.137.242.189:5900 proto: tcp Severity: medium
    Attempting to receive TCP data. Timeout=10
    Closing connection.
```




## Install Instructions - Centos 7.x and Ubuntu LTS 15.x

+ Create the folder: /opt/obelisk_decept
    + `mkdir /opt/obelisk_decept`
+ Copy the zip file to the /opt folder, then unzip it.
    + `cd /opt`
    + `cp /tmp/obelisk_decept.zip /opt`
    + `unzip /opt/obelisk_decept.zip`

```
Archive:  obelisk_decept.zip
   creating: obelisk_decept/config/
  inflating: obelisk_decept/config/obelisk_decept.service
   creating: obelisk_decept/decept/
  inflating: obelisk_decept/decept/DeceptSystem.py
 extracting: obelisk_decept/decept/__init__.py
  inflating: obelisk_decept/odlauncher.py
   creating: obelisk_decept/logs/
  inflating: obelisk_decept/logs/obelisk_decept.log
   creating: obelisk_decept/bin/
  inflating: obelisk_decept/bin/obelisk_installer.sh
```


+ Run obelisk_install.sh in the bin folder.
    + `/bin/sh /opt/obelisk_decept/bin/obelisk_installer.sh`

```
bash-4.2# sh obelisk_decept/bin/obelisk_installer.sh
Copying file: /opt/obelisk_decept/config/obelisk_decept.service to /lib/systemd/system
‘/opt/obelisk_decept/config/obelisk_decept.service’ -> ‘/lib/systemd/system/obelisk_decept.service’
Created symlink from /etc/systemd/system/multi-user.target.wants/obelisk_decept.service to /usr/lib/systemd/system/obelisk_decept.service.
Checking log file.
Nov  7 09:09:07 ohon02 systemd: Started Obelisk Decept Service.
Nov  7 09:09:07 ohon02 systemd: Starting Obelisk Decept Service...
? obelisk_decept.service - Obelisk Decept Service
   Loaded: loaded (/usr/lib/systemd/system/obelisk_decept.service; enabled; vendor preset: disabled)
   Active: active (running) since Tue 2017-11-07 09:09:06 EST; 3s ago
 Main PID: 2398 (python)
   CGroup: /system.slice/obelisk_decept.service
           ??2398 /usr/bin/python /opt/obelisk_decept/odlauncher.py

Nov 07 09:09:06 ohon02.obelisksec.com systemd[1]: Started Obelisk Decept Service.
Nov 07 09:09:06 ohon02.obelisksec.com systemd[1]: Starting Obelisk Decept Service...
bash-4.2#
```

+ Check to see if the service started, the results should look similar to the following:
   + `systemctl status obelisk_decept`

```
? obelisk_decept.service - My Script Service
   Loaded: loaded (/usr/lib/systemd/system/obelisk_decept.service; enabled; vendor preset: disabled)
   Active: active (running) since Tue 2017-11-07 09:09:06 EST; 6min ago
 Main PID: 2398 (python)
   CGroup: /system.slice/obelisk_decept.service
           ??2398 /usr/bin/python /opt/obelisk_decept/odlauncher.py

Nov 07 09:09:06 ohon02.obelisksec.com systemd[1]: Started My Script Service.
Nov 07 09:09:06 ohon02.obelisksec.com systemd[1]: Starting My Script Service...
```

+ Finished.

## Install Instructions - Ubuntu LTS 14.x

+ Create the folder: /opt/obelisk_decept
    + `mkdir /opt/obelisk_decept`
+ Copy the zip file to the /opt folder, then unzip it.
    + `cd /opt`
    + `cp /tmp/obelisk_decept.zip /opt`
    + `unzip /opt/obelisk_decept.zip`

```
Archive:  obelisk_decept.zip
   creating: obelisk_decept/config/
  inflating: obelisk_decept/config/obelisk_decept.service
   creating: obelisk_decept/decept/
  inflating: obelisk_decept/decept/DeceptSystem.py
 extracting: obelisk_decept/decept/__init__.py
  inflating: obelisk_decept/odlauncher.py
   creating: obelisk_decept/logs/
  inflating: obelisk_decept/logs/obelisk_decept.log
   creating: obelisk_decept/bin/
  inflating: obelisk_decept/bin/obelisk_installer.sh
```

+ Run obelisk_install.sh in the bin folder
    + `/bin/sh /opt/obelisk_decept/bin/obelisk_installer_ubuntu.sh`

```
root@honeypot:/opt# /bin/sh /opt/obelisk_decept/bin/obelisk_installer_ubuntu.sh
Copying file: /opt/obelisk_decept/config/obelisk_decept.conf to /etc/init/
‘/opt/obelisk_decept/config/obelisk_decept.conf’ -> ‘/etc/init/obelisk_decept.conf’
obelisk_decept start/running, process 2724

2017-11-08 18:47:12,381 - decept - INFO - TCP Connection #2 detected: Source: 218.66.104.158:3740 Destination: 64.137.247.35:1433 proto: tcp Severity: medium
2017-11-08 18:47:12,382 - decept - INFO - Attempting to receive TCP data. Timeout=10
2017-11-08 18:47:12,382 - decept - INFO - Bytes in: 41 Data received: ^^^')U?'^^^
2017-11-08 18:47:22,401 - decept - INFO - Closing connection.
2017-11-08 18:47:32,412 - decept - INFO - TCP Connection #3 detected: Source: 218.66.104.158:4232 Destination: 64.137.247.35:1433 proto: tcp Severity: medium
2017-11-08 18:47:32,413 - decept - INFO - Attempting to receive TCP data. Timeout=10
????g}2?CCCC-F7C4D350D2saMicrol office64.137.247.35,1433ODBCmaster'^^^ ^^^'??q8 ??Vtxx
2017-11-08 18:47:42,413 - decept - INFO - Closing connection.
2017-11-08 18:48:13,122 - decept - INFO - TCP Connection #4 detected: Source: 125.99.81.222:52050 Destination: 64.137.247.35:23 proto: tcp Severity: medium
2017-11-08 18:48:13,122 - decept - INFO - Attempting to receive TCP data. Timeout=10

obelisk_decept start/running, process 2724
```


+ Check to see if the service started, the results should look similar to the following:
   + `service obelisksec status`

```
root@honeypot:/opt# service obelisk_decept status
obelisk_decept start/running, process 2724
```

+ Finished.

## Run in Docker
+ Download this repository
+ Build the docker image
+ Run the image

```
Sample Commands:

git clone /url/to/repository
cd obelisk_decept
docker build -t obelisk .
docker run docker run -p 2020:20 -p 2021:21 -p 2023:23 -p 2025:25 -p 2053:53 -p 2053:53/udp obelisk
```
<i>Note: Run command is a sample. More ports are supported by the app.</i>


## <i class="fa fa-wrench fa-3x" aria-hidden="true"></i> License
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. See http://www.gnu.org/licenses/

<center><img src="http://resources.infosecinstitute.com/wp-content/uploads/virtual-honey-pot-sized.jpg" width="325" height="200"></center>

### About Derek Arnold
Derek Arnold has spent the last 13 years securing large retail, medical device, and insurance companies. He has worked on large, diverse enterprises in the Fortune 500. His key specialties include security operations, threat intelligence, physical security and SIEM. He helps organizations solve their unique security challenges using Splunk Enterprise, security orchestration and automation, and security operations.
