# Cyber Defense Framework
## Pyramid of Pain
The pyramid of pain illustrates the varying levels of difficulty and cost an adversary would encounter to evade detection and continue their attack.<br>
Ex: Hashes are easy to modify to hide an attack/tool/script but not TTPs (Techniques Tactics Procedures)
![[Pasted image 20260219112804.png]]
Ref: [What Is Pyramid of Pain in Cybersecurity? | Picus](https://www.picussecurity.com/resource/glossary/what-is-pyramid-of-pain)

### **Hash Values (Trivial)**
- Considered trivial as it is easy to modify file contents to change hashes.
	
>❔ **Analyse the report associated with the hash "b8ef959a9176aef07fdca8705254a163b50b49a17217a4ff0107487f59d4a35d" [here.](https://assets.tryhackme.com/additional/pyramidofpain/t3-virustotal.pdf) What is the filename of the sample?**
> > Sales_Receipt 5606.xls

### **IP Address (Easy)**
- An adversary can make it challenging to successfully carry out IP blocking is by using Fast Flux.
- Fast Flux is a DNS technique used by botnets to hide phishing, web proxying, malware delivery, and malware communication activities behind compromised hosts acting as proxies.
	  Ref: [Fast Flux 101: How Cybercriminals Improve the Resilience of Their Infrastructure to Evade Detection and Law Enforcement Takedowns](https://unit42.paloaltonetworks.com/fast-flux-101/)
	
>❔ **Read the following [report](https://assets.tryhackme.com/additional/pyramidofpain/task3-anyrun.pdf) to answer this question. What is the **first IP address** the malicious process (**PID 1632**) attempts to communicate with?**
> > 50.87.136.52

>❔ **Read the following [report](https://assets.tryhackme.com/additional/pyramidofpain/task3-anyrun.pdf) to answer this question. What is the **first domain name** the malicious process ((PID 1632) attempts to communicate with?**
> > craftingalegacy.com

### **Domain Names (Simple)**
- Attackers can purchase domains for cheap and modify the DNS records.
- DNS providers often have loose standards. 
- A Punycode attack can be used by the attackers to redirect users to a malicious domain that seems legitimate at first glance.
	- ``` `adıdas.de`  which has the Punycode of  `http://xn--addas-o4a.de/`   ```
		- Modern browsers should now be able to translate Punycode effectively.
- To detect malicious domains, proxy logs or web server logs can be used.
- Attackers usually use URL shorteners. You can preview the URL redirection by adding '+' to the end of the shortened URL.
	  
>❔ **Go to [this report on app.any.run](https://app.any.run/tasks/a66178de-7596-4a05-945d-704dbf6b3b90) and provide the first **suspicious** domain request you are seeing, you will be using this report to answer the remaining questions of this task.**
> > craftingalegacy.com

>❔ **What term refers to an address used to access websites?**
> > Domain Name

>❔ **What type of attack uses Unicode characters in the domain name to imitate the a known domain?**
> > Punycode attack

>❔ **Provide the redirected website for the shortened URL using a preview: https://tinyurl.com/bw7t8p4u**
> > https://tryhackme.com/

### **Host Artifacts (Annoying)**
- Traces or observables that attackers leave on the system (registry values, suspicious processes, patterns and IOCs, etc)
- It would be annoying for an attacker to rework their toolset to avoid a detection.
	
	>❔ *A security vendor has analysed the malicious sample for us. Review the report [here](https://assets.tryhackme.com/additional/pyramidofpain/task5-report.pdf) to answer the following questions.*
	> > Review the report from the link.

	>❔ **A process named **regidle.exe** makes a POST request to an IP address based in the United States (US) on **port 8080**. What is the IP address?**
	> > 96.126.101.6

	>❔ **The actor drops a malicious executable (EXE). What is the name of this executable?**
	> > G_jugk.exe

	>❔ **Look at this [report](https://assets.tryhackme.com/additional/pyramidofpain/vtotal2.png) by Virustotal. How many vendors determine this host to be malicious?**
	> > 9

### **Network Artifacts (Annoying)**
- A network artifact can be a user-agent string, C2 information, or URI patterns followed by the HTTP POST requests.
- Network artifacts can be detected in Wireshark PCAPs (file that contains the packet data of a network) by using a network protocol analyzer such as [TShark](https://www.wireshark.org/docs/wsug_html_chunked/AppToolstshark.html) or exploring IDS (Intrusion Detection System) logging from a source such as [Snort](https://www.snort.org/).
	
	>❔ **What browser uses the User-Agent string shown in the screenshot above?**
	> > Internet Explorer

	>❔ **How many POST requests are in the screenshot from the pcap file?**
	> > 6

### **Tools (Challenging)**
- It is challenging for an attacker to find new tools that would be able to execute the attack on the machine without being flagged.
- The attacker would need to change their toolset and how these tools work.
- Antivirus signatures, detection rules, and YARA rules can be great weapons for you to use against attackers at this stage.
- Use [MalwareBazaar](https://bazaar.abuse.ch/) and [Malshare](https://malshare.com/) to find resources, samples, malicious feeds and Yara results.
- [SOC Prime Threat Detection Marketplace](https://tdm.socprime.com/) can be used to find detection rules.
- [SSDeep](https://ssdeep-project.github.io/ssdeep/index.html) can be used for fuzzy hashing.
	
	>❔ **Provide the method used to determine similarity between the files**
	> > Fuzzy Hashing

	>❔ **Provide the alternative name for fuzzy hashes without the abbreviation**
	> > context triggered piecewise hashes

### **TTPs (Tough)**
- This includes the whole [MITRE](https://attack.mitre.org/) [ATT&CK Matrix](https://attack.mitre.org/), which means all the steps taken by an adversary to achieve his goal.
- TTPs are quite hard to change.
- Detection models shall be properly tuned to flag suspicious activity upon execution.
	
	>❔ **Navigate to ATT&CK Matrix webpage. How many techniques fall under the Exfiltration category?**
	> > 9

	>❔ **Chimera is a China-based hacking group that has been active since 2018. What is the name of the commercial, remote access tool they use for C2 beacons and data exfiltration?**
	> > Cobalt Strike

## **Practical: The Pyramid of Pain**
- Complete the interactive task.<br>

	>❔ **Complete the static site. What is the flag?**
	> > THM{PYRAMIDS_COMPLETE}

## Cyber Kill Chain
The Cyber Kill Chain consists of target identification, decision and order to attack the target, and target destruction.
It is the roadmap and attacker takes for a successful attack. Understanding this maps helps defenders understand where and what to look as well as what to secure.
![[Pasted image 20260220105132.png]]
Ref: [Cyber Kill Chain® | Lockheed Martin](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)

### **Reconnaissance**
- Adversaries use OSINT to gather publicly available information about the target from but not limited to: search engines, public media, social media accounts, forums/blogs, public records, WHOIS, harvesting information.
- Passive Reconnaissance: No direct interaction with the target. 
- Active Reconnaissance: Varying types of contact: social engineering, port scanning, banner grabbing, probing.
- Some harvesting tools include but are not limited to: [theHarvester](https://github.com/laramies/theHarvester), [Hunter.io](https://hunter.io/), [OSINT Framework](https://osintframework.com/).
	
>❔ What is the name of the Intel Gathering Tool that is a web-based interface to the common tools and resources for open-source intelligence?
> > OSINT Framework

>❔ What is the definition for the email gathering process during the stage of reconnaissance?
> > email harvesting

### **Weaponization**
- The attacker makes use of tools to craft a malicious package to be delivered to a victim.
	
>❔ What is the term for automated scripts embedded in Microsoft Office documents that can be used to perform tasks or exploited by attackers for malicious purposes?
> > Macros

### **Delivery**
- Refers to the method used to deliver the payload/malware into the target environment.
	
>❔ What do you call an attack targeting a specific group by infecting their frequently visited website?
> > Watering Hole Attack  

### **Exploitation**
- The moment the malicious is triggered and runs on the target's environment.
	
>❔ What is the term for a cyber attack that exploits a software vulnerability that is unknown by software vendors?
> > Zero-day

### **Installation**
- Refers to techniques and tools an attacker may use or install on the target system to achieve persistence and eventually their end goal.
	
>❔ What technique is used to modify file time attributes to hide new or changes to existing files?
> > Timestomping

>❔ What malicious script can be planted by an attacker on the web server to maintain access to the compromised system and enables the web server to be accessed remotely?
> > Web Shell

### **Command & Control**
- After getting persistence and executing the malware on the victim's machine, the attacker opens up the C2 channel through the malware to remotely control and manipulate the victim.
	
>❔ What is the C2 communication where the victim makes regular DNS requests to a DNS server and domain which belong to an attacker.
> > DNS Tunneling

### **Actions on Objectives (Exfiltration)**
- After all stages were successful, the attacker can now achieve his end goal and exfiltrate data.
- Ex: Steal crendentials, privilege escalation, internal reconn, lateral movement, exfiltration, corrupt backups etc.
	  
>❔ What technology is included in Microsoft Windows that can create backup copies or snapshots of files or volumes on the computer, even when they are in use?
> > Shadow Copy

**Practice Analysis**
>❔ What is the flag after you complete the static site?
> > THM{7HR347_1N73L_12_4w35om3}
