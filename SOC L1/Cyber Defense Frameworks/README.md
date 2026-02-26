# Cyber Defense Framework
## Pyramid of Pain
The pyramid of pain illustrates the varying levels of difficulty and cost an adversary would encounter to evade detection and continue their attack.<br>
Ex: Hashes are easy to modify to hide an attack/tool/script but not TTPs (Techniques Tactics Procedures)
![[Pasted image 20260219112804.png]]
Ref: [What Is Pyramid of Pain in Cybersecurity? | Picus](https://www.picussecurity.com/resource/glossary/what-is-pyramid-of-pain)
Levels:
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

