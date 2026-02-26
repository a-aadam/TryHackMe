# Cyber Defense Framework
<details>
<summary><h2><strong>Pyramid of Pain</strong></h2></summary>
The pyramid of pain illustrates the varying levels of difficulty and cost an adversary would encounter to evade detection and continue their attack.<br>
Ex: Hashes are easy to modify to hide an attack/tool/script but not TTPs (Techniques Tactics Procedures)<br>
<br><img width="500" height="628" alt="CyberDefFrameworkFigure1" src="https://github.com/user-attachments/assets/99d16086-d4b1-4ab2-8c06-f095a5d307af" /><br>
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
</details>

---
<details>
<summary><h2><strong>Cyber Kill Chain</strong></h2></summary>
The Cyber Kill Chain consists of target identification, decision and order to attack the target, and target destruction.
It is the roadmap and attacker takes for a successful attack. Understanding this maps helps defenders understand where and what to look as well as what to secure.
<br><br><img height="500" alt="CyberDefFrameworkFigure2" src="https://github.com/user-attachments/assets/210aca53-2486-4fb3-ab5e-9bccdf4d07c7" /><br>
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

### **Practice Analysis**
- Complete the interactive task.
>❔ What is the flag after you complete the static site?
> > THM{7HR347_1N73L_12_4w35om3}

</details>

---
<details>
<summary><h2><strong>Unified Kill Chain</strong></h2></summary>

## **What is a "Kill Chain"**
- The term originates from the military.
- It is used to explain the different stages of an attack: methodology, path used to approach and penetrate a target.
- Ex: scanning, vulnerability exploit, privilege escalation...
> Where does the term "Kill Chain" originate from?
> > Military

### **What is "Threat Modelling"**
- It is a set of steps (to identity risks) used to improve the security of a system.
	
1. Identify the systems and applications that need to be secured and identify their function within their environment.
   Ex: How critical they are. Are they hosting sensitive information.
2. Asses the vulnerabilities and weaknesses of the systems and applications identified as well as how they may be exploited.
3. Create an action plan to secure these systems and applications.
4. Set policies to prevent vulnerabilities from occurring.
	Ex: Set SDLC, Patching policies, employee trainings.
	
- Threat Modelling provides a high-level overview of an organization's IT assets and procedures.
- The UKC encourages threat modelling through identification of potential attack surfaces and exploits.
	
> What is the technical term for a piece of software or hardware in IT (Information Technology?)
> > Asset

### **Introduction to Unified Kill Chain**
- Paul Pols' [Unified Kill Chain,](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) (20170, aims to complement (not compete with) other cybersecurity kill chain frameworks. UKC identifies 18 phases of an attack which is its main advantage compared to other traditional framework.

<img width="500" alt="CyberDefFrameworkFigure3" src="https://github.com/user-attachments/assets/e72440a3-38cc-4bef-b780-97de4c073f3e" /><br><br>

| **Benefits of the Unified Kill Chain (UKC) Framework**                                                                                                                                                | **How do Other Frameworks Compare?**                                                                                              |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Modern (released in 2017, updated in 2022).                                                                                                                                                           | Some frameworks, such as MITRE’s were released in 2013, when the cybersecurity landscape was very different.                      |
| The UKC is extremely detailed (18 phases).                                                                                                                                                            | Other frameworks often have a small handful of phases.                                                                            |
| The UKC covers an entire attack - from reconnaissance, exploitation, post-exploitation and includes identifying an attacker's motivation.                                                             | Other frameworks cover a limited amount of phases.                                                                                |
| The UKC highlights a much more realistic attack scenario. Various stages will often re-occur. For example, after exploiting a machine, an attacker will begin reconnaissance to pivot another system. | Other frameworks do not account for the fact that an attacker will go back and forth between the various phases during an attack. |

<br>

> In what year was the Unified Kill Chain framework released?
> > 2017

> According to the Unified Kill Chain, how many phases are there to an attack?
> > 18

> What is the name of the attack phase where an attacker employs techniques to evade detection?
> > Defense Evasion

> What is the name of the attack phase where an attacker employs techniques to remove data from a network?
> > Exfiltration

> What is the name of the attack phase where an attacker achieves their objectives?
> > Objectives

### **Phase: In (Initial Foothold)**
<br><img width="500" alt="CyberDefFrameworkFigure4" src="https://github.com/user-attachments/assets/c059b9c1-a902-4302-9d68-f1f45bc587a7" /><br>


Phases though which an attacker may gain access to an environment:
	
- **Reconnaissance**: Gather information about their target system. It can be either passive or active.<br>
		Ex: Discover what systems or services are running and which ones may be exploited. Find employee details for phishing/social engineering. Finding credentials to be used later. Understand network topology and infrastructure to be used for pivoting.
	
- **Weaponization**: the attacker getting ready for the attack my preparing their tools, exfiltration servers, etc.
	
- **Social Engineering**: Manipulate employees into performing certain actions.<br>
		Ex: Getting a user to open a malicious attachment. Stealing credentials through a spoofed webpage. 
	
- **Exploitation**:The attacker abuses a vulnerability of a system.<br>
		Ex: Execution of reverse shells, putting the victim machine on a C2 server for RCE.
	
- **Persistence**: Ways by which an attacker maintains access to the victim machine.<br>
		Ex: Creating a service that allows an attacker to regain access, putting the victim machine on a C2 server for RCE at any time, leaving backdoors.
	
- **Defense Evasion**: Ways by which attacker bypasses defense systems.
	
- **Command & Control**: Establishes communication between the target machine and the attacker's machine to achieve various goals.<br>
		Ex: Execute code, steal data, credentials and other valuable information, for lateral movement.
	
- **Pivoting**: Method by which an attacker moves from the target machine to other machine within the same environment.
	
> What is an example of a tactic to gain a foothold using emails?
> > Phishing

> Impersonating an employee to request a password reset is a form of what?
> > Social Engineering

> An adversary setting up the Command & Control server infrastructure is what phase of the Unified Kill Chain?
> > Weaponization

> Exploiting a vulnerability present on a system is what phase of the Unified Kill Chain?
> > Exploitation

> Moving from one system to another is an example of?
> > Pivoting

> Leaving behind a malicious service that allows the adversary to log back into the target is what?
> > Persistence

### **Phase: Through (Network Propagation)**
<br><img width="500" alt="CyberDefFrameworkFigure5" src="https://github.com/user-attachments/assets/f0ec6c74-97ed-4d68-8252-345586578eff" /><br>

After a successful foothold was established, an attacker would set up one of the system as pivot to gather information about the network.
	
- **Pivot**: After a system was accessed, it may be used as staging site and a tunnel between their command operations (attacker's machine) and the target network as well as using it for any further malicious distributions within the victim network.
	
- **Discovery**: Aims at discovering information about the target system. The attacker would learn about the active users, permissions, applications and software, activity, files, directory, etc...
	
- **Privilege Escalation**: After discovery (and knowledge gathering), an attacker would leverage the information gathered about accounts, vulnerabilities, misconfigurations to elevate their access permissions.
	
- **Execution**: The deployment of payloads, especially for persistence (at this stage).
	
- **Credentials Access**: Along with privilege escalation, the attacker would try to steal account information through various methods.
	
- **Lateral Movement**: Using the obtained credentials from Credentials Access, the attacker would attempt to move to other machines on the network.
> As a SOC analyst, you pick up an alert pointing to failed logins from an administrator account.  What phase of the Unified Kill Chain would an attacker be seeking to achieve? 
> > Privilege Escalation

> Mimikatz, a known post-exploitation tool, was detected on the IT Manager's workstation. The Security logs show that the tool was attempting to dump OS and user secrets. Which Unified Kill Chain phase does this activity correspond to? 
> > Credential Access

### **Phase: Out (Action on Objectives)**: 
- After obtaining enough critical access, the attack would then conduct their end goal (compromising CIA)

### **Collection** 
- Gather data and information of interest.<br>Ex. Drives, browser data, audio video, e-mails, files.
### **Exfiltration**
- Steal data, usually compressed and encrypted to avoid detection and sent through a tunnel/C2.
### **Impact** 
- An attacker may manipulate, interrupt or destroy the assets which they compromised.
### **Objectives** 
With all the gathered power, the attacker would then seek to achieve their organizational goal.
The “Kill Chain” is used to describe the methodology/path attackers such as hackers or APTs use to approach and intrude a target.
Threat modelling are the steps to identify risks, aiming to improve the security of a system. It includes:
- Identifying the systems and application that need to be secured.
- Identify the function of the systems and applications within the environment.

> While monitoring the network as a SOC analyst, you observe a big traffic spike. Most of the network traffic is sent to an unknown, suspicious IP address.  What Unified Kill Chain phase could describe this activity?
> > Exfiltration

> Personally identifiable information (PII) has been released to the public by an adversary. Your organisation is facing reputational losses and scrutiny for the breach. What part of the CIA triad would be affected by this action?
> > Confidentiality

### **Practical**
Complete the interactive task.
> Match the scenario prompt to the correct phase of the Unified Kill Chain to reveal the flag at the end. What is the flag?
> > THM{UKC_SCENARIO}

</details>

---

<details>
<summary><h2><strong>MITRE</strong></h2></summary>
MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK)<br>

### **ATT&CK Framework**


- A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.
	- [Tactic](https://attack.mitre.org/tactics/enterprise/): An adversary's goal or objective. The “why” of an attack.
	- [Technique](https://attack.mitre.org/techniques/enterprise/): How an adversary achieves their goal or objective.
	- Procedure: The implementation or how the technique is executed.
- The [MITRE ATT&CK Matrix](https://attack.mitre.org/matrices/) is a powerful visual representation of all tactics and techniques that exist within the framework.
-  You can also utilize the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/), a handy tool for annotating and exploring matrices.
	
> What Tactic does the Hide Artifacts technique belong to in the ATT&CK Matrix?
> > Defense Evasion

> Which ID is associated with the Create Account technique?
> > T1136

### **ATT&CK in Operation**
- Through mapping threat activity to TTPs, defenders can translate intelligence into real detection logic, queries, and playbooks.

| Who                                   | Their Goal                                                                           | How They Use ATT&CK                                                                                          |
| ------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| Cyber Threat Intelligence (CTI) Teams | Collect and analyze threat information to improve an organization's security posture | Map observed threat actor behavior to ATT&CK TTPs to create profiles that are actionable across the industry |
| SOC Analysts                          | Investigate and triage security alerts                                               | Link activity to tactics and techniques to provide detailed context for alerts and prioritize incidents      |
| Detection Engineers                   | Design and improve detection systems                                                 | Map SIEM/EDR and other rules to ATT&CK to ensure better detection efforts                                    |
| Incident Responders                   | Respond to and investigate security incidents                                        | Map incident timelines to MITRE tactics and techniques to better visualize the attack.                       |
| Red & Purple Teams                    | Emulate adversary behavior to test and improve defenses                              | Build emulation plans and exercises aligned with techniques and known group operations                       |
> In which country is Mustang Panda based?
> > China

> Which ATT&CK technique ID maps to Mustang Panda’s Reconnaissance tactics?
> > T1598

> Which software is Mustang Panda known to use for Access Token Manipulation?
> > Cobalt Strike

### **ATT&CK for Threat Intelligence**
- Groups that might target your organization can be found from [Groups](https://attack.mitre.org/groups/)
	
> Which APT group has targeted the aviation sector and has been active since at least 2013?
> > APT33

> Which ATT&CK sub-technique used by this group is a key area of concern for companies using Office 365?
> > Cloud Accounts

> According to ATT&CK, what tool is linked to the APT group and the sub-technique you identified?
> >

> Which mitigation strategy advises removing inactive or unused accounts to reduce exposure to this sub-technique?
> > User Account Management

> What Detection Strategy ID would you implement to detect abused or compromised cloud accounts?
> > DET0546

### **Cyber Analytics Repository (CAR)**
- The MITRE Corporation Cyber Analytics Repository (CAR) is a publicly available knowledge base/collection of analytic rules and detection patterns mapped to the  ATT&CK framework to help security teams detect and respond to adversary behaviors.
- [Analytics | MITRE Cyber Analytics Repository](https://car.mitre.org/analytics/)
- CAR [ATT&CK Navigator layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/mitre-attack/car/master/docs/coverage/car_analytic_coverage_04_05_2022.json)
	
> Which ATT&CK Tactic is associated with [CAR-2019-07-001](https://car.mitre.org/analytics/CAR-2019-07-001/)?
> > Defense Evasion

> What is the Analytic Type for Access Permission Modification?
> > Situational Awareness

### **MITRE D3FEND Framework**
- D3FEND: Detection, Denial, and Disruption Framework Empowering Network Defense
- A structured framework that maps out defensive techniques and establishes a common language for describing how security controls work.
	- How the proposed defense works.
	- Considerations for implementation.
	- Relation with digital artifacts.
	- 
<img width="500" alt="CyberDefFrameworkFigure6" src="https://github.com/user-attachments/assets/a2ef802b-6da6-4b29-8cbd-8b528fe7d96d" />

- [D3FEND Matrix | MITRE D3FEND™](https://d3fend.mitre.org/)

	
> Which sub-technique of [User Behavior Analysis](https://d3fend.mitre.org/technique/d3f:UserBehaviorAnalysis/) would you use to analyze the geolocation data of user logon attempts?
> > User Geolocation Logon Pattern Analysis

> Which digital artifact does this sub-technique rely on analyzing?
> > Network Traffic

### **Other MITRE Projects**

#### **Emulation Plans**
- MITRE's [Adversary Emulation Library](https://ctid.mitre.org/resources/adversary-emulation-library/), primarily maintained and contributed to by The Center for Threat Informed Defense ([CTID](https://ctid.mitre.org/)), is a free resource of adversary emulation plans whose [library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library) currently contains several emulations that mimic step-by-step real-world attacks by known threat groups.
#### **Caldera**
- [Caldera](https://caldera.mitre.org/) is an automated adversary emulation tool providing the ability to simulate real-world attacker behavior utilizing the ATT&CK framework and designed to help security teams test and enhance their defenses.
- It allows defenders to evaluate detection methods and IR.
#### **New and Emerging Frameworks**
- [AADAPT](https://aadapt.mitre.org/) (Adversarial Actions in Digital Asset Payment Technologies) is a newly released knowledge base that includes its own matrix, covering adversary tactics and techniques related to digital asset management systems.
- [ATLAS](https://atlas.mitre.org/) (Adversarial Threat Landscape for Artificial-Intelligence Systems) is a knowledge base and framework that includes a [matrix](https://atlas.mitre.org/matrices/ATLAS), focusing on threats targeting artificial intelligence and machine learning systems.






















</details>
