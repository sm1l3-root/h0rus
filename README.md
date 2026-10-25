# 🦅 h0rus - Community Edition
Network Topology Generator , Ghost Node And Role Finder And Pivot Score Generating Penetration Testing Network Scanning analyzing and auto-decide featured Tool that makes 2 or 3 weeks job just in a few minutes   

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0.en.html)
[![Release](https://img.shields.io/badge/version-v1.0.0--alpha-red.svg)](#)

> **h0rus** is an autonomous recognition and network analysis framework that transforms passive **Nmap, Traceroute, DNS, ARP, and OS command outputs** into actionable intelligence. By leveraging **Weighted Jaccard Similarity** and **Bayesian Network Theorems**, h0rus classifies host roles, detects **TTL/Hop anomalies**, and identifies hidden **Ghost Nodes** through dependency matrices.
>
> Built with a custom mathematical formula (**PivotScore**), h0rus automatically determines the most strategic target for lateral movement—turning **2 to 3 weeks of manual reconnaissance into 2 to 3 minutes**.
<img width="1458" height="716" alt="Image" src="https://github.com/user-attachments/assets/43474534-dbeb-48d2-8443-72c6e52ecb6c" />
---
## 📌 Why h0rus?

Existing network discovery tools either produce static, uncontextualized topology diagrams (like Zenmap) or demand invasive agent installations and credentialed domain access (like BloodHound);
Also neither them is using h0rus's methodology to inspecting network, BloodHound is only searches Active Directory machines but h0rus make his decisions by ttl,  port and role dependency so h0rus is able to detect non-AD machines also;
	

**h0rus**:
- **Zero-Dependency Parser:** Parses Nmap XML and Traceroute logs using pure Python without NPSL licensing conflicts.
- **h0rus is also able to use OS data for generating a topology unlike other network scanners**
- **Mathematical Role Inference:** Classifies node roles (e.g., Domain Controller, Gateway, Database) using statistical **Weighted Jaccard** similarity scores instead of rigid hardcoded guesses.
- **Ghost Node & Pivot Analysis:** Uncovers hidden nodes that do not directly respond to scans but create traffic dependencies with **Bayes Network Theorem** and dependency matrices, also operator has all control on the parameters and able to edit through the files. 
- **Calculating a PivotScore:** for Red Teaming scenarios h0rus is able to calculate a pivotscore and arrange the nodes sizes by the score for a Red Team operator to select the most strategical lateral movement node in seconds 
- **Finding Vulnerabilities:** h0rus is able to find known vulnerabilities by searching nodes ports services in Searchsploit DB publicly open exploit db without without any interruptions to the license intervals with its own parser and writes to an output file 
-**Password Spray Attack:** h0rus is able to detect ssh and smb services and make a password spray attack on those ip addresses
  
!!!The files that you want to look at for optimizing statistical part of the h0rus

	/rolefinder/dns2role.json
	/rolefinder/port2role.json
	/relation/dependencyMatrix.json
	/relation/cpd_tables.json
	/pivotscore/role_score.json
---

## What is a pivotscore and how it is working?

<img width="1836" height="857" alt="Image" src="https://github.com/user-attachments/assets/a3528546-9a5a-41ac-8bf5-5119611975ea" />

pivotscore is a mathematical formule that i invented that determines a devices criticallity to attack for a Red Team operator automaticly.

formule: 

<img width="362" height="316" alt="Image" src="https://github.com/user-attachments/assets/2bb5bd0d-04a0-4ac2-bc59-dfea2fcd13de" />

But How?

formule works in a very simple way, if a devices ghost nodes is valuable and the count of this valuable nodes are more than other devices the formule grows exponantially because of "the power of" method 
and the power of (ghosts value scores role mean) is a really big number so i use a sqrt on the power to limit its growing potential 

---

<img width="1848" height="867" alt="Image" src="https://github.com/user-attachments/assets/93475251-cce3-463d-b96b-147f82f984ad" />

##  Topographic Visualization Rules

The generated dynamic HTML/Canvas topology map applies the following visual semantics:

* 🔴 **Red Nodes:** Active devices analyzed by the **GhostBuster Engine**.
* 🌟 **Star-Shaped Nodes:** Discovered **Ghost Nodes** (unresponsive or hidden targets).
* 📐 **Node Sizing:** Node size scales proportionally with its calculated **PivotScore**. Larger nodes signify prime candidates for lateral movement.
* 🖱️ **Interactive Hover:** Hovering over any node displays its inferred role , open ports , OS , interface data and exact PivotScore .

---


## 🚀 Quick Start

### Prerequisites
- **Python 3.9+**
- **Nmap** installed and added to your system `PATH`
- Administrator / Root privileges (recommended for raw SYN scans and OS fingerprinting)

### Installation & Execution

1. Clone the repository:
   ```bash
   git clone [https://github.com/sm1l3-root/h0rus.git](https://github.com/sm1l3-root/h0rus.git)
   cd h0rus
Install Python dependencies:

Bash
pip install -r requirements.txt
Run the primary analysis script:

Bash
python h0rus.py
Open the generated interactive topology file in your browser and check the terminal execution logs for matched offline exploits.


## 🗺️ Roadmap & Future Enhancements

We are actively developing **h0rus** to expand its threat-hunting capabilities, analytical precision, and integration ecosystem. Below is the feature matrix planned for upcoming releases:

### 🟢 Short-Term (v1.0.1-beta)
- [ ] **Dynamic Exploit Severity Scoring:** Integrate CVSS v3.1 criticality mapping (Critical, High, Medium) directly into matched Searchsploit/Exploit-DB vulnerabilities.
- [ ] **Adding the linux command outputs and parseing the outputs for relationfinder
### 🟡 Mid-Term (v1.5.0-stable)
- [ ] **Making a lightweight executable script version 
- [ ] **with this lightweight version you able to add new hacked machines topologies to the main start-toplogy 

### 🔴 Enterprise Roadmap (Commercial Version)
- [ ] **there is no public information for this section right now

---

##Some Details!!!
- Normally h0rus is able to run in both linux and windows systems but right now its able to RUN ON just windows machines
- Also h0rusus datasets are right now configured to my vm test machines so you might wanna change the given files in the first section!!!

Developer: Efe Dora Cankardeş -> sm1l3

Project Status: v1.0.0-alpha (Public Alpha)

Pull requests and issue reports are welcome! For major architectural changes, please open an issue first to discuss what you would like to change.


🛡️ License & Commercial Licensing
This project is open-source and licensed under the GNU Affero General Public License v3 (AGPLv3).

*For commercial licensing options, enterprise features, custom integrations, or proprietary distribution, please contact:*  
**Efe Dora Cankardeş** - [LinkedIn]
