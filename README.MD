# 🦅 h0rus - Community Edition 
Network Topology Generator , Ghost Node And Role Finder, Pivot Score Generating Penetration Testing Network Scanning , analyzing and auto-decide featured Tool that makes 2 or 3 weeks manuel job in 2-3 minutes   

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0.en.html)
[![Release](https://img.shields.io/badge/version-v0.9.0--alpha-red.svg)](#)


> **h0rus** is an autonomous recognition and network analysis framework that transforms passive **Nmap, Traceroute, DNS, ARP, and OS command outputs** into actionable intelligence. By leveraging **Weighted Jaccard Similarity** and **Bayesian Network Theorems**, h0rus classifies host roles, detects **TTL/Hop anomalies**, and identifies hidden **Ghost Nodes** through dependency matrices.
>
> Built with a custom mathematical formula (**PivotScore**), h0rus automatically determines the most strategic target for lateral movement—turning **2 to 3 weeks of manual reconnaissance into 2 to 3 minutes**.

<img width="1458" height="716" alt="Image" src="https://github.com/user-attachments/assets/98a4e3d4-525a-448c-a07c-e1a552370079" />
---
## 📌 Why h0rus?

Existing network discovery tools either produce static, uncontextualized topology diagrams (like Zenmap) or demand invasive agent installations and credentialed domain access (like BloodHound);
Also neither them is using h0rus methodology to inspecting network, BloodHound is only searches Active Directory machines but h0rus make his decisions by ttl,  port and role dependency so h0rus is able to detect non-AD machines also;
	

**h0rus**:
- **Zero-Dependency Parser:** Parses Nmap XML and Traceroute logs using pure Python without NPSL licensing conflicts.
- **h0rus is able to use OS data for generating a topology
- **Mathematical Role Inference:** Classifies node roles (e.g., Domain Controller, Gateway, Database) using statistical **Weighted Jaccard** similarity scores instead of rigid hardcoded guesses.
- **Ghost Node & Pivot Analysis:** Uncovers hidden nodes that do not directly respond to scans but create traffic dependencies with **Bayes Network Theorem** and dependency matrices, also operator has all control on the parameters and able to edit through the files. 
- **Calculating a **PivotScore: ** for Red Teaming and Threat Hunting scenarios h0rus is able to calculate a pivotscore and arrange the nodes sizes by the score for a Red Team operator to select the most strategical lateral movement node in seconds 

---

## What is a pivotscore and how it is working?

pivotscore is a mathematical formule that i invented that determines a devices criticallity to attack for a Red Team operator automaticly.

### Mathematical Formulation

<img width="362" height="316" alt="Image" src="https://github.com/user-attachments/assets/08e57774-5e6d-41ab-a081-be5c1ee92974" />

But How?

formule works in a very simple way, if a devices ghost nodes is valuable and the count of this valuable nodes are more than other devices the formule grows exponantially because of "the power of" method 
and the power of (ghosts value scores role mean) is a really big number so i use a sqrt on the power to limit its growing potential 

<img width="1600" height="746" alt="Image" src="https://github.com/user-attachments/assets/c31ca4f6-bbf6-4852-8426-a983f5f6912d" />
---

## 🖥️ Topographic Visualization Rules
<img width="1600" height="750" alt="Image" src="https://github.com/user-attachments/assets/d04c6e5b-4e47-4612-81ba-e90d1d0c940e" />
The generated dynamic HTML/Canvas topology map applies the following visual semantics:

* 🔴 **Red Nodes:** Active devices analyzed by the **GhostBuster Engine**.
* 🌟 **Star-Shaped Nodes:** Discovered **Ghost Nodes** (unresponsive or hidden targets).
* 📐 **Node Sizing:** Node size scales proportionally with its calculated **PivotScore**. Larger nodes signify prime candidates for lateral movement.
* 🖱️ **Interactive Hover:** Hovering over any node displays its inferred role and exact PivotScore.

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

### 🟢 Short-Term (v0.9.5-beta)
- [ ] **Dynamic Exploit Severity Scoring:** Integrate CVSS v3.1 criticality mapping (Critical, High, Medium) directly into matched Searchsploit/Exploit-DB vulnerabilities.
- [ ] **Advanced CLI Argument Parsing:** Migration to robust `argparse` execution flags (e.g., `python h0rus.py -t 192.168.1.0/24 --output json`).
- [ ] **Graceful Error & Guard Clauses:** Enhanced fallback mechanisms for single-host topologies, empty ARP tables, and unprivileged raw socket execution.
- [ ] **Adding interface names to the topology for arp interfaces and categorys them automaticly
- [ ] **Adding the linux command outputs and parseing the outputs for relationfinder
### 🟡 Mid-Term (v1.0.0-stable)
- [ ] **Running GhostBuster and PivotScore algorithms on OS relation data 
- [ ] **Making a lightweight executable script version 
- [ ] **with this lightweight version you able to add new hacked machines topologies to the main start-toplogy 

### 🔴 Enterprise Roadmap (Commercial Version)
- [ ] **there is no public information for this section right now

---

##Some Details!
- Normally h0rus is able to run in both linux and windows systems but right now its able to RUN ON just windows machines
- Vulnerability matching heuristics utilize publicly available exploit metadata sourced from the OffSec Exploit-DB / Searchsploit archive.
## ⚠️ Legal & Ethical Disclaimer

**h0rus** is developed strictly for educational, threat hunting, and authorized penetration testing purposes only. The developer (Efe Dora Cankardeş) assumes no liability and is not responsible for any misuse, unauthorized network scanning, or damage caused by this utility. Users are solely responsible for complying with all applicable local, state, and federal security laws before executing scans against any network assets.
Developer: Efe Dora Cankardeş -> sm1l3

Project Status: v0.9.0-alpha (Public Alpha)

Pull requests and issue reports are welcome! For major architectural changes, please open an issue first to discuss what you would like to change.


🛡️ License & Commercial Licensing
This project is open-source and licensed under the GNU Affero General Public License v3 (AGPLv3).

*For commercial licensing options, enterprise features, custom integrations, or proprietary distribution, please contact:*  
**Efe Dora Cankardeş** - [https://www.linkedin.com/in/efe-dora-cankarde%C5%9F-389444218]
