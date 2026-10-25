import pyfiglet
from colorama import Fore, Style, init

# Tüm modül import'larını en başta yapıyoruz
from scan.nmapStarter import Run
from scan.nmapAnalyzer import JsonNmap
from scan.nmapOs2target import os2target
from scan.passwordSpray import sshSpray
from scan.passwordSpray import smbSpray
from rolefinder.parser import ParserforRolefinder
from rolefinder.Results2buster import Json
from relation.GhostBuster import GhostBuster
from pivotscore.PivotScore import PivotScore
from report.NodeEdge import NodeEdge
from report.gui import gui
from osdetect.JsonParser import Write

# Colorama başlatma
init(autoreset=True)

def main():
    
    ascii_banner = pyfiglet.figlet_format("welcome to h0rus ! !", font="graffiti")
    print(Fore.RED + Style.BRIGHT + ascii_banner)
    
    outputfile = input("ENTER OUTPUT FILE NAME EX: horus_out.html -----> ")
    if not outputfile.strip():
        print(Fore.YELLOW + "[!] YOU MUST ENTER A OUTPUT FILE!!!")
        return
    if not outputfile.lower().endswith((".html")):
        outputfile += ".html"
        
    target_network = input("ENTER TARGET NETWORK SUBNET EX: 192.168.1.0/24 -----> ").strip()
    if not target_network:
        print(Fore.YELLOW + "[!] You Must to enter a target network.")
        return

   
    print(Fore.CYAN + "\n[*] Running System Commands...")
    Write.writeJson()
    

    print(Fore.CYAN + "[*] Parseing outputs...")
    os2target.main()
    print(Fore.CYAN + "[*] Nmap scan is starting...")
    Run.runnner(target_network)
    JsonNmap.JsonNmap()
    JsonNmap.JsonNmap()
    print(Fore.CYAN + "[*] ssh password spray is starting...")
    sshSpray.spray()
    print(Fore.CYAN + "[*] smb password spray is starting...")
    smbSpray.spray()
    print(Fore.CYAN + "you can get the password spray results on the scan/sshPasSprayresults.txt and scan/smbPasSprayresults.txt files ")
    print(Fore.CYAN + "[*] parsing json for rolefinder...")
    ParserforRolefinder.writeJson("rolefinder/outputforport2role.json") 

    print(Fore.CYAN + "[*] parsing data for ghostbuster...")
    Json.role2json()

    print(Fore.CYAN + "[*] Ghostbuster is catching the ghosts...")
    GhostBuster.ScanTESTS()

    print(Fore.CYAN + "[*] PivotScore Calculating...")
    PivotScore.Calculate()

    print(Fore.CYAN + "[*] Node and Edges are calculating...")
    gui.generate_topology_map(NodeEdge.CollectGs(),outputfile)
    print(Fore.GREEN + "\n[+] known vulnerabilities in services are saved in knownVulns.txt!!!")
    print(Fore.GREEN + "\n[+] h0rus successfully runned!")

if __name__ == "__main__":
    main()