import pyfiglet
from colorama import Fore, Style, init

# Tüm modül import'larını en başta yapıyoruz
from scan.nmapStarter import Run
from scan.nmapAnalyzer import JsonNmap
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
        
    target_network = input("ENTER TARGET NETWORK EX: 192.168.1.0/24 -----> ").strip()
    if not target_network:
        print(Fore.YELLOW + "[!] You Must to enter a target network.")
        return

   
    print(Fore.CYAN + "\n[*] Adım 1: Nmap scan is starting...")
    Run.runnner(target_network)

    print(Fore.CYAN + "[*] Adım 2: Parseing nmap outputs...")
    JsonNmap.JsonNmap()
    JsonNmap.JsonNmap()
    print(Fore.CYAN + "[*] Adım 3: Running System Commands...")
    Write.writeJson()
    print(Fore.CYAN + "[*] Adım 4: parsing json for rolefinder...")
    ParserforRolefinder.writeJson("rolefinder/outputforport2role.json") 

    print(Fore.CYAN + "[*] Adım 5: parsing data for ghostbuster...")
    Json.role2json()

    print(Fore.CYAN + "[*] Adım 6: Ghostbuster is catching the ghosts...")
    GhostBuster.ScanTESTS()

    print(Fore.CYAN + "[*] Adım 7: PivotScore Calculating...")
    PivotScore.Calculate()

    print(Fore.CYAN + "[*] Adım 8: Node and Edges are calculating...")
    gui.generate_topology_map(NodeEdge.CollectGs(),outputfile)
    print(Fore.GREEN + "\n[+] known vulnerabilities in services are saved in knownVulns.txt!!!")
    print(Fore.GREEN + "\n[+] h0rus successfully runned!")

if __name__ == "__main__":
    main()