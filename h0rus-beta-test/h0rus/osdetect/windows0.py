from osdetect import OsDetection
import os 
import subprocess
import sys
import re
import json 

class IfWin():
    def WinCommands():
        #print (OsDetection.detect())
        if OsDetection.detect() == "win":
            def WinRun():
                #ipconfig
                #arp -a
                #powershell.exe Get-NetRoute
                #powershell.exe Get-NetNeighbor
                #powershell.exe Get-NetIpConfiguration
                #powershell.exe Get-NetTcpConnection
                def ipconfig():
                    output = subprocess.check_output(["ipconfig"], text=True, encoding="cp857")
                    #default_gateway = re.search(r"Default Gateway[.\s]+:\s+([0-9.]+)", output)
                    all_v4_gateways = re.findall(r"Default Gateway[.\s:]+([0-9.]+)", output)
                    default_gateway = all_v4_gateways[0] if all_v4_gateways else "Not Found"
                    return "\ndefault gateway="+default_gateway
                
                def arp():
                    output = subprocess.check_output(["arp","-a"], text=True, encoding="cp857")
                    interface= re.findall(r"Interface:\s+([0-9.]+)", output)
                    dynamics=  re.findall(r"([0-9.]+)\s+[a-f0-9-]+\s+dynamic", output, re.IGNORECASE)
                    
                    
                    return f"\ninterfaces={interface}\ndynamic ips={dynamics}"
                
                def NetNeighbor():
                    
                    ps_code = "Get-NetNeighbor -State Reachable,Stale | Where-Object {$_.IPAddress -notlike '224*' -and $_.IPAddress -notlike '239*'} | Select-Object -ExpandProperty IPAddress"
    
                    try:
                        cikti = subprocess.check_output(["powershell.exe", "-Command", ps_code], text=True, errors="ignore")
                        # Boş satırları temizleyip benzersiz IP listesi yap
                        ip_listesi = sorted(list(set(cikti.splitlines())))
                        return f"\nNet Neighbor reachebale and stale={[ip.strip() for ip in ip_listesi if ip.strip()]}"
                    except Exception as e:
                        return f"Hata: {e}"
                    
                def NetIpConfiguration():
                    output= subprocess.check_output(["powershell.exe","Get-NetIpConfiguration"], text=True, encoding="cp857")
                    dns = re.findall(r"DNSServer\s+:\s+\{?([0-9.]+)\}?", output)
                    ip = re.findall(r"IPv4Address\s+:\s+\{?([0-9.]+)\}?", output)
    
                    # InterfaceAlias değerlerini çeker (İki noktadan sonraki ismi alır)
                    alias = re.findall(r"InterfaceAlias\s+:\s+(.+)", output)
                    
                    return f"\nDns Server={dns}\nipv4 addresses={ip}\nInterface Aliases={alias}"
                
                def NetTcpConnection():
                    #output = subprocess.check_output(["powershell.exe"," Get-NetTcpConnection"], text=True, encoding="cp857")
                    ps_cmd = (
                        "Get-NetTCPConnection -State Established | "
                        "Where-Object { "
                        "  $_.RemoteAddress -ne '0.0.0.0' -and "
                        "  $_.RemoteAddress -ne '127.0.0.1' -and "
                        "  $_.LocalAddress -ne '127.0.0.1' -and "
                        "  $_.RemoteAddress -ne '::1' -and "
                        "  $_.LocalAddress -ne '::1' "
                        "} | "
                        "Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort | "
                        "Format-Table -HideTableHeaders"
                        
                    )
    
                    try:
                        output = subprocess.check_output(["powershell.exe", "-Command", ps_cmd], text=True, errors="ignore")
                        return f"\nNet Tcp Connections={[line.strip() for line in output.splitlines() if line.strip()]}"
                    except Exception as e:
                        return f"Hata: {e}"

                def NetRoute():
                    output = subprocess.check_output(["powershell.exe","Get-NetRoute"], text=True, encoding="cp857")
                    
                    try:
                        # PowerShell üzerinden Get-NetRoute komutunu çalıştır
                        cmd = ["powershell", "-Command", "Get-NetRoute | Select-Object DestinationPrefix, NextHop | Format-Table -HideTableHeaders"]
                        cikti = subprocess.check_output(cmd, encoding="cp857", errors="ignore")
        
                        via_ips = set()
        
                        # Çıktıyı satır satır analiz et
                        for satir in cikti.splitlines():
                            # Satırdaki IP adreslerini yakala
                            ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", satir)
            
                            # Eğer satırda en az 2 IP varsa (DestinationPrefix ve NextHop)
                            if len(ips) >= 2:
                                dest_ip = ips[0]
                                next_hop = ips[1]
                
                                # Anlamlı "via" Filtresi:
                                # 1. NextHop '0.0.0.0' (On-Link) olmamalı
                                # 2. Loopback (127.x) veya Multicast (224-239.x) olmamalı
                                # 3. Destination adresi ile NextHop adresi aynı olmamalı
                                if next_hop != "0.0.0.0" and not next_hop.startswith("127.") and not next_hop.startswith("224."):
                                    if dest_ip != next_hop:
                                        via_ips.add(f"Hedef Ağ: {dest_ip} -> via (NextHop): {next_hop}")
                        
                        return f"\nNet Route={via_ips}"

                    except Exception as e:
                        return [f"Hata: {e}"]

                
                
                
                
                return arp()+ipconfig()+NetRoute()+NetNeighbor()+NetIpConfiguration()+NetTcpConnection()
                
               
            return WinRun()
        else:
            print("error win")
            
    WinCommands()
    