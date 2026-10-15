from osdetect.osdetect import OsDetection
import os 
import subprocess
import sys
import re

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
                    ps_code = "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue).NextHop | Where-Object { $_ -ne '0.0.0.0' } | ConvertTo-Json"

                        
                                        
                    output = subprocess.check_output(["powershell.exe", "-Command", ps_code], text=True, errors="ignore")
                    return f"\n++\n"+output
                
                def arp():
                    ps_code = "$localIPs = (Get-NetIPAddress -AddressFamily IPv4).IPAddress; Get-NetNeighbor -AddressFamily IPv4 -State Reachable,Stale | Where-Object { $_.IPAddress -notlike '224*' -and $_.IPAddress -notlike '239*' -and $_.IPAddress -notlike '255*' -and $localIPs -notcontains $_.IPAddress } | Group-Object InterfaceAlias | ForEach-Object { $alias = $_.Name; $ipConfig = Get-NetIPConfiguration -InterfaceAlias $alias -ErrorAction SilentlyContinue; [PSCustomObject]@{ Interface = $alias; LocalIP = $ipConfig.IPv4Address.IPAddress; DynamicIPs = ($_.Group.IPAddress | Select-Object -Unique) } } | ConvertTo-Json -Depth 3"
                        
                                        
                    output = subprocess.check_output(["powershell.exe", "-Command", ps_code], text=True, errors="ignore")
                    return f"\n+\n"+output
                
                def NetNeighbor():
                    
                    ps_code = "Get-NetNeighbor -State Reachable,Stale | Where-Object { $_.IPAddress -notlike '224*' -and $_.IPAddress -notlike '239*' -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike 'ff02*' } | Select-Object -ExpandProperty IPAddress | Select-Object -Unique | ConvertTo-Json"
   
                    
                    output = subprocess.check_output(["powershell.exe", "-Command", ps_code], text=True, errors="ignore")
                    return f"\n++++\n"+output
                    
                def NetIpConfiguration():
                    ps_code = "Get-NetIPConfiguration | Select-Object InterfaceAlias, @{N='IPv4Addresses';E={$_.IPv4Address.IPAddress}}, @{N='DNSServers';E={$_.DNSServer.ServerAddresses}} | ConvertTo-Json -Depth 3"
                       
                                        
                    output = subprocess.check_output(["powershell.exe", "-Command", ps_code], text=True, errors="ignore")
                    return f"\n+++++\n"+output
                
                def NetTcpConnection():
                    ps_code = "Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '127.0.0.1' -and $_.LocalAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1' -and $_.LocalAddress -ne '::1' } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort | ConvertTo-Json"                       
                                        
                    output = subprocess.check_output(["powershell.exe", "-Command", ps_code], text=True, errors="ignore")
                    return f"\n++++++\n"+output
                def NetRoute():
                    ps_code = "Get-NetRoute | Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.NextHop -ne '::' -and $_.NextHop -notlike '127.*' -and $_.NextHop -notlike '224.*' -and $_.NextHop -notlike '239.*' -and $_.NextHop -ne $_.DestinationPrefix.Split('/')[0] } | Select-Object DestinationPrefix, NextHop | ConvertTo-Json"
                                       
                    output = subprocess.check_output(["powershell.exe", "-Command", ps_code], text=True, errors="ignore")
                    return f"\n+++\n"+output

                
                def forRegex():
                    return "\n+++++++\n"

                
                
                return arp()+ipconfig()+NetRoute()+NetNeighbor()+NetIpConfiguration()+NetTcpConnection()+forRegex()
                
               
            return WinRun()
        else:
            print("error win")
            
    #WinCommands()
    