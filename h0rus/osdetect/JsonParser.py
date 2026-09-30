from linux import IfLinux
from windows import IfWin
import json
import re
import os

#print(IfLinux.LinCommands())
class Write():
    def writeJson():
        file = open("output.json" ,"w+")
        file.write(IfWin.WinCommands())
        file.close()

    
    writeJson()

class Open():
    
    def openJson():
        file = open("output.json","r+")
        return file.read() 
        file.close()

    openJson()

class Regex():
    
    def regex(start,finish):
        pattern = rf"{re.escape(start)}(.*?){re.escape(finish)}"
        content = Open.openJson()
        match = re.search(pattern,content,re.DOTALL)
    
        if match:
            extract=match.group(1).strip()
            return extract
    
        else:
            return None
        
class Parse():

    
        
        
        
    #print(IfWin.WinCommands())

    def parseJson():


        def Arp():
            s="+"
            f="++"
            data=Regex.regex(s,f)
            Pdata=json.loads(data)
            
            interface=[item.get("Interface") for item in Pdata if item.get("Interface") is not None]
            allLocalip = [item.get("LocalIP") for item in Pdata if item.get("LocalIP") is not None]
            allip = [item.get("DynamicIPs") for item in Pdata if item.get("DynamicIPs") is not None]
            return (
                f"\ninterfaces = \n{str(interface)}\n"
                f"local ips = \n{str(allLocalip)}\n"
                f"Dynamic Ips = \n{str(allip)}"
            )
        def Gateway():
            s="++"
            f="+++"
            data=Regex.regex(s,f)
            cleaned = data.replace('"', '')
            Cdata = cleaned.split()
            #salt veri
            return (f"\nGateway = \n{str(Cdata)}\n")
            
        
        def NetRoute():
            s="+++"
            f="++++"
            data=Regex.regex(s,f)
            Pdata=json.loads(data)
            
            allNextHop= [item.get("NextHop") for item in Pdata if item.get("NextHop") is not None]
            allDestPre= [item.get("DestinationPrefix") for item in Pdata if item.get("DestinationPrefix") is not None]
            return (
                f"Destination Prefixes = \n{str(allDestPre)}\n"
                f"\nNexthops = \n{str(allNextHop)}\n"
                
            )
        
        def NetNeigh():
            s="++++"
            f="+++++"
            data=Regex.regex(s,f)
            
            #salt veri
            cleaned = data.replace('"', '')
            Cdata = cleaned.split()
            return (f"Net Neighbors = \n{str(Cdata)}\n")
        
        def NetIpConf():
            s="+++++"
            f="++++++"
            data=Regex.regex(s,f)
            Pdata=json.loads(data)
          
            allinterfaces = [item.get("InterfaceAlias") for item in Pdata if item.get("InterfaceAlias") is not None]
            allipv4= [item.get("IPv4Addresses") for item in Pdata if item.get("IPv4Addresses") is not None]
            alldns= [item.get("DNSServers" , {}).get("value",[]) for item in Pdata if item.get("DNSServers" , {}).get("value",[]) is not None]
            return (
                f"Interface alias = \n{str(allinterfaces)}\n"
                f"\nIpv4 addresses = \n{str(allipv4)}\n"
                f"\nDNS servers = \n{str(alldns)}\n"            
            )
        
        def NetTcpConn():
            s="++++++"
            f="+++++++"
            data=Regex.regex(s,f)
            Pdata=json.loads(data)
           
            alllocaladd = [item.get("LocalAddress") for item in Pdata if item.get("LocalAddress") is not None]
            alllocalport = [item.get("LocalPort") for item in Pdata if item.get("LocalPort") is not None]
            allremoteadd = [item.get("RemoteAddress") for item in Pdata if item.get("RemoteAddress") is not None]
            allremoteport = [item.get("RemotePort") for item in Pdata if item.get("RemotePort") is not None]
            return (
                f"Local addresses = \n{str(alllocaladd)}\n"
                f"\nLocal ports = \n{str(alllocalport)}\n"
                f"\nRemote addresses = \n{str(allremoteadd)}\n"
                f"\nRemote ports = \n{str(allremoteport)}\n"             
            )

        return Arp()+Gateway()+NetRoute()+NetNeigh()+NetIpConf()+NetTcpConn()

    print(parseJson())

    