from osdetect.linux import IfLinux
from osdetect.windows import IfWin
import json
import re
import os
import ipaddress

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

    


    def Arp():
        s="+"
        f="++"
        data=Regex.regex(s,f)
        Pdata=json.loads(data)
        if isinstance(Pdata, dict):
            Pdata = [Pdata]
        interface=[item.get("Interface") for item in Pdata if isinstance(item, dict) and item.get("Interface") is not None]
        allLocalip = [item.get("LocalIP") for item in Pdata if isinstance(item, dict) and item.get("LocalIP") is not None]
        allip = [item.get("DynamicIPs") for item in Pdata if isinstance(item, dict) and item.get("DynamicIPs") is not None]
        return (
            f"\ninterfaces\n{str(interface)}\n"
            f"localips\n{str(allLocalip)}\n"
            f"DynamicIps\n{str(allip)}DYEnd"
        )
    
    def Gateway():
        s="++"
        f="+++"
        data=Regex.regex(s,f)
        cleaned = data.replace('"', '')
        Cdata = cleaned.split()
        #salt veri
        return (f"\nGateway\n{str(Cdata)}GaEnd\n")
            
        
    def NetRoute():
        s="+++"
        f="++++"
        data=Regex.regex(s,f)
        Pdata=json.loads(data)
        if isinstance(Pdata, dict):
            Pdata = [Pdata]
        allNextHop = [item.get("NextHop") for item in Pdata if isinstance(item, dict) and item.get("NextHop") is not None]
        allDestPre = [item.get("DestinationPrefix") for item in Pdata if isinstance(item, dict) and item.get("DestinationPrefix") is not None]
        return (
            f"DestinationPrefixes\n{str(allDestPre)}\n"
            f"\nNexthops\n{str(allNextHop)}HopEnd\n"
            
        )
        
    def NetNeigh():
        s="++++"
        f="+++++"
        data=Regex.regex(s,f)
        
        #salt veri
        cleaned0 = data.strip("[]'\" ")
        cleaned = cleaned0.replace('"', '')
        cleaned2 = cleaned.replace(",", '')
        Cdata = cleaned2.split()
        
        print("jsonparser döndü")
        return (f"NetNeighbors\n{str(Cdata)}NeighEnd\n")
        
    def NetIpConf():
        s="+++++"
        f="++++++"
        data=Regex.regex(s,f)
        Pdata=json.loads(data)
        if isinstance(Pdata, dict):
            Pdata = [Pdata]

        else:
            pass

        allinterfaces = [item.get("InterfaceAlias") for item in Pdata if isinstance(item, dict) and item.get("InterfaceAlias") is not None]
        allipv4= [item.get("IPv4Addresses") for item in Pdata if isinstance(item, dict) and item.get("IPv4Addresses") is not None]
        alldns = [item.get("DNSServers").get("value") if isinstance(item.get("DNSServers"), dict) else item.get("DNSServers") for item in Pdata if isinstance(item, dict) and item.get("DNSServers") is not None]
        return (
            f"Interfacealias\n{str(allinterfaces)}\n"
            f"\nIpv4addresses\n{str(allipv4)}\n"
            f"\nDNSservers\n{str(alldns)}DnsEnd\n"            
        )
        
    def NetTcpConn():
        s="++++++"
        f="+++++++"
        data=Regex.regex(s,f)
        Pdata=json.loads(data)
        if isinstance(Pdata, dict):
            Pdata = [Pdata]
        alllocaladd = [item.get("LocalAddress") for item in Pdata if isinstance(item, dict) and item.get("LocalAddress") is not None]
        alllocalport = [item.get("LocalPort") for item in Pdata if isinstance(item, dict) and item.get("LocalPort") is not None]
        allremoteadd = [item.get("RemoteAddress") for item in Pdata if isinstance(item, dict) and item.get("RemoteAddress") is not None]
        allremoteport = [item.get("RemotePort") for item in Pdata if isinstance(item, dict) and item.get("RemotePort") is not None]
        #elde fazla data olsun diye bir sürü saçma sapan filtrelenmesi gereken veriiy döndürüyorum onları filtrelemeyi unutma 
        
        return (
            f"Localaddresses\n{str(alllocaladd)}\n"
            f"\nLocalports\n{str(alllocalport)}\n"
            f"\nRemoteaddresses\n{str(allremoteadd)}\n"
            f"\nRemoteports\n{str(allremoteport)}RemEnd\n"             
        )

        #return Arp()+Gateway()+NetRoute()+NetNeigh()+NetIpConf()+NetTcpConn()

    

    