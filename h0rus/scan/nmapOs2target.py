"""import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))"""
import ipaddress
from relation.RelationFinder import Inspect

class os2target:
    @staticmethod
    def getipv4s():
        arp = Inspect.Arp()
        ipconf = Inspect.NetIpConf()
        neigh = Inspect.NetNeigh()
        conn = Inspect.NetTCPConf()
        ip1 = ipconf["ipv4adds"]
        ip2 = arp["dynamic_ips"]
        ip3 = neigh["neighbors"]
        ip4 = conn["remoteadds"]
        iplist = list(set(ip1))

        return iplist

    @staticmethod
    def openFile(data_list):
        # Her IP'nin sonuna alt satıra geçme karakteri (\n) ekliyoruz
        output = "\n".join(data_list)
        with open("nmaptargets.txt", "w", encoding="utf-8") as f:
            f.writelines(output)
    

    
    @staticmethod
    def inspect():
        subnetted=[]
        ips  =os2target.getipv4s()
        for ip in ips:
            ip_obj = ipaddress.ip_address(ip.strip())
            if isinstance(ip_obj, ipaddress.IPv4Address):
            
            
                subnetted.append(ip)
        return subnetted
    @staticmethod
    def main():
        ips = os2target.inspect()
        
        os2target.openFile(ips)

