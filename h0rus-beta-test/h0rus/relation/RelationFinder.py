import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import re
from osdetect.JsonParser import Parse 
import socket
import ast
import ipaddress
#varolan tespit edilen roller jsona yazılılp rolefinderın içinden çekilecek
#bu çekilen veriler dependency matrix kullanılarak ilişkilendirilecek
#OS komutlarından bulunan veriler burada node edge verilerine eklenecek 
#aynı zamanda kolay incelenmesi için json dosyasına da output edilecek bu roller

class Regex():
    
    def regex(start,finish,data):
        pattern = rf"{re.escape(start)}(.*?){re.escape(finish)}"
        content = data
        match = re.search(pattern,content,re.DOTALL)
    
        if match:
            extract=match.group(1).strip()
            return extract
    
        else:
            return None

class localip():
    def getLocalIp():
        
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = "127.0.0.1"
        finally:
            s.close()

        return local_ip



class Inspect():
    
    
        
    def Arp():
        interfaces = []
        localips = []
        dynamicips=[]
        
        ndata=Parse.Arp()
        interfaces.append(Regex.regex("interfaces","localips",ndata))
        localips.append(Regex.regex("localips","DynamicIps",ndata))
        dynamicips.append(Regex.regex("DynamicIps","DYEnd",ndata))
        interfaces=ast.literal_eval(interfaces[0])
        localips=ast.literal_eval(localips[0])
        dynamicips=ast.literal_eval(dynamicips[0])
        return {
            "interface": interfaces,
            "local_ips": localips,
            "dynamic_ips": dynamicips
        }

    
    def Gateway():
        ndata=Parse.Gateway()
        
        gateway=[]
                
        
        gateway.append(Regex.regex("Gateway","GaEnd",ndata))
        
        gateway=ast.literal_eval(gateway[0])
        return {
            "gateways": gateway
            
        }

    def NetRoute():
        
        ndata=Parse.NetRoute()
                
        DestinationPrefixes=[]
        NextHops=[]              
                
        DestinationPrefixes.append(Regex.regex("DestinationPrefixes","Nexthops",ndata))
        NextHops.append(Regex.regex("NextHops","HopEnd",ndata))
                        
        DestinationPrefixes=ast.literal_eval(DestinationPrefixes[0])
        #NextHops=ast.literal_eval(NextHops[0])
        return {
            "DestinationPre": DestinationPrefixes,
            "NextHops":NextHops
                    
        }

    def NetNeigh():
        ndata=Parse.NetNeigh()
        
        neighbors=[]
                
        
        neighbors.append(Regex.regex("NetNeighbors","NeighEnd",ndata))
        neighbors=ast.literal_eval(neighbors[0])
        #neighbors = ast.literal_eval(neighbors1[0])
        print(neighbors)
        print("RelationFinder bitti ")
        return {
            "neighbors": neighbors
            
        }

    def NetIpConf():
        ndata=Parse.NetIpConf()
        
        interfacealiases=[]
        ipv4dds=[]
        dnsservers=[]
        
        #interfacealiases.append(Regex.regex("InterfaceAlias","Ipv4Addresses",ndata))
        ipv4dds.append(Regex.regex("Ipv4addresses","DNSservers",ndata))
        dnsservers.append(Regex.regex("DNSservers","DnsEnd",ndata))
        #interfacealiases=ast.literal_eval(interfacealiases[0])
        ipv4dds=ast.literal_eval(ipv4dds[0])
        dnsservers=ast.literal_eval(dnsservers[0])
        return {
            #"interfacealias": interfacealiases,
            "ipv4adds": ipv4dds,
            "dnsservers": dnsservers
            
        }
    def NetTCPConf():
        ndata=Parse.NetTcpConn()
        
        localadds=[]
        localports=[]
        remoteadds=[]
        remoteports=[]

        localadds.append(Regex.regex("Localaddresses","Localports",ndata))
        localports.append(Regex.regex("Localports","Remoteaddresses",ndata))
        remoteadds.append(Regex.regex("Remoteaddresses","Remoteports",ndata))
        remoteports.append(Regex.regex("Remoteports","RemEnd",ndata))
        localadds=ast.literal_eval(localadds[0])
        localports=ast.literal_eval(localports[0])
        remoteadds=ast.literal_eval(remoteadds[0])
        remoteports=ast.literal_eval(remoteports[0])
        #print(remoteports)
        #print(remoteadds)
        #print("realationfinder döndü")
        return {
            "localadds": localadds,
            "localports": localports,
            "remoteadds": remoteadds,
            "remoteports": remoteports
            
        }
    

        
class Relate():
    #source: Bağlantının başladığı düğüm (Node)

    #connected_to: Bağlantının bittiği düğüm
    @staticmethod
    def isIponSame(first,second):
        # Tırnak, köşeli parantez ve zone ID (%8) temizliği
        clean_first = str(first).strip("[]'\" ").split("%")[0]
        clean_second = str(second).strip("[]'\" ").split("%")[0]
    
        try:
            ip1 = ipaddress.ip_address(clean_first)
            ip2 = ipaddress.ip_address(clean_second)
        
            # Yalın IP'lerde Subnet/Network hatası almamak için ip_interface veya maske mantığı
            iface1 = ipaddress.ip_network(f"{clean_first}/24", strict=False)
            iface2 = ipaddress.ip_network(f"{clean_second}/24", strict=False)
        
            if ip1 in iface2 or ip2 in iface1:
                return "SameSub"
            else:
                return "Routed"
        except ValueError:
            return "Invalid"
    @staticmethod
    def Arp():
        #mantık şu olacak; dynamicler NetCardsa bağlı olacaklar NetCards da bana bağlı olacaklar ip adreslerini de türlerine göre vlanları ayıran bir fonksiyon yazmam gerek
        NetCards=[]
        me=[]
        NetIndex=[]
        CardNames=[]
        dynamics=[]
        local=localip.getLocalIp()
    
        arp_data=Inspect.Arp()
        for ips in arp_data["local_ips"]:
            if ips == local:
                me.append(ips)

            else:
                NetCards.append(ips)
                NetIndex.append(arp_data["local_ips"].index(ips))

        for cards in NetIndex:
            CardNames.append(arp_data["interface"][int(cards)])

        for dyna in NetIndex:
            dynamics.append(arp_data["dynamic_ips"][int(dyna)])

        dynamics_connections=[]
        me_connections=[]
        
        dynamics_connections.append({
                           
            "end": dynamics,           
            "source": NetCards,
            "interface": CardNames
        })
        me_connections.append({

            "end": NetCards,
            "source": me
        })
        #print (dynamics_connections)
        #print (me_connections)
        return dynamics_connections ,me_connections
    
    
    @staticmethod
    def Gateway():
        gate_data=Inspect.Gateway()
        gateway=gate_data["gateways"]
        
        
        gateway_conn=[]
        gateway_conn.append({
        
            "gateway": gateway
            
        })
        #print ( gateway_conn)
        return gateway_conn

    
    @staticmethod
    def RouteData():
        route_data=Inspect.NetRoute()
        
        
        nexthop=route_data["NextHops"]
        dest=route_data["DestinationPre"]
        
                
        me_connection=[]
        route_connection=[]
        me_connection.append({
                
            "end": nexthop,
            "source": "me "
            
                    
        })
        route_connection.append({
            "end": dest,
            "source": nexthop
        })
        #print (me_connection and route_connection)
        return me_connection , route_connection
    
    @staticmethod
    def neigh():
        neigh_connection=[]
        neigh_data=Inspect.NetNeigh()
        neigh=neigh_data["neighbors"]
        neigh_connection.append({
            "end": neigh,
            "source": "me"
        })
        #print(neigh_connection)
        return neigh_connection
    
    @staticmethod
    def ipconf():
        #ipv4source
        #dns target
        ipconf_data=Inspect.NetIpConf()
        dns_conn=[]
        ipv4_conn=[]
        
        dns=ipconf_data["dnsservers"]
        ipv4=ipconf_data["ipv4adds"]
        #inter=ipconf_data["interfacealias"]
        dns_conn.append({
                
            "source": ipv4,
            "end": dns,
            #"interface": inter
                    
        })
        ipv4_conn.append({
            "source":"me",
            "end": ipv4

        })

        #print (dns_conn, ipv4_conn)
        #print("relation finder döndü")
        return dns_conn , ipv4_conn
    

    @staticmethod
    def NetTCPConn():
        #romete add = connected to
        #local add = source olacak 
        conn_data=Inspect.NetTCPConf()
        local=conn_data["localadds"]
        lports=conn_data["localports"]
        remote=conn_data["remoteadds"]
        rports=conn_data["remoteports"]
        remote_conn=[]
        samesub_ends, samesub_sources, samesub_lports, samesub_rports = [], [], [], []
        gateway_ends, gateway_sources, gateway_lports, gateway_rports = [], [], [], []
        local_conn=[]
        for i, (ip1, ip2) in enumerate(zip(local, remote)):
            current_lport = lports[i] if i < len(lports) else None
            current_rport = rports[i] if i < len(rports) else None
        
            # Aynı alt ağda ise local IP -> remote IP
            if Relate.isIponSame(ip1, ip2) == "SameSub":
                samesub_ends.append(ip2)
                samesub_sources.append(ip1)
                samesub_lports.append(current_lport)
                samesub_rports.append(current_rport)
            # Farklı alt ağda ise gateway -> remote IP
            else:
                gateway_ends.append(ip2)
                gateway_sources.append("gateway")
                gateway_lports.append(current_lport)
                gateway_rports.append(current_rport)

        # İki ayrı gruplanmış dict
        samesub_conn = {
            "end": samesub_ends,
            "source": samesub_sources,
            "localport": samesub_lports,
            "remoteport": samesub_rports
        }

        gateway_conn = {
            "end": gateway_ends,
            "source": gateway_sources,
            "localport": gateway_lports,
            "remoteport": gateway_rports
        }

        local_conn.append({
            "end": local,
            "source": "me",
            "localport": lports
        })

        return gateway_conn,samesub_conn, local_conn


if __name__ == "__main__":
    Relate.Arp()
    Relate.Gateway()
    Relate.RouteData()
    Relate.neigh()
    Relate.ipconf()
    Relate.NetTCPConn()