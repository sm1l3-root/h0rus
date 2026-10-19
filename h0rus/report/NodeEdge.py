
import networkx as nx
from relation.RelationFinder import Relate
import ast
import pandas as pd
import json
import re
class ParseOSdata():
    def arp_data():
        dynamics, me = Relate.Arp()
        
        stripped_dynamics=dynamics[0]
        stripped_me=me[0]
        dyna_source=[]
        dyna_end=[]
        dyna_interface=[]
        for source,end,interface in zip(stripped_dynamics['source'],stripped_dynamics['end'],stripped_dynamics['interface']):
            dyna_end.append(end)
            dyna_interface.append(interface)
            dyna_source.append(source)

        me_source=[]
        me_end=[]
        for source,end in zip(stripped_me['source'],stripped_me['end']):
            me_end.append(end)
            me_source.append(source)

        return dyna_source,dyna_end,dyna_interface ,me_source,me_end

    def gateway_data():
        gateway=Relate.Gateway()
        stripped_gateway=gateway[0]
        data=stripped_gateway["gateway"]
        
        return data

    def route_data():
        me,route=Relate.RouteData()
        stripped_route=route[0]
        stripped_me = me[0]
        source_data=[]
        end_data=[]
        default_source="default_data"
        for source,end in zip(stripped_route['source'],stripped_route['end']):
            if end:  # Hedef IP var ama kaynak None ise varsayılanı ata
                clean_source = source if source is not None else default_source
                source_data.append(clean_source)
                end_data.append(end)
            else:
                source_data.append(source)
                end_data.append(end)

        me_source=[]
        me_end=[]
        default_end="default_data"
       
        for end in stripped_me['end']:
            
            if stripped_me["source"]:  
                clean_end= end if end is not None else default_end
                me_source.append(stripped_me["source"])

                me_end.append(clean_end)
            else:
                me_end.append(end)
                me_source.append(source)


            
            
           
        return source_data,end_data, me_source, me_end

   
    def ipconf_data():
        dns_conn,ipv4_conn = Relate.ipconf()
        stripped_dns_conn = dns_conn[0]
        dns_source=[]
        dns_end=[]
        #dns_inter=[]
        for source,end in zip(stripped_dns_conn['source'],stripped_dns_conn['end']):
            dns_source.append(source)
            dns_end.append(end)
            #dns_inter.append(inter)
        ipv4_source=[]
        ipv4_end=[]
        stripped_ipv4= ipv4_conn[0]
        #print(stripped_ipv4["source"])
        for end in stripped_ipv4["end"]:
            ipv4_end.append(end)

            ipv4_source.append(stripped_ipv4["source"])

        #print(ipv4_source)
        
        #stripped_ipv4_end=ipv4_end[0]
        return dns_source,dns_end , ipv4_source,ipv4_end
        """print (dns_source)
        print (dns_end)
        #print(dns_inter)
        print("*"*20)
        print(ipv4_source)
        print(ipv4_end)"""

    def neigh_data():
        neigh=Relate.neigh()
        stripped_neigh = neigh[0]
        neigh_source=[]
        neigh_end=[]
        for end in stripped_neigh['end']:
            neigh_end.append(end)
            neigh_source.append(stripped_neigh['source'])

        return neigh_source,neigh_end

    def netTcp_data():
        remote_gateway_conn,remote_samesub_conn,local_conn=Relate.NetTCPConn()
        
        stripped_local= local_conn[0]
        return stripped_local,remote_gateway_conn,remote_samesub_conn
        print(stripped_local)
        

#ParseOSdata.netTcp_data()
#print(ParseOSdata.arp_data())
#

class ParseNmapTrace():
    def OpenTrace():
        
        df = pd.read_json("nmaprelations.json")
        return df
class ParsePivots():
    def OpenJson():
        df = pd.read_json("pivotscore/pivotscores.jsonl", lines=True)
        return df
class ParseGhostBuster():
    @staticmethod
    def OpenJson():
        
        df = pd.read_json('relation/output.jsonl', lines=True)
        return df
                
class ParseServices():
    #sadece pivotscore u olan ipleri alsın diğerlerini boşversin
    def OpenJson():
        file = open("nmapports.json", "r+")
        data = file.read()
        jsondata = json.loads(data)
        return jsondata
    def ParseJson():
        data = ParseServices.OpenJson()
        ip_data = ParsePivots.OpenJson()
        ip_list = ip_data["ip"].tolist()
        metadata={}       
        clean_services={}
            #print(ip_list)
        for ip in ip_list:
            #print(ip)
                                
            ip_data = data.get(ip, {})
                        
            ip_services = ip_data.get("services", [])
            #print(ip_services)
                        
                #print(ip_ports)
            cleaned = [m.group(1).strip() for service in ip_services if (m := re.search(r'\((.*?)\)', service))]
            clean_services[ip] = {
                "cleaned_services":cleaned
            }

            os_data = ip_data.get("os", [])
            ports = ip_data.get("open_ports", [])      
                
            
            metadata[ip] ={
                "os":os_data,
                "open_ports":ports
            }
        
        return clean_services,metadata

#class ParseNmap():

class NodeEdge():
    global G
    G = nx.DiGraph()
    def arp():
        dyna_source,dyna_end,dyna_interface ,me_source,me_end = ParseOSdata.arp_data()
        G.add_nodes_from(dyna_source, category="dynamic_source")
        G.add_nodes_from(dyna_end, category="dynamic_end")

        
        edges_dynamic = zip(dyna_source, dyna_end)
        G.add_edges_from(edges_dynamic, category="arp")
        #print(G.edges(data=True))
        G.add_nodes_from(me_source, category="me_source")
        G.add_nodes_from(me_end, category="me_end")
        edges_me = zip (me_source,me_end)
        G.add_edges_from(edges_me, category="arp")
                



    def gateway():
        gateway= ParseOSdata.gateway_data()
        
        G.add_nodes_from(gateway, category="gateway")
        #edge = zip(gateway,"me")
        G.add_edge("me", "gateway",category="gateway")
        
#NodeEdge.gateway()

    def route():
        source_data,end_data,me_source, me_end = ParseOSdata.route_data()
        G.add_nodes_from(source_data, category="route_source")
        G.add_nodes_from(end_data, category="route_end")
        edges = zip(source_data,end_data)
        G.add_edges_from(edges,category="ip_via_route")
        #print(me_end)
        #print("ödnüd")
        #print(me_source)
        G.add_nodes_from(me_source, category="route_me_source")
        G.add_nodes_from(me_end, category="route_me_end")
        edges_me = zip(me_source,me_end)
        G.add_edges_from(edges_me,category="ip_via_route")
        """print(G.edges(data=True))"""
        
    def ipconf():
        dns_source,dns_end , ipv4_source,ipv4_end=ParseOSdata.ipconf_data()
        #print(ipv4_source)
        #print(ipv4_end)
        G.add_nodes_from(ipv4_source, category="ipconf_ipv4_source")
        G.add_nodes_from(ipv4_end, category="ipconf_ipv4_end")
        
        #print(ipv4_end)
        ipv4_edges=zip(ipv4_source,ipv4_end)
        G.add_edges_from(ipv4_edges, category="ipconf_edges")
        
        G.add_nodes_from(dns_source,category="ipconf_dns_source")
        
        
        dns_nodes_end = [
            target 
            for group in dns_end 
            for target in (group if isinstance(group, list) else [group])
        ]
        G.add_nodes_from(dns_nodes_end,category="ipconf_dns_end")
        dns_edges = [
            (src, target) 
            for src, group in zip(dns_source, dns_end) 
            for target in (group if isinstance(group, list) else [group])
        ]
        G.add_edges_from(dns_edges, category="ipconf_edges")
        """print("ipconf edges-----------------")
        print(G.edges(data=True))"""
        

    def neigh():
        source, end=ParseOSdata.neigh_data()
        G.add_nodes_from(source, category="neigh")
        G.add_nodes_from(end, category="neigh")
        edges=zip(source,end)
        G.add_edges_from(edges, category="neigh_edges")
        print(G.edges(data=True))
        

    def NetTCP():
        local,remote_gateway_conn,remote_samesub_conn = ParseOSdata.netTcp_data()
        local_source=[]
        local_end=local["end"]
        local_ports=[]
        G.add_nodes_from(local_end,category="local_conn_end")
        
        G.add_nodes_from(local_source,category="local_conn_source")
        for _ in local_end:
            local_source.append(local["source"])
            #print(for_edge_me)
        #print(remote_gateway_conn[""])
        #print(remote_gateway_conn[""])
        local_edge=zip(local_source,local_end)
        G.add_edges_from(local_edge, category="TCP_conn_edge")
        if remote_samesub_conn["end"] == [] and remote_gateway_conn["end"] != []:
            print ("samesub boş gateway dolu")
            gateway_rport=[]
            gateway_lport=[]
            gateway_source=remote_gateway_conn["source"]
            gateway_end=remote_gateway_conn["end"]
            G.add_nodes_from(gateway_source, category="remote_conn_gateway_source")
            G.add_nodes_from(gateway_end, category="remote_conn_gateway_end")
            edges=zip(gateway_source,gateway_end)
            G.add_edges_from(edges, category="TCP_conn_edge")
        elif remote_gateway_conn["end"] == [] and remote_samesub_conn != []:
            print("gateway boş samesub dolu")
            samesub_end=remote_samesub_conn["end"]
            samesub_source=remote_samesub_conn["source"]
            samesub_lport=[]
            samesub_rport=[]
            G.add_nodes_from(samesub_end,category="remote_conn_samesub_end")
            G.add_nodes_from(samesub_source,category="remote_conn_samesub_source")
            edges=zip(samesub_source,samesub_end)
            G.add_edges_from(edges,category="TCP_conn_edge")
        else:
            gateway_rport=[]
            gateway_lport=[]
            gateway_source=remote_gateway_conn["source"]
            gateway_end=remote_gateway_conn["end"]
            samesub_rport=[]
            samesub_lport=[]
            samesub_end=remote_samesub_conn["end"]
            samesub_source=remote_samesub_conn["source"]
            G.add_nodes_from(samesub_end,category="remote_conn_samesub_end")
            G.add_nodes_from(samesub_source,category="remote_conn_samesub_source")
            edges_samesub=zip(samesub_source,samesub_end)
            G.add_edges_from(edges_samesub,category="TCP_conn_edge")
            G.add_nodes_from(gateway_source, category="remote_conn_gateway_source")
            G.add_nodes_from(gateway_end, category="remote_conn_gateway_end")
            edges_gateway=zip(gateway_source,gateway_end)
            G.add_edges_from(edges_gateway, category="TCP_conn_edge")


    def GhostBuster():
        df = ParseGhostBuster.OpenJson()
        G_ghost = nx.from_pandas_edgelist(
            df,
            source='Node Ip',
            target='Ghost',
            edge_attr=True,
            create_using=nx.DiGraph()
        )
        #role_dict = df.set_index('Node Ip')['Node Role'].to_dict()
        #nx.set_node_attributes(G_ghost, role_dict, name='role')
        for u, v, data in G_ghost.edges(data=True):
            if 'Node Role' in data:
                G_ghost.nodes[u]['role'] = data['Node Role']
                G_ghost.nodes[u]['category'] = 'ghost_detector'
        
            G_ghost.nodes[v]['category'] = 'ghost_node'
            
        return G_ghost

    def metadata():
        
        
        services,os_data = ParseServices.ParseJson()
        for ip, metadata in os_data.items():
            G.add_node(
            ip,
            os=metadata['os'],
            open_ports=metadata['open_ports'],
              # h0rus metadata
            )
            G.nodes[ip]['os'] = os_data[ip]['os']
            G.nodes[ip]['open_ports'] = os_data[ip]['open_ports']
        

        
                    
                
    def SearchSploitDB():
        print("SERVICEs ARE SEARCHING IN SEARCHSPLOT DB")
        df = ParsePivots.OpenJson()
        pivot_ips = df["ip"].tolist()
        services, metadata = ParseServices.ParseJson()
        db = pd.read_csv("files_exploits.csv")
        ip_vulns = {}
        for ip in pivot_ips:
            for serv in services.get(ip,{}).get("cleaned_services", []):

                words = serv.split()

                
                condition = pd.Series(True, index=db.index)
                for word in words:
                    
                    if len(word) > 1:
                        condition &= db['description'].str.contains(word, case=False, na=False)

                results = db[condition]
                parsed_res = results[['id', 'file', 'description', 'port']]
                
                print("*"*20)
                print(ip)  
                print("*"*20)
                print(serv)
                print("*"*20)
                print(parsed_res)  
    def PivotScore():
        df = ParsePivots.OpenJson()
        #service = ParseServices.ParseJson()

        pivot_dict = df.set_index('ip')['score'].to_dict()
        
        nx.set_node_attributes(G, pivot_dict, name='pivot_score')
        
    def traceroute():
        df = ParseNmapTrace.OpenTrace()
        G_trace = nx.from_pandas_edgelist(
            df,
            source = "Source_IP",
            target="Target_IP",
            edge_attr=["Relation", "RTT_ms"],
            create_using=nx.DiGraph()

        )
        return G_trace
    def CollectGs():
        G.clear()
        NodeEdge.arp()
        NodeEdge.ipconf()
        NodeEdge.gateway()
        NodeEdge.neigh()
        NodeEdge.NetTCP()
        NodeEdge.route()
        G.update(NodeEdge.traceroute())
        G.update(NodeEdge.GhostBuster())
        NodeEdge.PivotScore()
        NodeEdge.metadata()
        NodeEdge.SearchSploitDB()
        return G
        

#print(NodeEdge.SearchSploitDB())
#print(ParseServices.ParseJson())

        



        
