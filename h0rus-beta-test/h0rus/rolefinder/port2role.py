import json 
import numpy as np
class OpenFiles():
    def importScanResults():
        with open("rolefinder/outputforport2role.json", "r", encoding="utf-8") as scans:
            return json.load(scans)
    #importScanResults()
    
    def importRoles():
        with open("rolefinder/port2roleTEST.json", "r", encoding="utf-8") as scans:
            return json.load(scans)
    #importRoles()

class JsonParse():
    
    roles=OpenFiles.importRoles()
    results=OpenFiles.importScanResults()
    @staticmethod
    def Attend():
        
        result_ports = []
        result_ip_array=[]
        role_ports=[]
        roles=OpenFiles.importRoles()
        """for rol_adi in roles.get("roles", {}).items():
            role_array.append(rol_adi)"""
        role_key_out = roles.get("roles", {})
        role_array = list(role_key_out.keys())
        
        #print(role_array)
        for a in role_array:
            #print(a)
                    
            dc_data = roles.get("roles", {}).get(a, {})
            
            ports = dc_data.get("mandatory_ports", [])
            #print("role port values\n")
            role_ports.append(ports)
            

        for ip in JsonParse.results.get("hosts", {}):        
            data = JsonParse.results.get("hosts",{}).get(ip, {})
            result_port =data.get("open_ports", [])
            result_ports.append(result_port)
            result_ip_array.append(ip)
            #print("scan results\n")
            #print(result_ports)
        

        return role_array,role_ports,result_ports,result_ip_array


    
    #result_id = result_port_data.get("target_id", [])

    
    #print(result_id)
    
    

    

class Port2Role():
    
    def calcRoles(result_ports):
        parser = JsonParse()
        role_array,role_ports,result_port,result_ip_array = parser.Attend()
        #print("role vector")
        role_vector = set(role_array)
        #print(role_vector)
        #print("target vector")
        target_vector = set(result_ports)
        #print(target_vector)
        #print("intersection")
        #intersection = len(role_vector.intersection(target_vector))
        #print(intersection)
        
        
        
       
        #####
        """role_array = []
        for rol_adi in parser.roles.get("roles", {}).keys():
            role_array.append(rol_adi)"""
            
        #role_array = ["Domain Controller","Web","Database Server","Virtualization","Linux Management"]
        roles=OpenFiles.importRoles()
        weight_array = [] 

        for a in role_array:
            print("jaccard")
            print(a)
                            
            #dc_data = roles.get("roles", {}).get(a, {})
                    
            mandatory_ports = set(parser.roles.get("roles", {}).get(a, {}).get("mandatory_ports", []))
            print("mandatory ports")
            print(mandatory_ports)
            # Kesişim işlemini yapıyoruz:
            inter_vector = mandatory_ports.intersection(set(target_vector))
            #mandatory_union = set(parser.roles.get("roles", {}).get(a, {}).get("mandatory_ports", {}))
            union = len(mandatory_ports.union(set(target_vector)))
            print("inter vector")
            print(inter_vector)
            #print("manda union")
            #print(mandatory_union)
            print("union")
            print(union)
            print("role port values\n")
            
            weight_sum = 0.0
            weighted_jaccard_sum_second = 0.0
            for i in inter_vector:
            
                weights = parser.roles.get("roles", {}).get(a, {}).get("weights", {}).get(str(i), 0.0)
                
                print("ports weights")
                print(inter_vector)
                weight_sum+= weights
            print("weighted sums")
            print(weight_sum)
            #print("weight_sum")
            #print(weight_sum)
            
            weighted_jaccard_sum=((len(inter_vector) / union)+weight_sum)
            
            print(weighted_jaccard_sum) 
            weight_array.append(weighted_jaccard_sum) 
            weight_sum = 0.0


        #print (weight_array)
        decision = weight_array.index(max(weight_array))
        print("decision")
        print("*"*20)
        print (role_array[decision])

    def calcJaccard4ips():
        
        role_array,role_ports,result_ports,result_ip_array = JsonParse.Attend()
        for port,ip in zip(result_ports,result_ip_array):
            print("calculating role for ip: ")
            print(ip)
            Port2Role.calcRoles(port)
            #print(port)
            print("*"*20)
            

Port2Role.calcJaccard4ips()