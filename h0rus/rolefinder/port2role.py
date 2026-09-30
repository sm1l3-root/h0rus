import json 
import numpy as np
class OpenFiles():
    def importScanResults():
        with open("rolefinder/portTEST.json", "r", encoding="utf-8") as scans:
            return json.load(scans)
    importScanResults()
    
    def importRoles():
        with open("rolefinder/port2roleTEST.json", "r", encoding="utf-8") as scans:
            return json.load(scans)
    importRoles()

class JsonParse():
    roles=OpenFiles.importRoles()
    results=OpenFiles.importScanResults()
    @staticmethod
    def Attend():
        role_array = []
        for rol_adi in JsonParse.roles.get("roles", {}).items():
            role_array.append(rol_adi)
            
        roles=OpenFiles.importRoles()
        
        for a in role_array:
            #print(a)
                    
            dc_data = roles.get("roles", {}).get(a, {})
            
            role_ports = dc_data.get("mandatory_ports", [])
            #print("role port values\n")
            
            return role_ports
            
    result_port_data = results.get("test_cases", {})
    result_ports =result_port_data.get("open_ports", [])
    print("scan results\n")
    print(result_ports)
    Attend()
    result_id = result_port_data.get("target_id", [])

    
    #print(result_id)
    
    

    

class Port2Role():
    
    def calcRoles():
        parser = JsonParse()
        parser.Attend()
        role_vector = set(JsonParse.Attend())
        target_vector = set(JsonParse.result_ports)
        intersection = len(role_vector.intersection(target_vector))
        print("intersection\n")
        
        
        
       
        #####
        role_array = []
        for rol_adi in JsonParse.roles.get("roles", {}).keys():
            role_array.append(rol_adi)
            
        #role_array = ["Domain Controller","Web","Database Server","Virtualization","Linux Management"]
        roles=OpenFiles.importRoles()
        weight_array = [] 

        for a in role_array:
            print(a)
                            
            dc_data = roles.get("roles", {}).get(a, {})
                    
            mandatory_ports = set(parser.roles.get("roles", {}).get(a, {}).get("mandatory_ports", []))

            # Kesişim işlemini yapıyoruz:
            inter_vector = mandatory_ports.intersection(set(target_vector))
            mandatory_union = set(parser.roles.get("roles", {}).get(a, {}).get("mandatory_ports", {}))
            union = len(mandatory_union.union(set(target_vector)))
            #print("role port values\n")
               
            weight_sum = 0.0
            weighted_jaccard_sum_second = 0.0
            for i in inter_vector:
            
                weights = parser.roles.get("roles", {}).get(a, {}).get("weights", {}).get(str(i), 0.0)
                
                #print("ports weights")
                print(inter_vector)
                weight_sum+= weights
            print("weighted sums")
            #print(weight_sum)
            #print("weight_sum")
            #print(weight_sum)
            
            weighted_jaccard_sum=((intersection / union)+weight_sum)
            
            print(weighted_jaccard_sum) 
            weight_array.append(weighted_jaccard_sum) 
            weight_sum = 0.0


        #print (weight_array)
        decision = weight_array.index(max(weight_array))
        print (role_array[decision])
    print("jaccard\n")
    print(calcRoles())

