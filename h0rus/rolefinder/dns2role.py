import json 
import re
import numpy as np
class OpenFiles():
    @staticmethod
    def importScanResults():
        with open("rolefinder/portTEST.json", "r", encoding="utf-8") as scans:
            return json.load(scans)
    importScanResults()
    @staticmethod
    def importRoles():
        with open("rolefinder/dns2roleTEST.json", "r", encoding="utf-8") as scans:
            return json.load(scans)
    importRoles()


class JsonParse():
    @staticmethod
    def JsonResult():
        
        results=OpenFiles.importScanResults()
        result_port_data = results.get("test_cases", {})
        result_hostname =result_port_data.get("hostname", {})
        return result_hostname
    JsonResult()

    def JsonKeySetNoise():
        keywords=OpenFiles.importRoles()
        noise=keywords.get("noise_keywords", {})
        return noise
    JsonKeySetNoise()

    def JsonRoles():
        role_array = []
        roles = OpenFiles.importRoles()
        
        for rol_adi in roles.get("roles", {}).keys():
            role_array.append(rol_adi)

        return role_array
    JsonRoles()
       

class Dns2Role():
    
    @staticmethod
    def splitting():
        
        clean = re.sub(r'[^\w\s]', ' ', JsonParse.JsonResult())
        return clean.split()
        
    
    def NoiseCleaning(raw_tokens, noise_list):
        noise_set = set(noise_list)
        filtered_tokens = list(set(raw_tokens) - noise_set)
        return filtered_tokens
    
    splitted_data = splitting()
    noise = JsonParse.JsonKeySetNoise()
    global noise_cleaned
    noise_cleaned = NoiseCleaning(splitted_data, noise)
    
    def dns2role():
        role_array=JsonParse.JsonRoles()
        roles = OpenFiles.importRoles()
        weight = 0.0
        #print (role_array)
        for a in role_array:
            #print(a)
            #print(roles.get("roles",{}).get(str(a), {}).get("keywords", []))
            for role_keywords in roles.get("roles",{}).get(str(a), {}).get("keywords", []):
                #match = list(set(role_keywords).intersection(noise_cleaned))
                #print (role_keywords)
                #print (noise_cleaned)
                if role_keywords in noise_cleaned:
                    print("match found!!!!!")
                    print("keyword=",role_keywords)
                    print("role name=",a)
                    weight = weight + roles.get("roles",{}).get(str(a), {}).get("weight", 0.0)

        
                
                
                
        return weight
    print(dns2role())
    