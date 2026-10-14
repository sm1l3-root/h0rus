import json 
import re
import numpy as np
class OpenFiles():
    @staticmethod
    def importScanResults():
        with open("rolefinder/outputforport2role.json", "r", encoding="utf-8") as scans:
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
        
        
        hostnames=[]
        results=OpenFiles.importScanResults()
        result_port_data = results.get("hosts", {})
        ips=list(result_port_data.keys())
        #print(ips)
        for ip in ips:
            name=results.get("hosts", {}).get(str(ip), {}).get("hostname", {})
            hostnames.append(name)
            #print(name)
        #print(hostnames)
        #print(test)
        return hostnames , ips
    
    #print(JsonResult())
    
    
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
        hostnames, ips = JsonParse.JsonResult()
        cleaned = []
        for clean in hostnames:
            clean = re.sub(r'[^\w\s]', ' ', clean)
            cleaned.append(clean.split())
        return cleaned
        
    
    def NoiseCleaning(raw_tokens, noise_list):
        NoiseCleaned = []
        for token in raw_tokens:
            noise_set = set(noise_list)
            filtered_tokens = list(set(token) - noise_set)
            NoiseCleaned.append(filtered_tokens)
        return NoiseCleaned
    
    splitted_data = splitting()
    noise = JsonParse.JsonKeySetNoise()
    global noise_cleaned
    noise_cleaned = NoiseCleaning(splitted_data, noise)
    #print(noise_cleaned)
    def dns2role():
        role_array=JsonParse.JsonRoles()
        roles = OpenFiles.importRoles()
        hostname,ips = JsonParse.JsonResult()
        
        #print (role_array)
        ip_array=[]
        finded_role=[]
        for results, ip in zip(noise_cleaned, ips):
            weight = 0.0
            for a in role_array:
            #print(a)
            #print(roles.get("roles",{}).get(str(a), {}).get("keywords", []))
                for role_keywords in roles.get("roles",{}).get(str(a), {}).get("keywords", []):
                #match = list(set(role_keywords).intersection(noise_cleaned))
                #print (role_keywords)
                #print (noise_cleaned)
                    if role_keywords in results:
                        print("match found!!!!!")
                        print("keyword=",role_keywords)
                        print("ip: ",ip)
                        print("role name=",a)
                        ip_array.append(ip)
                        finded_role.append(a)

                        weight = weight + roles.get("roles",{}).get(str(a), {}).get("weight", 0.0)

        
                
                
                
        return ip_array,finded_role
    print(dns2role())
    