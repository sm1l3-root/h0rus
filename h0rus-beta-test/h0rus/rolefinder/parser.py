import json
class ParserforRolefinder():
    def OpenJson():
        file = open("nmapports.json", "r+")
        data = file.read()
        jsondata = json.loads(data)
        return jsondata
    def ParseJson():
        data = ParserforRolefinder.OpenJson()
        
        ip_list = list(data.keys())
                    
        clean_ports=[]
        #print(ip_list)
        for ip in ip_list:
            #print(a)
                            
            ip_data = data.get(ip, {})
                    
            ip_ports = ip_data.get("open_ports", [])
            #print("role port values\n")
                    
            #print(ip_ports)
            clean_ports_int = [int(port.split('/')[0]) for port in ip_ports]
            clean_ports.append(clean_ports_int)

        return ip_list,clean_ports
    def writeJson(output_file):

        ip_list,port_list = ParserforRolefinder.ParseJson()
        clean_hosts = {}
        
        for ip, port in zip (ip_list,port_list):
            clean_hosts[ip] = {
                "hostname": "N/A",
                "open_ports": port
            }
        result_payload = {
            "hosts": clean_hosts
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result_payload, f, indent=4, ensure_ascii=False)

ParserforRolefinder.writeJson("rolefinder/outputforport2role.json")
