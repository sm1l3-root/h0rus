#prot2role çalıştıırlacak sırayla gelen ip verileri de tek tek ghostbustera gidebilecek şekilde yazdırılacak
from rolefinder.port2role import Port2Role
from rolefinder.dns2role import Dns2Role
import json
class Json():
    def getTTL(ip):
        f = open("nmapports.json","r")
        data = json.loads(f.read())
        return data.get(ip, {}).get("ttl", {}) , data.get(ip, {}).get("traceroute_hops", {})
    def busterOutput(data):
        f = open("relation/4ghostbuster.json","w")
        json_data = json.dumps(data, indent=4)
        f.write(json_data)
        f.close()

    def role2json():
        ip_array, finded_role = Dns2Role.dns2role()
        ips , decisions ,ports = Port2Role.calcJaccard4ips()
        output = {}

        for ip,decision, port,dnsrole in zip (ips,decisions,ports,finded_role):
            if not port:
                continue
            
            ttl, hops=Json.getTTL(ip)
            print("ttl data")
            print(ttl)
            output[ip] = {
                "port2role": decision,
                "open_ports": port,
                "ttl": ttl,
                "dns2role": dnsrole,
                "traceroute_hops": hops

            }
        result_payload = {
            "nodes": output

        }
        Json.busterOutput(result_payload)

#Json.role2json()