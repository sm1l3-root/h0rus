#prot2role çalıştıırlacak sırayla gelen ip verileri de tek tek ghostbustera gidebilecek şekilde yazdırılacak
from rolefinder.port2role import Port2Role
from rolefinder.dns2role import Dns2Role
import json
class Json():
    def busterOutput(data):
        f = open("relation/4ghostbuster.json","w")
        json_data = json.dumps(data, indent=4)
        f.write(json_data)

    def role2json():
        ip_array, finded_role = Dns2Role.dns2role()
        ips , decisions ,ports = Port2Role.calcJaccard4ips()
        output = {}

        for ip,decision, port,dnsrole in zip (ips,decisions,ports,finded_role):
            output[ip] = {
                "port2role": decision,
                "open_ports": port,
                "ttl": 128,
                "dns2role": dnsrole

            }
        result_payload = {
            "nodes": output

        }
        Json.busterOutput(result_payload)

Json.role2json()