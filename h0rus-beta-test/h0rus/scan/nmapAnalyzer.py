import json
import subprocess
import xmltodict

class Parse():
    def load_nmap_xml_turn_dict(xml_input):
        with open(xml_input, 'r', encoding='utf-8') as f:
            xml_data = f.read()

        # xmltodict ile XML'i doğrudan Python sözlüğüne çeviriyoruz
        parsed_dict = xmltodict.parse(xml_data)
    
        return parsed_dict

    def parse_nmap_dict_full(nmap_dict):
        """
    xmltodict ile çevrilmiş Nmap verisinden Traceroute topolojisini (Edges)
    ve OS, Port, Servis detaylarını (Node Attributes) çıkarır.
    """
        relations = []
        nodes_metadata = {}  # IP -> {os, ports, services, role} bilgileri
    
        nmap_run = nmap_dict.get('nmaprun', {})
        hosts = nmap_run.get('host', [])

        if isinstance(hosts, dict):
            hosts = [hosts]

        for host in hosts:
            # Sadece ayakta (up) olan host'ları işliyoruz
            status = host.get('status', {}).get('@state')
            if status != 'up':
                continue

            # 1. IP ADRESİ TESPİTİ
            addresses = host.get('address', [])
            target_ip = None
            mac_addr = None
            vendor = None

            if isinstance(addresses, dict):
                addresses = [addresses]

            for addr in addresses:
                if addr.get('@addrtype') == 'ipv4':
                    target_ip = addr.get('@addr')
                elif addr.get('@addrtype') == 'mac':
                    mac_addr = addr.get('@addr')
                    vendor = addr.get('@vendor', 'Unknown Vendor')

            if not target_ip:
                continue

        # 2. İŞLETİM SİSTEMİ TESPİTİ (-O)
            os_name = "N/A"
            os_info = host.get('os', {})
            if os_info:
                os_matches = os_info.get('osmatch', [])
                if isinstance(os_matches, dict):
                    os_matches = [os_matches]
                if os_matches:
                    # En yüksek doğruluk oranına (accuracy) sahip ilk tahmini alıyoruz
                    best_match = os_matches[0]
                    os_name = f"{best_match.get('@name', 'Unknown OS')} (%{best_match.get('@accuracy', '0')} accuracy)"

        # 3. PORT VE SERVİS TESPİTİ (-sS, -sV)
            ports_info = host.get('ports', {}).get('port', [])
            if isinstance(ports_info, dict):
                ports_info = [ports_info]

            open_ports = []
            services_summary = []

            for p in ports_info:
                port_state = p.get('state', {}).get('@state')
                if port_state == 'open':
                    port_id = p.get('@portid')
                    proto = p.get('@protocol', 'tcp')
                
                # Servis & Versiyon detayları (-sV)
                    service_obj = p.get('service', {})
                    s_name = service_obj.get('@name', 'unknown')
                    s_product = service_obj.get('@product', '')
                    s_version = service_obj.get('@version', '')
                
                    service_detail = f"{s_name}"
                    if s_product:
                        service_detail += f" ({s_product} {s_version})".strip()

                    open_ports.append(f"{port_id}/{proto}")
                    services_summary.append(f"Port {port_id}: {service_detail}")

        # Node metadata sözlüğüne ekliyoruz
            nodes_metadata[target_ip] = {
            "os": os_name,
            "open_ports": open_ports,
            "services": services_summary,
            "mac": mac_addr if mac_addr else "N/A",
            "vendor": vendor if vendor else "N/A"
            }

        # 4. TRACEROUTE HOP / TOPOLOJİ İLİŞKİLERİ
            trace = host.get('trace')
            if trace and 'hop' in trace:
                hops = trace.get('hop', [])
                if isinstance(hops, dict):
                    hops = [hops]

                hops_sorted = sorted(hops, key=lambda x: int(x.get('@ttl', 0)))
                previous_node = "LOCAL_HOST"

                for hop in hops_sorted:
                    current_hop_ip = hop.get('@ipaddr')
                    rtt = hop.get('@rtt', 'N/A')

                    if current_hop_ip:
                        relations.append({
                            "Source_IP": previous_node,
                            "Target_IP": current_hop_ip,
                            "Relation": "ROUTED_TO",
                            "RTT_ms": rtt
                        })
                        previous_node = current_hop_ip

                if previous_node != target_ip:
                    relations.append({
                    "Source_IP": previous_node,
                    "Target_IP": target_ip,
                    "Relation": "DESTINATION",
                    "RTT_ms": "0"
                    })

        return relations, nodes_metadata

class Json():
    global relationdata
    global metadata
    relationdata, metadata =(Parse.parse_nmap_dict_full(Parse.load_nmap_xml_turn_dict("scan.xml")))
    def relations():
        file = open("nmaprelations.jsonl","w")
        data = json.dumps(relationdata, indent=4)
        file.write(data+"\n")
        file.close()

    def nodesmeta():
        file = open("nmapports.jsonl","w")
        data = json.dumps(metadata, indent=4)
        file.write(data+"\n")
        file.close()

Json.relations()
Json.nodesmeta()