from pyvis.network import Network
from NodeEdge import NodeEdge
def generate_topology_map(G, output_html="h0rus_topology.html"):
    net = Network(
        height="850px", 
        width="100%", 
        bgcolor="#11111b",       # Koyu modern arka plan
        font_color="#cdd6f4", 
        directed=True
    )
    
    # 1. KATEGORİLERE GÖRE CANLI RENK VE ŞEKİL HARİTASI
    category_styles = {
        "me": {"color": "#fab387", "size": 30, "shape": "square"},             # Turuncu Kare (Merkez)
        "gateway": {"color": "#f38ba8", "size": 25, "shape": "diamond"},        # Kırmızı Baklava
        "local_interface": {"color": "#89b4fa", "size": 20, "shape": "dot"},    # Mavi Daire
        "ipconf_ipv4_edges": {"color": "#89b4fa", "size": 18, "shape": "dot"},
        "ipconf_dns_end": {"color": "#cba6f7", "size": 18, "shape": "triangle"}, # Mor Üçgen (DNS)
        "remote_socket": {"color": "#a6e3a1", "size": 14, "shape": "dot"},      # Yeşil Daire (Dış IP'ler)
        "dynamic_arp": {"color": "#f9e2af", "size": 16, "shape": "star"}        # Sarı Yıldız (ARP)
    }
    
    # 2. DÜĞÜM (NODE) STİLLERİNİ VE ETİKETLERİNİ ATAMA
    for node, data in G.nodes(data=True):
        cat = data.get("category", "default")
        role = data.get("role", "N/A")
        
        # 'me' düğümünü özel yakala
        if str(node).strip() == "me":
            cat = "me"
            
        style = category_styles.get(cat, {"color": "#9399b2", "size": 15, "shape": "dot"})
        
        G.nodes[node]["color"] = style["color"]
        G.nodes[node]["size"] = style["size"]
        G.nodes[node]["shape"] = style["shape"]
        
        # Düğüm üstüne IP metni ekleyip fareyle üstüne gelince detay gösterelim
        G.nodes[node]["label"] = str(node)
        G.nodes[node]["title"] = f"Node ID: {node}\nCategory: {cat}\nRole: {role}"

    # 3. KENAR (EDGE) ÇİZGİLERİNİ VE OKLARI DÜZENLEME
    for u, v, data in G.edges(data=True):
        rel = data.get("category", data.get("relation", ""))
        lport = data.get("localport", "")
        rport = data.get("remoteport", "")
        
        G.edges[u, v]["color"] = {"color": "#585b70", "highlight": "#f5e0dc"}
        G.edges[u, v]["arrows"] = "to"  # Yön oklarını belirgin yap
        
        if rport:
            G.edges[u, v]["title"] = f"Relation: {rel}\nPort: {rport}"
        else:
            G.edges[u, v]["title"] = f"Relation: {rel}"

    # NetworkX'ten PyVis'e Aktarım
    net.from_nx(G)
    
    # 4. CRITICAL: FİZİK VE MESAFE AYARLARI (Düğümleri İterek Düzleştirir)
    net.options = {
        "physics": {
            "barnesHut": {
                "gravitationalConstant": -12000, # İtme gücünü artırdık (Düğümleri açar)
                "centralGravity": 0.2,
                "springLength": 180,             # Kenar uzunluklarını artırdık
                "springConstant": 0.04,
                "damping": 0.09
            },
            "minVelocity": 0.75
        },
        "edges": {
            "smooth": {
                "type": "continuous",            # Karışık kıvrımlar yerine düzgün eğriler
                "forceDirection": "none"
            }
        },
        "interaction": {
            "hover": True,
            "navigationButtons": True            # Zoom ve yön butonları ekler
        }
    }
    
    net.write_html(output_html)
    print(f"[+] Düzenlenmiş topoloji haritası oluşturuldu: {output_html}")

generate_topology_map(NodeEdge.CollectGs())