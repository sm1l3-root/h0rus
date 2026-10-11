#json ile outputla networkü çizdir 
#topolojideki önceki nodelar ile filtre
import sys
import os
# Bulunduğun 'relation' klasörünün bir üst klasörünü (h0rus) Python path'ine ekler
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import ipaddress
import json
from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination
#from rolefinder.dns2role import Dns2Role
#from rolefinder.port2role import Port2Role
#from RelationFinder import Relate



class Json():
    
    @staticmethod
    def makeJson():
        file_path = "relation/output.jsonl"
        
        
        
        file= open(file_path,"a+")
        return file
    
    @staticmethod
    def openJson():
        file = open("relation/dependencyMatrix.json","r+")
        return file.read() 
        
    
    
    @staticmethod
    def InspectMatrix(role):
        Matrixdata = json.loads(Json.openJson())["role_dependencies"]
        get_role=Matrixdata[role]
        get_role_data=get_role["direct_dependencies"]
        return get_role_data

    @staticmethod
    def test():
        file = open("relation/ghostbusterTEST.json")
        return file.read()

    def InspectTEST(id):
        test_data= json.loads(Json.test())["test_cases"]
        get_case = test_data.get(id)
        return get_case

    def AllTESTnames():
        role_names=[]
        role=json.loads(Json.test())["test_cases"]
        for roles in role:
        
            role_names.append(roles)
        
        return role_names

    @staticmethod
    def InspectCPD(proof):
        file = open("relation/cpd_tables.json")
        data=json.loads(file.read())["cpd_definitions"]
        get_cpd = data.get(proof)["values"]
        return get_cpd
    
class delete_past:
    def zerOutput():
        file_path = "relation/output.jsonl"
                
        try:        
            if os.path.getsize(file_path) > 0:
                with open(file_path, "w") as file:
                    pass 
        except:
            pass
    

class Write():
    def writeJson(data):
        
        file = Json.makeJson()
        
        file.write(data+ "\n")

class TEST():
    def get_port_role(name):
        load=Json.InspectTEST(name).get("visible_node")
        role=load.get("port_role")
        return role

    def get_dns_role(name):
        load=Json.InspectTEST(name).get("visible_node")
        role=load.get("dns_role")
        return role
    
    def get_open_ports(name):
        load=Json.InspectTEST(name).get("visible_node")
        role=load.get("open_ports")
        return role
    def get_ttl(name):
        load=Json.InspectTEST(name).get("visible_node")
        role=load.get("ttl")
        return role

    def get_ip(name):
        load=Json.InspectTEST(name).get("visible_node")
        role=load.get("ip")
        return role

    
class GhostBuster():
    "name değişkeni role finder vs. gelen verilere göre belirlenir bu sayede liste istediğimiz kadar büyütülebilir"
    @staticmethod
    def Role_Match(name):
        dns=TEST.get_dns_role(name)
        port=TEST.get_port_role(name)
        if port == dns:
            return 1
        else:
            return 0
    @staticmethod
    def Dependency_names(name):
        role=Json.InspectMatrix(name)
        #role_name = role[0]["role_name"]
        role_names=[]
        for role_all in role:

            role_names.append(role_all["role_name"])

        return role_names
            
       
        #return role_names
    @staticmethod
    def Dependency_ports(name):
        role=Json.InspectMatrix(name)
        role_ports=[]
        
        for role_all in role:
            role_ports.append(role_all["discriminative_ports"])

        return role_ports
    @staticmethod
    def Dependency_score(name):
        role=Json.InspectMatrix(name)
        role_scores=[]
        for role_all in role:
            role_scores.append(role_all["probability"])
            #role_score=role["probability"]
        return role_scores

    def Dependency_port_weight(name):
        role=Json.InspectMatrix(name)
        port_scores=[]
        for role_all in role:
            port_scores.append(role_all["port_weight"])
            #role_score=role["probability"]
        return port_scores

    @staticmethod
    def Bayes(port_match,ttl_glitch,prior_probability,role_match):
        model = DiscreteBayesianNetwork([
            ('Ghost_Node', 'Port_Match'),
            ('Ghost_Node', 'TTL_Anom'),
            ('Ghost_Node', 'Role_Match')
        ])
        cpd_ghost = TabularCPD(
                    variable='Ghost_Node',
                    variable_card=2,
                    values=[[1 - prior_probability],  # 0: Ghost Node Yok 
                            [prior_probability]]       # 1: Ghost Node Var
                )
        cpd_port = TabularCPD(
            variable='Port_Match', variable_card=2,
            values=Json.InspectCPD("Port_Match"),  # [Ghost=0 iken Port=1, Ghost=1 iken Port=1]
            evidence=['Ghost_Node'], evidence_card=[2]
        )
        cpd_ttl = TabularCPD(
            variable='TTL_Anom', variable_card=2,
            values=Json.InspectCPD("TTL_Anom"),

            evidence=['Ghost_Node'], evidence_card=[2]
        )
        
        cpd_role = TabularCPD(
            variable="Role_Match", variable_card=2,
            values=Json.InspectCPD("Role_Match"),
            evidence=['Ghost_Node'], evidence_card=[2]
        )
        #prior_probability = 0.90#dependency matrixten alıcaz bunu ghost başına 

        
        model.add_cpds(cpd_ghost, cpd_port, cpd_ttl, cpd_role)
        assert model.check_model()
        infer = VariableElimination(model)
        live_evidence = {
            'Port_Match': int(port_match),
            'TTL_Anom': int(ttl_glitch),
            'Role_Match': int(role_match)
        }
        
        posterior_result = infer.query(variables=['Ghost_Node'], evidence=live_evidence)
        #print(posterior_result)
        prob_not_ghost = posterior_result.values[0]  # P(Ghost_Node = 0) -> Normal Düğüm
        prob_is_ghost  = posterior_result.values[1]  # P(Ghost_Node = 1) -> Ghost Node
        GHOST_THRESHOLD = 0.70
        is_ghost_decision = bool(prob_is_ghost >= GHOST_THRESHOLD)
        if is_ghost_decision is True:
            return 1
        else:
            return 0
        #return posterior_result


    def overlap_for_ports(test_ports, dep_ports,port_weights):
       #ileride weighted hale getirilecek
        set_live = set(dep_ports)
        set_target = set(test_ports)
        

        intersection = set_live.intersection(set_target)

        if test_ports and isinstance(test_ports[0], list):
            test_ports = test_ports[0]
        
        if dep_ports and isinstance(dep_ports[0], list):
            dep_ports = dep_ports[0]
        
        if port_weights and isinstance(port_weights[0], list):
            port_weights = port_weights[0]


        matrix_weight_map = dict(zip(dep_ports, port_weights))
        
        #print(intersection)
        inter_weights=0.0
        
        for a in intersection:
            port_weight = matrix_weight_map.get(a, 0.0)
            inter_weights+=port_weight

        # Birleşim kümesi boşsa sıfır bölme hatasını engelle
        if not intersection:
            return 0.0
        
        min_cardinality = min(len(set_live), len(set_target))
        if min_cardinality == 0:
            return 0.0


        overlap_normal=len(intersection) / min_cardinality
        overlap_weighted= overlap_normal+inter_weights
        #print("overlap_normal")
        #print(overlap_normal)
        #print("overlap weighted")
        #print(overlap_weighted)
        #print("inter weights")
        #print(inter_weights)
        
        return overlap_normal+inter_weights


    @staticmethod
    def port_match(test_name,port_list,weight):
        #overlap coeffiecnt ile belli bir skorun üstündeyse tetiklenmesini isteyeceğim
        #Dep_portlist=GhostBuster.Dependency_ports(name_compare)
        test_portlist=TEST.get_open_ports(test_name)
        
        #print(GhostBuster.overlap_for_ports(test_portlist,port_list))
            
        if  GhostBuster.overlap_for_ports(test_portlist,port_list,weight) >= 0.50:
                
            return 1

        return 0 
    @staticmethod
    def TTL(name):
        if TEST.get_ttl(name) == (64 or 128 or 255):
            return 0
        else:
            return 1
        
    def Decide(name):
        
        role=TEST.get_port_role(name)
        
        
        dep_name=GhostBuster.Dependency_names(role)
        dep_port=GhostBuster.Dependency_ports(role)
        dep_score=GhostBuster.Dependency_score(role)
        dep_weight=GhostBuster.Dependency_port_weight(role)
        for names,ports,scores,weight in zip(dep_name,dep_port,dep_score,dep_weight):
            #print(weight)
            port = GhostBuster.port_match(name,ports,weight)
            ttl = GhostBuster.TTL(name)
            match = GhostBuster.Role_Match(name)
            ip = TEST.get_ip(name)
            #role_match = GhostBuster.Roles()
            #print(match)
            #print("-"*20)
            #print(names+"\n")
            #print(GhostBuster.Bayes(port,ttl,scores,match))
            
            if GhostBuster.Bayes(port,ttl,scores,match) == 1:
                """
                print("Node")
                print("-"*20)
                print(role)
                print("-"*20)
                print("Ghost Node")
                print("-"*20)
                print(names)
                """
                output = ({
                    "Node Ip": ip,
                    "Node Role":role,
                    "Ghost":names
                    
                })
                
                json_output = json.dumps(output)
                Write.writeJson(json_output)
            else:
                pass

        
        #print(final_json_output)
        #return final_json_output

            
        
    def ScanTESTS():
        delete_past.zerOutput()
        names=Json.AllTESTnames()
        for name in names:
            print(name)
            print("*"*20)
            GhostBuster.Decide(name)

    
GhostBuster.ScanTESTS()
#GhostBuster.Decide("TC-02")     



"""
test_role=TEST.get_port_role("TC-01")
test_ports=TEST.get_open_ports("TC-01")
test_ttl=TEST.get_ttl("TC-01")"""
    #def compare_expected_ghosts():



