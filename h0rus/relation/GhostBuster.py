#bayes teoremi kullanılacak
#dependency matrix ile eldeki ip lerin rolleri karşılaştırılacak
#Relation finder algoritmasının verdiği relationlar kanıt olarak sunulacak
#portlar rolle birlikte kanıt olarak sunulacak
#TTL okuma ile test edilecek ve ona göre confidence artacak
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
    
class GhostBuster():
    "name değişkeni role finder vs. gelen verilere göre belirlenir bu sayede liste istediğimiz kadar büyütülebilir"
    def Dependency_names(name):
        role=Json.InspectMatrix(name)
        #role_name = role[0]["role_name"]
        role_names=[]
        for role_all in role:

            role_names.append(role_all["role_name"])

        return role_names
            
       
        #return role_names

    def Dependency_ports(name):
        role=Json.InspectMatrix(name)
        role_ports=[]
        
        for role_all in role:
            role_ports.append(role_all["typical_ports"])

        return role_ports

    def Dependency_score(name):
        role=Json.InspectMatrix(name)
        role_scores=[]
        for role_all in role:
            role_scores.append(role_all["probability"])
            #role_score=role["probability"]
        return role_scores[1]

    def Bayes(port_match,ttl_glitch,prior_probability):
        model = DiscreteBayesianNetwork([
            ('Ghost_Node', 'Port_Match'),
            ('Ghost_Node', 'TTL_Anom')
        ])
        cpd_ghost = TabularCPD(
                    variable='Ghost_Node',
                    variable_card=2,
                    values=[[1 - prior_probability],  # 0: Ghost Node Yok (%10)
                            [prior_probability]]       # 1: Ghost Node Var (%90)
                )
        cpd_port = TabularCPD(
            variable='Port_Match', variable_card=2,
            values=[[0.85, 0.15],   # [Ghost=0 iken Port=0, Ghost=1 iken Port=0]
                    [0.15, 0.85]],  # [Ghost=0 iken Port=1, Ghost=1 iken Port=1]
            evidence=['Ghost_Node'], evidence_card=[2]
        )
        cpd_ttl = TabularCPD(
            variable='TTL_Anom', variable_card=2,
            values=[[0.80, 0.30],
                    [0.20, 0.70]],

            evidence=['Ghost_Node'], evidence_card=[2]
        )
        #prior_probability = 0.90#dependency matrixten alıcaz bunu ghost başına 

        
        model.add_cpds(cpd_ghost, cpd_port, cpd_ttl)
        assert model.check_model()
        infer = VariableElimination(model)
        live_evidence = {
            'Port_Match': int(port_match),
            'TTL_Anom': int(ttl_glitch)
        }
        posterior_result = infer.query(variables=['Ghost_Node'], evidence=live_evidence)
        return posterior_result
    def port_match(name_compare,test_name):
        Dep_portlist=GhostBuster.Dependency_ports(name_compare)
        test_portlist=TEST.get_open_ports(test_name)
        
        for port_test in set(test_portlist):
            if port_test in Dep_portlist:
                return 1

        return 0 
                

                
                        

        
    




class TEST():
    def get_port_role(name):
        load=Json.InspectTEST(name).get("visible_node")
        role=load.get("port_role")
        return role

    """def get_dns_role(name):
        load=Json.InspectTEST(name).get("visible_node")
        role=load.get("dns_role")
        return role"""
    def get_open_ports(name):
        load=Json.InspectTEST(name).get("visible_node")
        role=load.get("open_ports")
        return role
    def get_ttl(name):
        load=Json.InspectTEST(name).get("visible_node")
        role=load.get("ttl")
        return role
"""
test_role=TEST.get_port_role("TC-01")
test_ports=TEST.get_open_ports("TC-01")
test_ttl=TEST.get_ttl("TC-01")"""
    #def compare_expected_ghosts():
def TTL(name):
    if TEST.get_ttl(name) == (64 or 128 or 255):
        return 0
    else:
        return 1

port = GhostBuster.port_match("Domain_Controller","TC-03")
ttl = TTL("TC-03")
dep = GhostBuster.Dependency_score("Domain_Controller")
print(GhostBuster.Bayes(port,ttl,dep))
