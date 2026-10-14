import os 
import sys
import json
from itertools import groupby
import math
class Json():
    @staticmethod
    def OpenScores():
        file = open("pivotscore/role_score.json","r+")
        return file.read()
    @staticmethod
    def OpenBusteds():
        with open("relation/output.jsonl", "r", encoding="utf-8") as file:
            for line in file:
                if line.strip():  # Boş satırları atla
                    yield json.loads(line)

    def CategoriseBusteds():
        stream = Json.OpenBusteds()
        for ip, group in groupby(stream, key=lambda x: x["Node Ip"]):
            ghosts = []
            node_role = None
        
            # Sadece o IP'ye ait elemanlar döngüye girer
            for item in group:
                if not node_role:
                    node_role = item["Node Role"]
                ghosts.append(item["Ghost"])
        
            # 3. İlgili IP'nin tüm Ghost'ları toplandı, istediğin çıktıyı üret
            grouped_result = {
                "Node_Ip": ip,
                "Node_Role": node_role,
                "Ghost_Nodes": ghosts,
                "Ghost_Count": len(ghosts)
            }
            yield grouped_result

    def zerOutput():
        file_path = "pivotscore/pivotscores.jsonl"
                    
        try:          
            if os.path.getsize(file_path) > 0:
                with open(file_path, "w") as file:
                    pass 
        except:
            pass
        
    
     
    def openOutput():
        file = open("pivotscore/pivotscores.jsonl","a")
        return file
    
    def Output(scores):
        dumpedData= json.dumps(scores)
        Json.openOutput().write(dumpedData+"\n")

class PivotScore():
    @staticmethod
    def getRoleScores(roles):
        Matrixdata = json.loads(Json.OpenScores())["Role_Scores"]
        scores=[]
        
        for role in roles:
            get_role=Matrixdata[role]
            get_role_data=get_role["score"]
            scores.append(1+get_role_data)

        return scores


    
    #print(getRoleScores(["Database_Server","Internal_DNS_Server"]))
    
    @staticmethod
    def Calculate():
        Json.zerOutput()
        scores=[]
        ips=[]
        data = Json.CategoriseBusteds()
        for i in data:
            ip = i["Node_Ip"]
            role = i["Node_Role"]
            ghosts = i["Ghost_Nodes"]
            count = i["Ghost_Count"]
            
            try:
                score=PivotScore.getRoleScores(ghosts)
                average=math.fsum(score)/len(score)
                sqrt_of_average=math.sqrt(average)

                pivotscore=count*(average**sqrt_of_average)
                ips.append(ip)
                scores.append(pivotscore)
                print("Node ip: ",ip," "+"pivotscore: ",pivotscore)
            except:
                print("role is not able to find in role_score file")

        
        #print("bunu hackle:",ips[scores.index(max(scores))])
        for ip,score in zip(ips,scores):
            data=({"ip":ip,"score":score})
            Json.Output(data)
        
PivotScore.Calculate()


            


        
    