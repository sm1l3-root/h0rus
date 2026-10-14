from rolefinder.parser import ParserforRolefinder
from rolefinder.Results2buster import Json
from relation.GhostBuster import GhostBuster
from pivotscore.PivotScore import PivotScore
from report.NodeEdge import NodeEdge
from report.gui import gui

print("*"*20)
print("welcome to h0rus")
print("*"*20)
ParserforRolefinder.writeJson("rolefinder/outputforport2role.json") 
Json.role2json()
GhostBuster.ScanTESTS()
PivotScore.Calculate()
gui.generate_topology_map(NodeEdge.CollectGs())

