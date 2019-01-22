from pyclass_infoflow import *
import os
import sqlite3
import time
from neo4j.v1 import GraphDatabase
#Configurations:
#dev = "HUAWEI_P20"

user="neo4j"
password="123"

#

def run_betweenness_centrality(tx):
	label = "label" #all nodes were labeled as "label"
	target_relationship = "path" #or "channel","allow"
	cql = 'CALL algo.betweenness.stream(\'%s\',\'%s\',{direction:"both"}) \
			YIELD nodeId, centrality \
			MATCH (node:%s) WHERE id(node) = nodeId \
			RETURN node.name AS node,centrality \
			ORDER BY centrality DESC;'%(label,target_relationship,label)

	return tx.run(cql)

def run_KshortestPath(session,src,dst):
	#all paths' cost in default are set to 1.
	path_num = 3 #the first path_num of shortestpaths will be returned 
	cql1 = "MATCH (start:label{name:\'%s\'}), (end:label{name:\'%s\'}) \
			CALL algo.kShortestPaths(start, end, 3, 'cost' ,{}) \
			YIELD resultCount \
			RETURN resultCount" % (src,dst)
	print cql1

	result_paths = []

	for i in range(path_num):
		cql2 = 'MATCH p=()-[r:PATH_%s]->() RETURN p '%str(i)
		result_paths.append(session.run(cql2))

		cql3 = 'MATCH p=()-[r:PATH_%s]->() delete r'%str(i)
		session.run(cql3)
	#print result_paths
	return result_paths

if __name__ == '__main__':
	driver = GraphDatabase.driver("bolt://localhost:7687",auth = (user,password))
	with driver.session() as session:
		tx = session.begin_transaction()
		#Call the algo to get result:

		'''
		#1.betweenness_centrality algorithm
		#result = run_betweenness_centrality(tx) #path centrality
		for record in result :
			print record

		'''
		
		#2.Kshortestpath algorithm
		result_list = run_KshortestPath(session,"isolated_app","system_server")
		for i in result_list:
			for record in i :
				print record[0]._nodes[0].graph
			