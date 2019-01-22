#The code will generate a new subgraph in infomation flowing view;
#relationship between nodes are rather "allow" but "infoflow" 
#it will directly modify all the connections in original sepolicy graph.
#1.add connections between dirct-nodes (such as :file open -> channel,dataflow)
#2.add connections based on calculation of original se-vector (sevice_manager\execute)

from pyclass_infoflow import *
from py2neo import Graph,Node,Relationship,cypher,NodeSelector,NodeSelection
import os
import sqlite3
import time
from neo4j.v1 import GraphDatabase

#Configurations:
#dev = "HUAWEI_P20"

user="neo4j"
password="123"
path_count=0

#Function defines:
def add_dirct_connection(session):
	cql1 = "match p= (a)-[:allow]->(b) return p"
	tx = session.begin_transaction()
	perm_list = ["setopt","sendto","set","transition",\
				"sigchld","append","write","write","call","transfer",\
				"signal","sigstop","sigkill","ptrace","add","connect",\
				"connectto","getopt","recvfrom","read","read","open",\
				"use","execute","execute_no_trans","find","accept"] #only consider this perms

	spetial_list = ["execute","add","find"] #deal it later

	#Main loop:
	
	print "start loop\n"
	count = 0 
	print "Entering loop"
	result = tx.run(cql1)
	for record in result:
		count += 1
		if count % 10000 == 0:
			print "count:%d"%count

		claz = record[0]._relationships[0]._properties["class"]
		perm = record[0]._relationships[0]._properties["permission"]
		if (perm in spetial_list) :
			# we will work on it later
			continue


		op_obj = op(claz,perm)
		if (op_obj.direction == -1):
			#Not our target 
			del op_obj
			continue

		#Connect normal nodes
		start_node = record[0].start._properties["name"]
		end_node = record[0].end._properties["name"]
		dev = record[0].end._properties["dev"]
		info_type = op_obj.data_type
		direction = op_obj.direction
		channel = op_obj.channel
		channel_direction = op_obj.channel_direction
		cql2 = ''
		cql3 = ''
		if info_type !=None:
			if direction == 0:
				#write-like ops
				#cql2 is used to add dataflow connection between start and end nodes
				cql2 = " Match (a:label{name:\"%s\",dev:\"%s\"}),(b:label{name:\"%s\",dev:\"%s\"}) Merge (a)-[:dataflow{name:\"%s\"}]->(b)"\
						%(start_node,dev,end_node,dev,info_type.name)
			else:
				#read-like ops
				cql2 = " Match (a:label{name:\"%s\",dev:\"%s\"}),(b:label{name:\"%s\",dev:\"%s\"}) Merge (a)-[:dataflow{name:\"%s\"}]->(b)"\
						%(end_node,dev,start_node,dev,info_type.name)

		if channel != "":
			#channel has its direction
			if channel_direction == 2:
				#open
				cql3 = " Match (a:label{name:\"%s\",dev:\"%s\"}),(b:label{name:\"%s\",dev:\"%s\"}) Merge (a)-[:channel{name:\"%s\"}]->(b)  Merge (a)<-[:channel{name:\"%s\"}]-(b)"\
						%(start_node,dev,end_node,dev,channel,channel)
			if channel_direction == 0:
				#direction out
				cql3 = " Match (a:label{name:\"%s\",dev:\"%s\"}),(b:label{name:\"%s\",dev:\"%s\"}) Merge (a)-[:channel{name:\"%s\"}]->(b)"\
						%(start_node,dev,end_node,dev,channel)

			if channel_direction == 1:
				#direction in
				cql3 = " Match (a:label{name:\"%s\",dev:\"%s\"}),(b:label{name:\"%s\",dev:\"%s\"}) Merge (a)<-[:channel{name:\"%s\"}]-(b)"\
						%(start_node,dev,end_node,dev,channel)



		#Commit cql:
		if cql2!="":
			tx.run(cql2)
		if cql3!="":
			tx.run(cql3)
	
	# End of record traverse	
	tx.commit()
	print "End of loop! Normal relationships are transfered into dataflow&channel connections\n"


def create_binder_channel(session):
	#if a-[service_manager:find]->(b)<-[service_manager:find]-(c)
	#then a-[:channel{name:"binder_channel",intermedia:b.name}]-(c)
	cql1 = 'Match p = (a)-[:allow{class:"service_manager",permission:"find"}]->(b)<-[:allow{class:"service_manager",permission:"add"}]-(c)\
			 with a,b,c merge (a)-[:channel{name:"binder_channel",intermedia:b.name}]->(c)'
	tx = session.begin_transaction()
	result = tx.run(cql1)
	tx.commit()

	print "[create_binder_channel] Finished"
	return result

def create_exec_channel(session):
	#create both channel and dataflow for execute operation  
	cql1 = 'match p = (b)<-[:type_transition]-(a)-[r:allow{permission:"execute"}]->(f) where (a)-[:allow{permission:"transition"}]-(b) '
	cql1 += 'merge (a)<-[:channel{name:"file_execute"}]-(f) merge (a)<-[:dataflow{name:"execflow"}]-(f)'
	#cql1 += 'with a,f, delete r where (a)<-[r:dataflow{name:"ptrace"}]-(f)'
	tx = session.begin_transaction()
	result = tx.run(cql1)
	tx.commit()
	print "[create_exec_channel] Finished"
	return result

def add_x_path(session,channel,src,dst):
	#print "[Adding_x_path]:", channel,src,dst
	canpass_dic = {"socket_opt":["socket_opt"],\
					"socket":["socket_content"],\
					"property":["property"],\
					"proc_control":["ptrace","transition","sigchld","signal","signal_stop","kill"],\
					"file":["file_content","fd"],\
					"binder_channel":["parcel_normal","parcel_binder","fd"],\
					"file_execute":["execflow"]}
	canpassdata_list = canpass_dic[channel]
	cql2 = 'match p=(a{name:\"%s\"})-[r:dataflow]->(b{name:\"%s\"}) \
			with r,a,b where exists(r.name) merge (a)-[:path{name:r.name}]->(b)'\
			%(src,dst)
	dataflow_result = session.run(cql2)

	return 

def create_path(session):
	#query for all connection with "channel" label.
	#and check whether there exists a dataflow between two nodes 
	

	cql1 = "match p= (a)-[:channel]->(b) return p" 
	
	print "[create_path]\n"
	count = 0 
	result = session.run(cql1)
	for record in result:
		count += 1
		if count % 10000 == 0:
			print "count:%d"%count

		channelname = record[0]._relationships[0]._properties["name"]
		src =  record[0].start._properties["name"]
		dst = record[0].end._properties["name"]
		add_x_path(session,channelname,src,dst)

		'''
		if channelname == "socket_opt" :
			cql2 = 'match p=(a{name:\"%s\"})-[r:dataflow{name:socket_opt}]->(b{name:\"%s\"}) return p'%(src,dst)
			checkresult = tx.run(cql2)
			if (sum(1 for _ in checkresult.records()) != 0):
				#create path 
				cql3 = 'merge (a{name:\"%s\"})-[r:path{name:socket_opt}]->(b{name:\"%s\"}) '%(src,dst)

		if channelname == "socket" :
			cql2 = 'match p=(a{name:\"%s\"})-[r:dataflow{name:socket_content}]->(b{name:\"%s\"}) return p'%(src,dst)
			checkresult = tx.run(cql2)
			if (sum(1 for _ in checkresult.records()) != 0):
				#create path 
				cql3 = 'merge (a{name:\"%s\"})-[r:path{name:socket}]->(b{name:\"%s\"}) '%(src,dst)

		if channelname == "property" :
			cql2 = 'match p=(a{name:\"%s\"})-[r:dataflow{name:property}]->(b{name:\"%s\"}) return p'%(src,dst)
			checkresult = tx.run(cql2)
			if (sum(1 for _ in checkresult.records()) != 0):
				#create path 
				cql3 = 'merge (a{name:\"%s\"})-[r:path{name:property}]->(b{name:\"%s\"}) '%(src,dst)
		'''

#main function used for test.
if __name__ == '__main__':
	driver = GraphDatabase.driver("bolt://localhost:7687",auth = (user,password))
	with driver.session() as session:
		#-----
		#Creating graph:
		
		#time1 = time.clock()

		#add_dirct_connection(session) 
		#print "Time use:",time.clock()-time1	
	
		#compute  binder channel and exec channel

		#create_binder_channel(session) #service_manager:{find,add}
		#create_exec_channel(session) # file execute + type_transition

		#create path,i.e. Existing both channel and its related dataflow connection between two nodes
		create_path(session) #not used yet

		
