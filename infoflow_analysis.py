#The code will generate a new subgraph in infomation flowing view;
#relationship between nodes are rather "allow" but "infoflow" 
#it will directly modify all the connections in original sepolicy graph.
#1.add connections between dirct-nodes (such as :file open -> channel,dataflow)
#2.add connections based on calculation of original se-vector (sevice_manager\execute)

#!!!abandoned. Use "infoflow_analysis_basedon_ori.py" instead.

from pyclass_infoflow import *
from py2neo import Graph,Node,Relationship,cypher,NodeSelector,NodeSelection
import os
import sqlite3
from neo4j.v1 import GraphDatabase


dev = "HUAWEI_P20"
csv_policy = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/csv_policy/%s/csv_policy.csv"%dev
csv_info_flow = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/csv_policy/%s/csv_info_flow.csv"%dev
csv_channel = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/csv_policy/%s/csv_channel.csv"%dev
user="neo4j"
password="123"



# This will anaylyse a line read from csv_policy.csv;
# info_type is a list about which types of information can be transfered depending on class:permission set;
# Return a line to be write to new csv_info_flow.csv
def write_to_csv(line,info_flow_csv,channel_csv):
	line_splited = line.strip("\n").split(",")
	domain = line_splited[0]
	typee = line_splited[1]
	claz = line_splited[2]
	perm = line_splited[3]
	operation = op(claz,perm)
	if operation.ischannel:
		#write a line for channel vector:
		if operation.direction == 0:
			#write_like channel such as socket connectto (->)
			line_to_write = domain + ","   #src,channel,
			line_to_write += operation.channel + ","#info_type
			line_to_write += typee
		else:
			line_to_write = typee + "," #src,channel,
			line_to_write += operation.channel + ","#info_type
			line_to_write += domain
		line_to_write += "\n"
		#print "[CHANNEL]" + line_to_write
		channel_csv.write(line_to_write)
	if operation.data_type != None:
		#write a line for dataflow vector:
		if operation.direction == 0:
			#write_like channel such as socket connectto (->)
			line_to_write = domain  + "," #src,channel,
			line_to_write += operation.data_type.name + "," #info_type
			line_to_write += typee
		else:
			line_to_write = typee + ","  #src,channel,
			line_to_write += operation.data_type.name  + ","#info_type
			line_to_write += domain
		line_to_write += "\n"
		#print "[INFO]"+line_to_write
		info_flow_csv.write(line_to_write)
	del operation #free memory
	

def policy_csv_transfer(csv_policy):
	#return the files'names of output csv_info_flow file
	with open(csv_policy,"r") as fin:
		with open(csv_info_flow,"w") as infoflow_out:
			with open(csv_channel,"w") as channel_out:
				channel_out.write("src,info_type,dest\n")
				infoflow_out.write("src,info_type,dest\n")
				for line_in in fin:
					#f.write(info_analy(line_in))
					 write_to_csv(line_in,infoflow_out,channel_out)
	return csv_info_flow,csv_channel

def gen_infoflow_graph(session,csv_file):
	print "[Importing data from csv_file:%s\n]"%csv_file
	csv_file = csv_file.replace("\\","/")
	print "Loading csv file: %s\n"%csv_file
	cql = ''
	cql += "USING PERIODIC COMMIT 5000 \n"
	cql += "LOAD CSV WITH HEADERS FROM \"file://"+csv_file +"\" AS line \n"
	cql += " Merge (a:label{name:line.src,dev:\"%s\"})\n"%dev
	cql += " Merge (b:label{name:line.dest,dev:\"%s\"})\n"%dev
	cql += " Merge (a)-[r:dataflow{info_type:line.info_type}] -> (b)"

	session.run("CREATE INDEX ON:label(name)")

	print cql
	session.run(cql)
	session.commit()

def gen_channel_graph(session,csv_file):
	print "[Importing data from csv_file:%s\n]"%csv_file
	csv_file = csv_file.replace("\\","/")
	print "Loading csv file: %s\n"%csv_file
	cql = ''
	cql += "USING PERIODIC COMMIT 5000 \n"
	cql += "LOAD CSV WITH HEADERS FROM \"file://"+csv_file +"\" AS line \n"
	cql += " Merge (a:label{name:line.src,dev:\"%s\"})\n"%dev
	cql += " Merge (b:label{name:line.dest,dev:\"%s\"})\n"%dev
	cql += " Merge (a)-[r:channel{info_type:line.info_type}] -> (b)"

	session.run("CREATE INDEX ON:label(name)")
	#graph.run("CREATE INDEX ON:type(name)")
	print cql
	session.run(cql)
	

def build_binder_channel(session):
	#Firstly get all paths like this:
	# a-[channel:{info_type:service_handler}]-> xxx_service <- [info_type:service_handler]
	cql1 = r'match p = (s)-[:channel{info_type:"service_handler"}]->(service_manager)-[:channel{info_type:"service_handler"}]->(c) return p limit 10 '
	tx = session.begin_transaction()

	for record in tx.run(cql1):
		print record[0].start
		print "--\n"
		exit()

					
#Check whether dataflow and channel vectors are consistent, and merge the 
def merge_path(tx):
	pass

if __name__ == '__main__':
	driver = GraphDatabase.driver("bolt://localhost:7687",auth = (user,password))
	with driver.session() as session:
		#-----
		#Creating graph:
		#gen_channel_graph(session,csv_channel)
		add_dirct_connection(session) #compute the binder channel
		#gen_infoflow_graph(tx,csv_info_flow)
		#----
		#calculating relationship transfer:
		#merge_path(tx)

	#import_into_neo(info_flow)
	#generate_neverallow_csv(platform_cil,nonplatform_cil)
