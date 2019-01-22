#from py2neo import Graph,Node,Relationship,cypher,NodeSelector,NodeSelection
import os
import sqlite3
from neo4j.v1 import GraphDatabase


#####GLOBAL CONFIGS#######
#dev = "HUAWEI_P20"
dev_list = ["Pixel","HUAWEI_P20","mi8se"]
config_workdir = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/"
config_sepolicy_file = config_workdir + "%s/vendor_etc_selinux/selinux/sepolicy_dec"
config_seinfo_file = config_workdir +"%s/vendor_etc_selinux/selinux/seinfo_all"
config_csv_policy = config_workdir +"/csv_policy/%s/csv_policy.csv"
user="neo4j"
password="123"

#####GLOBAL SETTINGS####################

#this will exclued policy rule targeting at itself;
#FOR EXAMPLE,this rule will be igonored : allow vold,vold,unix_stream_socket,ioctl 
config_exclude_self = True 

#All the rules related to attributed will be expanded to the domains it belongs
config_expand_attr = True

#####


#Generate attribute dic from seinfo result:
'''
bluetoothdomain
      platform_app
      priv_app
      radio
      system_server
      untrusted_app
      untrusted_app_25
      untrusted_v2_app

will generate such an entry:
attribute_dic["bluetoothdomian"] = ["platform_app","priv_app",..."untrusted_v2_app"]

The dic will be used when parsing sepolicy rules. All the rules related to 
bluetoothdomain will be expanded as :
allow platform_app type class permissions
allow priv_app ....
...
allow untrusted_v2_app .... 
'''
def gen_attribute_dic(seinfo_file):
	attribute_dic = dict()
	with open(seinfo_file,"r") as f:
		while(True):
			line = f.readline()
			if line.startswith("Attributes:"):
				#print line
				f.seek(f.tell(),0)
				break
		#f.seek to where attributes info starts
		attribute = ""
		while (True):
			content = f.readline().strip("\n")
			#print content
			if content.startswith("   "):
				if (content.startswith("      ")):
					attribute_dic[attribute].append(content.strip(" "))
					
				else:
					attribute = content.strip(" ")
					attribute_dic[attribute]=list()
			else:
				#neither attribute nor domain
				break


	return attribute_dic

		





#parse_sepolicy:
#General sepolicy format-------allow domains types : classes permissions;
#input:sepolicy file
#output: av_dic = {"domains":domains,"types":types,"classes":classes,"permissions":permissions}
#
def parse_sepolicy(sepolicy_file):
	av_dics = []
	count = 0
	with open(sepolicy_file) as f:
		for line in f:
			if count % 1000 == 0:
				print "%d lines of rules have been added\n"% count
			line = line.strip()
			#print line
			if line.startswith("allow"):
				label_group = line.split(" ")
				domains = label_group[1]
				types = label_group[2]
				if config_exclude_self == True:
					if (domains == types):
						continue
				if config_expand_attr == True:
					#domain and type will be transformed into lists
					attribute_dic = gen_attribute_dic(seinfo_file)
					if attribute_dic.has_key(domains):
						domain_list = attribute_dic[domains]
					else:
						#no such attr,use domain name directly
						domain_list = list()
						domain_list.append(domains)
					if attribute_dic.has_key(types):
						#print "has_key:%s"%types
						type_list = attribute_dic[types]
					else:
						#no such attr,use domain name directly
						type_list = list()
						type_list.append(types)
					
					for domain in domain_list:
						for _type in type_list:
							assert label_group[3] == ":"
							classes = label_group[4]
							permissions = label_group[5:-1]
							if ("{" in permissions) or ("}" in permissions):
								permissions.remove("{")
								permissions.remove("}")

							av_dic = {"domain":domain,"type":_type,"class":classes,"permissions":permissions}
							av_dics.append(av_dic)

				else:
					#not expand attr;
					assert label_group[3] == ":"
					classes = label_group[4]
					permissions = label_group[5:-1]
					if ("{" in permissions) or ("}" in permissions):
						permissions.remove("{")
						permissions.remove("}")

					av_dic = {"domain":domains,"type":types,"class":classes,"permissions":permissions}
					av_dics.append(av_dic)

			count += 1

	return av_dics


#write_policy_to_csv:
#csv file of access vector: domain-[:allow{class:permission}]->types
#For example : allow manufacture_app proc : file { ioctl read write getattr lock open } will be write as:
#domain,type,class,permission
#manufacture_app,proc,file,ioctl
#manufacture_app,proc,file,read
#...,....,...,...

def write_policy_to_csv(av_dics):
	with open(csv_policy,'w') as f:
		f.write("domain,type,class,permission")
		for av_dic in av_dics:
			for permission in av_dic["permissions"]:
				line_to_write = '\n'
				line_to_write += av_dic["domain"] + "," + av_dic["type"] + "," + av_dic["class"]+","
				line_to_write += permission
				f.write(line_to_write)






#gen_graph:
#import generated csv_file into neo4j:
#NOTE THAT : regard both "domain" and "type" as "label",since both of them are regarded as a point in attack graph
#merge (a:label{name:"manufacture"})
#merge (b:label{name:"proc"})
#merge (a)-[:allow{file:"ioctl"}]->(b)
#merge (a)-[:allow{file:"read"}]->(b)
#merge ...etc
def gen_graph(csv_file):
	csv_file = csv_file.replace("\\","/")
	print "Loading csv file: %s\n"%csv_file
	cql = ''
	cql += "USING PERIODIC COMMIT 5000 \n"
	cql += "LOAD CSV WITH HEADERS FROM \"file://"+csv_file +"\" AS line \n"
	cql += " Merge (a:label{name:line.domain,dev:\"%s\"})\n"%dev
	cql += " Merge (b:label{name:line.type,dev:\"%s\"})\n"%dev
	cql += " Merge (a)-[:allow{class:line.class,permission:line.permission}] -> (b)\n"
	#graph = Graph(host="localhost",http_port=7474,bolt_port=7687,user=user,password=password)
	driver = GraphDatabase.driver("bolt://localhost:7687",auth = (user,password))
	with driver.session() as session:
		#graph.run("CREATE INDEX ON:type(name)")
		print cql
		session.run(cql)
		session.run("CREATE INDEX ON:label(name)")

	
def add_typetrans_connection(sepolicy_file):
	driver = GraphDatabase.driver("bolt://localhost:7687",auth = (user,password))
	#graph = Graph(host="localhost",http_port=7474,bolt_port=7687,user=user,password=password)
	with open(sepolicy_file) as f:
		for line in f:
			line = line.strip()
			if line.startswith("type_transition") and ": process" in line:
				#only considering process type_transition, which is related to execute
				source_type = line.split(" ")[1]
				target_type = line.split(" ")[2]
				trans_target = line.split(" ")[5].strip(";\n")
				cql = ''
				cql += 'Match (a{name:\"%s\",dev:\"%s\"}),(b{name:\"%s\",dev:\"%s\"}) '\
						% (source_type,dev,trans_target,dev)
				cql += 'Merge (a)-[:type_transition{class:"process",intermedia:\"%s\"}]->(b)'%(target_type)
				print cql
				#graph.run(cql)
				with driver.session() as session:
					#graph.run("CREATE INDEX ON:type(name)")
					session.run(cql)
					session.run("CREATE INDEX ON:label(name)")
				





if __name__ == '__main__':

	for dev in dev_list:
		print "dev:",dev
		sepolicy_file = config_sepolicy_file%dev
		seinfo_file = config_seinfo_file%dev
		csv_policy = config_csv_policy%dev
		if not os.path.exists(os.path.dirname(csv_policy)):
			os.mkdir(os.path.dirname(csv_policy))

		print sepolicy_file,seinfo_file,csv_policy

		av_dics = parse_sepolicy(sepolicy_file)
		print len(av_dics)
		write_policy_to_csv(av_dics)

		gen_graph(csv_policy)

		#newly added function:used to parse type_transition rules in sepolicy
		add_typetrans_connection(sepolicy_file)

		#find_deputy_path()