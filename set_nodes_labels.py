from py2neo import Graph,Node,Relationship,cypher,NodeSelector,NodeSelection
import os
import sqlite3
from neo4j.v1 import GraphDatabase


#####GLOBAL CONFIGS#######
dev = "HUAWEI_P20"
sepolicy_file = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/%s/vendor_etc_selinux/selinux/sepolicy_dec"%dev
csv_policy = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/csv_policy/csv_policy.csv"
user = "neo4j"
password = "123"

#####GLOBAL SETTINGS####################

#####Labels for permissions and domains####
user_domain = {"untrusted_app_all","untrusted_app_25","coredomain","untrusted_app","untrusted_app_27","untrusted_v2_app","bluetoothdomain","appdomain","netdomain","domain"}
#####################################
# Common groupings of object classes.
#
capability_class_set = {"capability","capability2","cap_userns","cap2_userns"}
global_capability_class_set = {"capability","cap_userns"}
global_capability2_class_set = {"capability2","cap2_userns"}
devfile_class_set = {"chr_file","blk_file"}
notdevfile_class_set = {"file","lnk_file","sock_file","fifo_file"}
file_class_set = devfile_class_set|notdevfile_class_set
dir_file_class_set = {"dir"}|file_class_set
socket_class_set = {"socket","tcp_socket","udp_socket","rawip_socket","netlink_socket","packet_socket","key_socket","unix_stream_socket","unix_dgram_socket","appletalk_socket","netlink_route_socket","netlink_tcpdiag_socket","netlink_nflog_socket","netlink_xfrm_socket","netlink_selinux_socket","netlink_audit_socket","netlink_dnrt_socket","netlink_kobject_uevent_socket","tun_socket","netlink_iscsi_socket","netlink_fib_lookup_socket","netlink_connector_socket","netlink_netfilter_socket","netlink_generic_socket","netlink_scsitransport_socket","netlink_rdma_socket","netlink_crypto_socket","sctp_socket","icmp_socket","ax25_socket","ipx_socket","netrom_socket","atmpvc_socket","x25_socket","rose_socket","decnet_socket","atmsvc_socket","rds_socket","irda_socket","pppox_socket","llc_socket","can_socket","tipc_socket","bluetooth_socket","iucv_socket","rxrpc_socket","isdn_socket","phonet_socket","ieee802154_socket","caif_socket","alg_socket","nfc_socket","vsock_socket","kcm_socket","qipcrtr_socket","smc_socket"}
dgram_socket_class_set = {"udp_socket","unix_dgram_socket"}
stream_socket_class_set = {"tcp_socket","unix_stream_socket"}
unpriv_socket_class_set = {"tcp_socket","udp_socket","unix_stream_socket","unix_dgram_socket"}
ipc_class_set = {"sem","msgq","shm","ipc"}
#####################################
#Common groupings of permissions.
#
x_file_perms = {"getattr","execute","execute_no_trans","map"}
r_file_perms = {"getattr","open","read","ioctl","lock","map"}
w_file_perms = {"open","append","write","lock","map"}
rx_file_perms = r_file_perms|x_file_perms
ra_file_perms = r_file_perms|{"append"}
rw_file_perms = r_file_perms|w_file_perms
rwx_file_perms = rw_file_perms|x_file_perms
create_file_perms = {"create","rename","setattr","unlink"}|rw_file_perms

r_dir_perms = {"open","getattr","read","search","ioctl","lock"}
w_dir_perms = {"open","search","write","add_name","remove_name","lock"}
ra_dir_perms = r_dir_perms|{"add_name","write"}
rw_dir_perms = r_dir_perms|w_dir_perms
create_dir_perms = {"create","reparent","rename","rmdir","setattr"}|rw_dir_perms

r_ipc_perms = {"getattr","read","associate","unix_read"}
w_ipc_perms = {"write","unix_write"}
rw_ipc_perms = r_ipc_perms|w_ipc_perms
create_ipc_perms = {"create","setattr","destroy"}|rw_ipc_perms
#####################################
#Common socket permission sets.
rw_socket_perms = {"ioctl","read","getattr","write","setattr","lock","append","bind","connect","getopt","setopt","shutdown"}
rw_socket_perms_no_ioctl = {"read","getattr","write","setattr","lock","append","bind","connect","getopt","setopt","shutdown"}
create_socket_perms = {"create"}|rw_socket_perms
create_socket_perms_no_ioctl = {"create"}|rw_socket_perms_no_ioctl
rw_stream_socket_perms = rw_socket_perms|{"listen","accept"}
create_stream_socket_perms = {"create"}|rw_stream_socket_perms


def set_user_domain_lable(tx):
	#cql = r'MATCH (n) where n.name = "untrusted_app_all" or n.name = "untrusted_app_25" or n.name = "untrusted_app_27" or n.name = "untrusted_app" or n.name = "bluetoothdomain" or n.name = "netdomain" or n.name = "appdomain" set n:user_domain'
	for i in user_domain:
		cql = r'MATCH (n) where n.name = "%s" set n:user_domain '%i
		print cql
		for record in tx.run(cql):
			print record

def get_userdomain_nodes(tx,dev):
	ret_list = []
	for record in tx.run(r"MATCH (n:user_domain{dev:{dev}}) return n",dev=dev):
		ret_list.append(record)

	#print "get_userdomain_nodes:%d"%len(ret_list)
	return ret_list

#Get all directly connected path in OEM device policy(i.e a-[]->b which means
#length of path is 1)
def get_direct_path(tx,dev):
	ret_list = []
	for record in tx.run(r"match path=(a:user_domain)-[]->(b) where a.dev={dev}  and a.name<>b.name  and not b:user_domain return path"\
		,dev = dev):
		ret_list.append(record)

	#print "get_direct_path:%d"%len(ret_list)
	return ret_list

#Paring the record in an OEM device so as to get the nodes in direct-connected
#nodes. These nodes are used to check whether they are still connected in AOSP
#device. all nodes CONNECTED BY user_domain reveal attack surface of the device,
#which are our main target. The results are not neo-driver objs but strings to be used in further cql
#
#return : a list of dic{"target_context":"proc_net",class:"dir",permission:"search"}

#
def parsing_path_record(path_record):
	ret_list = [] #save the nodes connected by user_domain with their relationships in OEMs
	for record in path_record:
		record_dict = dict()
		record_dict["target_context"] = record["path"].end_node._properties["name"]
		record_dict["class"] = record["path"].relationships[0]._properties['class']
		record_dict["permission"] = record["path"].relationships[0]._properties['permission']
		#print record_dict
		ret_list.append(record_dict)

	return ret_list


#This will return :
#1. ret_list: a list of dicts containing unmatched paths(including relationships) in OEM 
#2. target_context_set: the set of all the context in path
def match_target_in_aosp(tx,OEM_context_list,aosp_dev):
	ret_list = []
	target_context_set = set()
	count_i = 0
	for record_dict in OEM_context_list:
		#if count_i % 50 == 0:
			#print "Complete:%d/%d"%(count_i,len(OEM_context_list))

		count_i += 1 
		name = record_dict["target_context"]
		_class = record_dict["class"]
		permission = record_dict["permission"]
		cql = r"MATCH p=(n:user_domain{dev:{aosp_dev}})"
		cql += r"-[r:allow{class:{_class},permission:{permission}}]->"
		cql += r"(m{dev:{aosp_dev},name:{name}})"
		cql += r" return p"
		result = tx.run(cql,aosp_dev=aosp_dev,name=name,_class=_class,permission=permission)
		if (sum(1 for _ in result.records()) == 0):
			#No result return . Then we find a deputy path (even though the length of path is 1)
			ret_list.append(record_dict)
			target_context_set.add(name)
			#print record_dict
	
	return ret_list,target_context_set

#Generate a cql to show target_path in graph
#target_context = {"target_context": , "class": , "permission"}
def gen_cql_showing_nodes(tx,target_context):
	_list =[] #used in cql

	for i in target_context :
		cql = r"match p = (n:user_domain)"
		cql += r"-[r:allow{class:%s,permission:%s}]->"%("\""+i["class"]+"\"","\""+i["permission"]+"\"")
		cql += r"(m{name:%s}) return p"%("\""+i["target_context"]+"\"")
		if i!=target_context[-1]:
			cql += "\nUnion"
		print cql

##Used to find why these paths are added. All deputy_path will be classified into one of below:
#1.new context added by OEM --ret_list1
#2.just add a new path from old context; --ret_list2
def anaylyse_deputy_path1(deputy_path):
	ret_list1=[]
	ret_list2=[]
	for path in deputy_path:
		target_context = path["target_context"]
		cql = r'match (n{dev:"Pixel",name:{name} }) return n'
		result = tx.run(cql,name=target_context)
		if (sum(1 for _ in result.records()) == 0):
			#no result return. -> ret_list1
			ret_list1.append(path)
		else:
			ret_list2.append(path)

	return ret_list1,ret_list2

#this will print a path graph from a <Record>
def drawpath(record):
	for i in record:
		#i is a Path class
		print i
		
		



#This function will get shortest path from user_domain to tcontext.Maxlen is used
#to limit the length of path.
def get_path(tx,tcontext,maxlen):
	ret_list =[]
	cql = "MATCH (a:user_domain),(b{ name: '%s' }),"% tcontext
	cql += "p = shortestPath((a)-[*..%s]-(b)) " % maxlen
	cql += "return p"
	print cql
	result = tx.run(cql,tcontext=tcontext,maxlen=maxlen)
	for record in result:
		ret_list.append(record)


	for i in ret_list:
		drawpath(i)



if __name__ == '__main__':
	driver = GraphDatabase.driver("bolt://localhost:7687",auth = (user,password))
	with driver.session() as session:
		tx = session.begin_transaction()
		set_user_domain_lable(tx) #set n:user_domain to untrusted_apps
		#for test:
		#target_user_domain_node_record = get_userdomain_nodes(tx,"Pixel")
		#print target_user_domain_node_record
		path_record = get_direct_path(tx,"HUAWEI_P20") #returned expresstion is "path"
		#print "direct-connected_path_record:",len(path_record)
		target_OEM_context_list = parsing_path_record(path_record)
		#print "target_OEM_context_list:",len(target_OEM_context_list)
		# see whether nodes connected in OEM are still connected in AOSP.
		# "1" means the length of path is 1
		deputy_path1,target_context1 = match_target_in_aosp(tx,target_OEM_context_list,"Pixel")
		#print "deputy_path1:",len(deputy_path1)
		#Generate the cql to show the nodes in graph 
		#print gen_cql_showing_nodes(tx,deputy_path1)
		#print target_context1,len(target_context1)

		oem_add_context,oem_add_path =anaylyse_deputy_path1(deputy_path1)
		#gen_cql_showing_nodes(tx,oem_add_path)
		print oem_add_path,len(oem_add_path)

		#get_path(tx,"video_device",5)

