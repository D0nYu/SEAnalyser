#This file defines all the classes to be used when do infoflow analysis.
#The final target is to translate csv_policy (policy vectors) 
#into infoflow vectors and channel vectors;
#Furthermore, based on <canpasschannel> member, 
#we can investigate whether the info+channel vectors can really work well.


class op:
	
	"""Regarding <class:permission> as operation """
	def __init__(self, claz,perm):
		self.claz = self.claz_normalize(claz) #treat ln_file\socket_file\dir...as file
		self.perm = perm

		# direction:
		# 0 = out(i.e. src->dest such as write)
		# 1 = in(i.e. src<-dest such as read)
		self.direction = self.get_direction(perm) 
		self.data_type = self.get_data_type(self.claz,perm) #class data_type
		self.channel = self.get_channel(self.claz,perm) #string
		self.channel_direction = self.get_channel_direction(self.claz,perm)
		if self.channel == "":
			self.ischannel = False
		else:
			self.ischannel = True


	def claz_normalize(self,claz):
		#return the normalized claz.
		#normal claz dict: socket,socket_opt,property_service,file,process,service_manager,binder,fd
		socket_list = ["unix_dgram_socket","unix_stream_socket","tcp_socket","udp_socket",\
						"tun_socket","rawip_socket","netlink_netfilter_socket","socket",\
						"netlink_route_socket","netlink_kobject_uevent_socket","netlink_nflog_socket",\
						"netlink_socket"]
		property_service_list = ["property_service"]
		file_list = ["lnk_file","dir","file","chr_file","sock_file","fifo_file","blk_file"]
		process_list = ["process"]
		binder_list = ["binder"]
		fd_list = ["fd"]
		service_manager_list =["hwservice_manager","service_manager"]
		if claz in socket_list:
			return "socket"
		if claz in property_service_list:
			return "property_service"
		if claz in file_list:
			return "file"
		if claz in process_list:
			return "process"
		if claz in binder_list:
			return "binder"
		if claz in fd_list:
			return "fd"
		if claz in service_manager_list:
			return "service_manager"

		return ""

	
	def get_direction(self,perm):
		#Both channel or dataflow direction will be returned.
		perm_out_list = ["setopt","sendto","set","transition","sigchld","append","write","write","call","transfer","signal","sigstop","sigkill","ptrace","add","connect","connectto"]
		perm_in_list = ["getopt","recvfrom","read","read","open","use","execute","execute_no_trans","find","accept"]
		
		if perm in perm_in_list:
			return 1 #read-like
		if perm in perm_out_list:
			return 0 #write-like

		return -1 #the direction of this operation will not be considered.

	#return a data_type class based on (claz,perm)  	
	def get_data_type(self,claz,perm):
		#data_type_dic = {("perm","claz"):"data_type"}
		data_type_dic = {("getopt","socket"):"socket_opt",\
						("recvfrom","socket"):"socket_content",\
						("read","socket"):"socket_content",\
						("read","file"):"file_content",\
						("open","file"):"fd",\
						("use","fd"):"fd",\
						("execute","file"):"execflow",\
						("execute_no_trans","file"):"execflow",\
						("setopt","socket_opt"):"socket_opt",\
						("sendto","socket"):"socket_content",\
						("set","property_service"):"property",\
						("transition","process"):"transition",\
						("sigchld","process"):"sigchld",\
						("append","file"):"file_content",\
						("write","socket"):"socket_content",\
						("write","file"):"file_content",\
						("call","binder"):"parcel_normal",\
						("transfer","binder"):"parcel_binder",\
						("signal","process"):"signal",\
						("sigstop","process"):"signal_stop",\
						("sigkill","process"):"kill",\
						("ptrace","process"):"ptrace"}
		data_type_name = data_type_dic.get((perm,claz),None)
		if data_type_name == None:
			#print "Error:Not target operation:(%s:%s)"%(claz,perm)
			return None
		return data_type(claz,perm,data_type_name)

	def get_channel(self,claz,perm):
		channel_enum = ["socket_opt","socket","property","proc_control","file","file_execute"]
		if perm in ["getopt","setopt"]:
			return channel_enum[0] #the operations openning socket_opt channel
		if perm in ["connectto","connect","accept"]:
			return channel_enum[1]
		if perm in ["set"]:
			return channel_enum[2] #"property"
		if perm in ["execute_no_trans","transition","sigchld","signal","sigstop","sigkill","ptrace"]:
			return channel_enum[3]#"proc_control"
		if perm in ["open"]:
			return channel_enum[4]#file
		if perm in ["execute"]:
			return channel_enum[5]#file_execute

		return ""

	def get_channel_direction(self,claz,perm):
		#channel_enum = ["socket_opt","socket","property","proc_control","file","file_execute"]
		#channel_direction = 0: 
		perm_out_list = ["setopt","connect","connectto","set","transition","sigchld","signal","sigstop","sigkill","ptrace"]
		perm_in_list = ["getopt","accept","execute_no_trans","execute"]
		perm_double_list = ["open"]
		if perm in perm_out_list:
			return 0
		if perm in perm_in_list:
			return 1
		if perm in perm_double_list:
			return 2 #double direction


class data_type(object):
	"""Type of data could be transformed by this op"""
	def __init__(self,claz,perm,name):
		self.name = name
		self.claz = claz
		self.perm = perm
		self.canpass = self.get_canpass_channel(name) #TODO:The channels that can tranfer this type of data

	def get_canpass_channel(self,name):
		#Given the data_type's name, return the channel it, i.e. data(name), uses
		#canpass_dic = {channel:[data_types]}
		canpass_dic = {"socket_opt":["socket_opt"],\
						"socket":["socket_content"],\
						"property":["property"],\
						"proc_control":["ptrace","transition","sigchld","signal","signal_stop","kill"],\
						"file":["file_content","fd"],\
						"binder_channel":["parcel_normal","parcel_binder","fd"],\
						"file_execute":["execflow"]}
		for i in canpass_dic:
			if name in canpass_dic[i]:
				return i

		#print "%s:Invalid data_type:%s\n"%(,name)
		return ""




if __name__ == '__main__':
	a=op("file","read")
	b=op("file","read")
	print a.data_type,b.perm