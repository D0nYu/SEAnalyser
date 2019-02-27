import cilparser
import os
import runtime_collector
from global_configs import *


userlevel_dict = {"cameraserver":1047,"mdnsr":1020,"_isolated":90000,\
				"bluetooth":1002,"logd":1036,"radio":1001,"mediaex":1040,"keystore":1017,\
				"media":1013,"system":1000,"webview_zygote":1053,"_app":10000,\
				"audioserver":1041,"gps":1021,"statsd":1066,"shell":2000,"nobody":9999,\
				"graphics":1003,"tombstoned":1058,"vpn":1016,"secure_element":1068,"incidentd":1067,\
				"nfc":1027,"wifi":1010,"drm":1019,"shared_relro":1037,\
				"mediacodec":1046,"root":0}

class dev(object):
	"""docstring for dev"""
	def __init__(self, dev_name,**kw):
		super(dev, self).__init__()
		print "-------Init dev:%s--------"%dev_name
		self.dev_name = dev_name
		self.finegrained_neal_list = [] #expanded neverallow 
		self.finegrained_neal_dict = dict()
		self.attri_dict = dict()
		self.finegrained_allow_list = [] #expanded allow
		self.finegrained_allow_dict = dict()
		self.related_fr_hash_dict = [] #used to get related subs

		self.domset = set()
		self.typeset = set()
		#set related cil file path first
		sys_cil_filepath = os.path.join(work_path,dev_name,sys_cil_file)
		#set vendor_sepolicy.cil/nonplat_sepolicy.cil
		
		sysver_cil_filepath = os.path.join(work_path,dev_name,sysver_cil_file)
		if os.path.exists(sysver_cil_filepath):#in Pixel
			print "seversion >= 28.0"
			ven_cil_filepath = os.path.join(work_path,dev_name,ven_cil_file)
			sysver_cil_filepath = os.path.join(work_path,dev_name,sysver_cil_file)
		else:#in OEM
			print "seversion <= 27.0"
			ven_cil_filepath = os.path.join(work_path,dev_name,np_cil_file)

		#set plat_sepolicy_vers.txt
		self.version_filepath = os.path.join(work_path,dev_name,version_file)
		with open(self.version_filepath) as f:
			self.seversion = f.read().strip() #string type: 26.0/27.0/28.0

		map_cil_filepath = os.path.join(work_path,dev_name,mapping_dir,self.seversion+".cil")
		print sys_cil_filepath,ven_cil_filepath,map_cil_filepath
		sys_parsed_result = cilparser.syscil_parser(dev_name,sys_cil_filepath)
		ven_parsed_result = cilparser.normalcil_parser(dev_name,ven_cil_filepath)
		map_parsed_result = cilparser.normalcil_parser(dev_name,map_cil_filepath)
		sysallow = sys_parsed_result[2] 
		sysneal = sys_parsed_result[1] 
		sysattr = sys_parsed_result[0]
		venattr = ven_parsed_result[0] 
		venallow = ven_parsed_result[2]
		venneal = ven_parsed_result[1]
	 	mapattr = map_parsed_result[0]
	 	sys_typetrans = sys_parsed_result[3] 
	 	ven_typetrans = ven_parsed_result[3]
	 	#merge
	 	#merge (sys,vendor,maps)'s attribute/allow/neverallow first
	 	#attribute:dict
		
	 	allattr_list = [sysattr,venattr,mapattr]
	 	if os.path.exists(sysver_cil_filepath):
	 		sysver_parsed_result = cilparser.normalcil_parser(dev_name,sysver_cil_filepath)
	 		allattr_list.append(sysver_parsed_result[0])

	 	merged_attr = cilparser.attr_merge(allattr_list)
	 	self.merged_attr = merged_attr
	 	#allow::a list of tuple [(d,t,c,[perms]),(),()]
	 	merged_allow = sysallow+venallow
	 	if os.path.exists(sysver_cil_filepath):
	 		merged_allow+=sysver_parsed_result[2]
	 	#neverallow:a dict---neal[filename]:[(d,t,c,perm)]
	 	
	 	if not os.path.exists(sysver_cil_filepath):
	 		merged_neal = dict(sysneal.items()+venneal.items())

	 	else:
	 		merged_neal = dict(sysneal.items()+venneal.items()+sysver_parsed_result[1].items())

	 	#Need clear the duplicated A and A_27_0,and instance them
	 	self.merged_neal = merged_neal
	 	for attr in merged_attr:
	 		#if not attr.startswith("base_typeattr_"):
	 		self.attri_dict[attr] = attribute(attr,merged_attr[attr][0],merged_attr[attr][1])

		#Futhermore, parse indirect neverallow from base_typeattr:
		indirect_neal_list = []
		count_i = 0 
		for allowrule in merged_allow:
			if "base_typeattr_" in allowrule[0]:
				#allow (subA - subB) X file [read,write,open]
				for indirect_neal_sub in self.attri_dict[allowrule[0]].notset:
					indirect_neal_list.append((indirect_neal_sub,allowrule[1],allowrule[2],allowrule[3]))
					count_i += 1

			if "base_typeattr_" in allowrule[1]:
				#allow X (objA-objB) file [read,write,open]
				for indirect_neal_obj in self.attri_dict[allowrule[1]].notset:
					indirect_neal_list.append((allowrule[0],indirect_neal_obj,allowrule[2],allowrule[3]))
					count_i += 1
		
		finegrained_indirect_neal_list = self.expandrules(indirect_neal_list,merged_attr)
		self.finegrained_neal_list = finegrained_indirect_neal_list
		print "indirect_neverallow:",len(finegrained_indirect_neal_list)



		self.finegrained_allow_list = self.expandrules(merged_allow,merged_attr)
		for fr in self.finegrained_allow_list:
			self.domset.add(fr.domain)
			self.typeset.add(fr._type)

		if "expanded_neal" in kw and kw['expanded_neal'] ==True:
			#directly get from neverallow rules
			merged_neal_list =[]
			merged_neal_list += indirect_neal_list
			for cilfile in merged_neal:
				for r in merged_neal[cilfile]:
					#type(r) = tuple
					merged_neal_list.append(r)
			
			#print len(merged_neal_list)
			self.finegrained_neal_list += self.expandrules(merged_neal_list,merged_attr)
			print "finegrained neverallow:%d"%(len(self.finegrained_neal_list))

			#infer from base_typeattr declaration
		
		if "fr_dict" in kw and kw["fr_dict"] == True:
			print "Fr Hashing"
			self.finegrained_allow_dict = self.get_fr_dict(self.finegrained_allow_list)
			self.finegrained_neal_dict = self.get_fr_dict(self.finegrained_neal_list)


		'''
		for i in self.finegrained_allow_list:
			print "----"
			i.show()

		print "neal list:"
		for i in self.finegrained_neal_list:
			print "----"
			i.show()
		'''
		##### Merge and expand typetransition
		merged_typetrans = sys_typetrans+ven_typetrans

		self.expanded_typetrans = self.expand_typetrans(merged_typetrans,merged_attr)
		print "Typetransitions:", len(self.expanded_typetrans)

		#Create Typetransition Graph (useing a dict):
		self.typetrans_dict = dict()
		for typetrans in self.expanded_typetrans:
			if not self.typetrans_dict.has_key(typetrans[0]):
				self.typetrans_dict[typetrans[0]] = [(typetrans[1],typetrans[3])]
			else:
				self.typetrans_dict[typetrans[0]].append((typetrans[1],typetrans[3]))

	def get_fr_dict(self,fr_list):
		ret_dict = dict()
		for r in fr_list:
			for perm in r.perms:
				if ret_dict.has_key(repr((r._type,r.claz,perm))):
					ret_dict[repr((r._type,r.claz,perm))].append(r.domain)
				else:
					ret_dict[repr((r._type,r.claz,perm))] = [r.domain]
		return ret_dict

	def expand_typetrans(self,typetrans_list,attr_dict):
		#BUGS here, not exclude _28_0
		ret_list = []
		for entry in typetrans_list:
			subset = cilparser.recursively_expand_attr(entry[0],attr_dict)
			objset = cilparser.recursively_expand_attr(entry[1],attr_dict)
			targetset = cilparser.recursively_expand_attr(entry[3],attr_dict)
			
			for sub in subset:
				for obj in objset:
					for tar in targetset:
						ret_list.append((sub,obj,entry[2],tar))
		return ret_list

	'''
	def expand_typetrans(self,typetrans_list,attr_dict):
		#BUGS here, not exclude _28_0
		print typetrans_list[1]
		print attr_dict["update_engine_28_0"]
		exit()
		ret_list = []
		for entry in typetrans_list:
			sublist = []
			objlist = []
			targetlist = []

			if attr_dict.get(entry[0])!=None:
				for i in (attr_dict[entry[0]][0]-attr_dict[entry[0]][1]):
					sublist.append(i)
			else:
				sublist.append(entry[0])

			if attr_dict.get(entry[1])!=None:
				for j in (attr_dict[entry[1]][0]-attr_dict[entry[1]][1]):
					objlist.append(j)
			else:
				objlist.append(entry[1])
			
			if attr_dict.get(entry[3])!=None:
				for k in (attr_dict[entry[3]][0]-attr_dict[entry[3]][1]):
					targetlist.append(k)
			else:
				targetlist.append(entry[3])
			
			for sub in sublist:
				for obj in objlist:
					for tar in targetlist:
						ret_list.append((sub,obj,entry[2],tar))
		return ret_list

	'''

	def expandrules(self,rule_list,attr_dict):
		ret_list = []
		for rule in rule_list:
			#('zygote', 'overlay_prop', 'file', ['ioctl', 'read', 'getattr', 'lock', 'map', 'open'])")
			for i in cilparser.expand_single_rule(rule,attr_dict):
				ret_list.append(finegrained_rule(i))

		return ret_list


class attribute(object):
	"""docstring for attribute"""
	def __init__(self, name, andset, notset):
		super(attribute, self).__init__()
		self.attr_name = name
		self.andset = andset
		self.notset = notset
		self.contained_typeset = andset - notset
		self.level = 0 #TODO

	def __repr__(self):
		return "[%s]---{%s-%s}"%(self.attr_name,str(self.andset),str(self.notset))

	def description(self):
		des = str(self.andset).strip("(set)")
		des += " - "
		if self.notset != set():
			des += str(self.notset).strip("(set)")

		print des

class rule(object):
	"""docstring for rule"""
	def __init__(self, rule_tuple):
		super(rule, self).__init__()

		self.domain = rule_tuple[0]
		self._type = rule_tuple[1]

		self.claz = rule_tuple[2]
		self.perms = rule_tuple[3]

	def __repr__(self):
		return "(%s,%s,%s,%s)"%(repr(self.domain),repr(self._type),repr(self.claz),repr(self.perms))

	def __str__(self):
		return "(%s,%s,%s,%s)"%(repr(self.domain),repr(self._type),repr(self.claz),repr(self.perms))

	def show(self,**kw):
		if 'perm' in kw:
			print " %s-[%s:(%s)]->%s "%(self.domain,self.claz,str(kw),self._type)
		else:
			print " %s-[%s:(%s)]->%s "%(self.domain,self.claz,str(self.perms),self._type)
		
	def tuple_type(self):
		return (self.domain,self.claz,str(self.perms),self._type)

class finegrained_rule(rule):
	"""input a finegrained tuple:('shell', 'self', 'process', ['execmem'], 
	"('appdomain', 'self', 'process', ['execmem'])")"""
	def __init__(self,fin_rule_tuple):
		super(finegrained_rule,self).__init__(fin_rule_tuple)
		if fin_rule_tuple[1] == "self":
			self._type = fin_rule_tuple[0]
		else:
			self._type = fin_rule_tuple[1]
		self.src_rule = rule(fin_rule_tuple[4])

'''
class domain(object):
	"""docstring for domain"""
	def __init__(self, domain_name):
		super(domain, self).__init__()
		self.name = domain_name
		self.attr_list = get_attr(self,domain_name)
		self.spawn_by_init = 
		self.defined_by_plat = 
		self.untrusted_code_ornot = 
	
	def get_attr(self,typename):
		ret_list = []
		for attr in self.attri_dict:
			if typename in dev_instance.attri_dict[attr].contained_typeset:
				ret_list.append(attr)

		ret_list.sort()
		return ret_list
'''

class sub_feature(object):
	"""All features of a subject type. Type name is needed to initialize the feature class"""
	def __init__(self, devins,arg):
		super(sub_feature, self).__init__()
		self.typename = arg

		##attribute features:
		#[0:domain,1:mlstrustedsubject,2:coredomain,3:appdomain,4:untrusted_app_all,5:netdomain,
		#6:bluetoothdomain,7:binderservicedomain,8:halserverdomain,9:halclientdomain]
		self.attribute_features = dict()
		self.attribute_features = {"domain":False,"mlstrustedsubject":False,"coredomain":False,"appdomain":False,\
		"untrusted_app_all":False,"netdomain":False,"bluetoothdomain":False,"binderservicedomain":False,"halserverdomain":False,\
		"halclientdomain":False}
		attrlist = get_attr(devins,arg)
		for attr in attrlist:
			if attr in self.attribute_features.keys():
				self.attribute_features[attr] = True

		#self.attribute_vec  = self.attrfeatures2vec(self.attribute_features)

		#untrusted features,which may run 3rd party code
		if "untrusted_app" in self.typename  or "isolated_app" == self.typename \
		or "ephemeral_app" == self.typename or "untrusted_v2_app" == self.typename:
			self.untrusted_domain = True  #untrusted_app\isolated_app\shell
		else:
			self.untrusted_domain = False


		
		#self.typetransition_path = [] #kernel,init,zygote,untrusted_app
		path = typetransition_lookup(devins.typetrans_dict,"kernel",arg)
		#print "typetransition lookup result:",path
		if path!=[]:#Got from typetransition in sepolicy
			if path[-1]!= arg:
				path.append(arg)

			self.typetransition_path = path

			self.typetransition_distance = self.typetransition_path.index(arg)
		
			exec_file = typetransition_file_lookup(devins.typetrans_dict,arg)
			self.exec_file_feature = obj_feature(devins,exec_file)

		else:
			#1.vendor_init is forked by init label
			#2.others are forked by zygote
			if self.typename == "vendor_init":
				self.typetransition_path = ["kernel","init","vendor_init"]
				self.typetransition_distance = 1
				exec_file = 'init_exec'
				self.exec_file_feature = obj_feature(devins,exec_file)
			else:
				if self.typename.endswith("_app") or self.typename =="system_server" or \
				self.typename in runtime_collector.seapp_info:
					self.typetransition_path = ["kernel","init","zygote"]+[arg]
					self.typetransition_distance = 4
					exec_file = 'zygote_fork'
					self.exec_file_feature = obj_feature(devins,exec_file)
				else:
					self.typetransition_path = ["unknown"]
					self.typetransition_distance = -1
					exec_file = 'unknown'
					self.exec_file_feature = obj_feature(devins,exec_file)


		#user who has this context when running. Read from an prepared dict file
		self.runtime_user = runtime_collector.runtime_feature_collector(devins,self.typetransition_path)
		self.userlevel = ''
		if self.runtime_user != None and self.runtime_user != "not_proc":
			uid = userlevel_dict.get(self.runtime_user)
			if uid == 0:
				self.userlevel = "root"
			if 1000<=uid<2000:
				self.userlevel = "system"
			if 2000<=uid<2900:
				self.userlevel = "shell"
			if 3000<=uid<5000: #not used
				self.userlevel = "supplemental group"
			if 9997<=uid<10000: 
				self.userlevel = "app_shared"
			if 10000<=uid<20000:
				self.userlevel = "app"
			if 20000<=uid<30000:#not used
				self.userlevel = "app cache data group"
			if 30000<=uid<40000:#not used
				self.userlevel = "app external data group"
			if 40000<=uid<50000:#not used
				self.userlevel = "app external cache data group"
			if 50000<=uid<60000:#not used
				self.userlevel = "app public data"
			if uid == 65534:#not used
				self.userlevel = "nomapping user"
			if 90000<=uid<100000:
				self.userlevel = "isolated"
			if self.userlevel == '':
				self.userlevel = "unknown_proc"


		else:
			#No related exec_file in fs, or not invoked by rc files
			#print "Unknown User (%s) for subject (%s)"%(self.runtime_user,arg)
			self.userlevel = "not_proc" #means not a proc




		#dictorize for sklearn DictVectorizer 
		self.feature_dict = self.attribute_features
		self.feature_dict["untrusted_domain"] = self.untrusted_domain
		#self.feature_dict["typetransition_distance"] = self.typetransition_distance
		self.feature_dict["userlevel"] = self.userlevel
		self.feature_dict["user"] = self.runtime_user
		self.feature_vector = self.feature_vectorize()

		#print self.typetransition_path,exec_file

	def tostr(self):
		ret_str = ""
		for i in self.feature_dict:
			if self.feature_dict[i] == True:
				ret_str += i
				ret_str += " "
		return ret_str


	def feature_vectorize(self):
		#print "Vector:"
		attr_vec = [0]*11
		feature_domain_lookuplist = ["domain","mlstrustedsubject","coredomain","appdomain","untrusted_app_all",\
									"netdomain","bluetoothdomain","binderservicedomain","halserverdomain","halclientdomain",\
									"untrusted_domain"]

		for attr in self.feature_dict:
			if self.feature_dict[attr]==True:
				idx = feature_domain_lookuplist.index(attr)
				attr_vec[idx] = 1
		userlevel_vec = [0] * 6 #dummy encoding for userlevel

		#root,system,shell,app_shared,app,isolated. (000000 for unknown)
		if self.userlevel == "root":
			userlevel_vec[0] = 1 
		if self.userlevel == "system":
			userlevel_vec[1] = 1 
		if self.userlevel == "shell":
			userlevel_vec[2] = 1
		if self.userlevel == "app_shared":
			userlevel_vec[3] = 1 
		if self.userlevel == "app":
			userlevel_vec[4] = 1
		if self.userlevel == "isolated":
			userlevel_vec[5] = 1



		return attr_vec+userlevel_vec
	


	def __repr__(self):
		ret_expr = ''
		ret_expr += "Type Name: %s \n" % self.typename
		#ret_expr += "Attribute Features:%s \n"% self.attribute_vec
		ret_expr += "Typetransition Path (length:%d):%s \n"%(self.typetransition_distance,self.typetransition_path)
		ret_expr += "Exec File :%s \n" %self.exec_file_feature.typename
		ret_expr += str(self.feature_dict)
		return ret_expr

	def attrfeatures2vec(self,attribute_features):
		print "Vector:"
		vec = [0]*10
		feature_domain_lookuplist = ["domain","mlstrustedsubject","coredomain","appdomain","untrusted_app_all",\
									"netdomain","bluetoothdomain","binderservicedomain","halserverdomain","halclientdomain"]

		for attr in attribute_features:
			if attribute_features[attr]==True:
				idx = feature_domain_lookuplist.index(attr)
				vec[idx] = 1
		
		return vec


class obj_feature(object):
	"""All features of an  object type"""
	def __init__(self, devins,arg):
		super(obj_feature, self).__init__()
		self.typename = arg
		self.fileflag = 0 #etc. 755
		self.owner = ""
		self.untrusted_file = False #create/write by an untrusted domain


	def filecontext_lookup(self,devins,arg):
		pass

#----class def ends------#

def typetransition_file_lookup(typetrans_dict,typename):
	for src_type in typetrans_dict:
			for entry in typetrans_dict[src_type]:
				if entry[1] == typename:
					exec_file = entry[0]
					return exec_file

	return ""

def typetransition_lookup(typetrans_dict,start,end):
	#find all paths from start("kernel") to end (target)
	path = []
	paths = []
	#print "Trying to find path from %s to %s recuresivly" % (start,end)
	if end == "kernel" or end == "su" or end =="crash_dump":
		return [end]
	count = 0
	for src_type in typetrans_dict:
		for entry in typetrans_dict[src_type]:
			if entry[1] == end:
				count = 1
				#print src_type,typetrans_dict[src_type],type(typetrans_dict[src_type])
				path += typetransition_lookup(typetrans_dict,start,src_type)
				if not src_type in path:
					path.append(src_type)
		if count != 0 :
			break
	return path


def get_attr(dev_instance,typename):
	ret_list = []

	for attr in dev_instance.attri_dict:
		if typename in dev_instance.attri_dict[attr].contained_typeset and not (typename+"_"+dev_instance.seversion.replace(".","_"))==attr:
			ret_list.append(attr)

	ret_list.sort()
	return ret_list
	



if __name__ == '__main__':
	#test
	dev_ins = dev("Pixel",fr_dict=True)
	exit()
	for testcase in ["location","hal_graphics_allocator_default","hal_tv_input_default","untrusted_app_25","system_server","logger_app","hardware_info_app_tmpfs","pdx_display_client_server_type","profman","surfaceflinger"]:
		print "-------------"
		print testcase
		feat_ins = sub_feature(devins,testcase)
		print feat_ins.feature_dict
		print feat_ins.typetransition_path
		print feat_ins.runtime_user


	