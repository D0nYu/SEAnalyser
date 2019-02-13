import cilparser
import os

work_path = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/"
sys_cil_file = "system_etc_selinux/selinux/plat_sepolicy.cil"
ven_cil_file = "vendor_etc_selinux/selinux/vendor_sepolicy.cil"#seversion >= 28
ven_seapp_file = "vendor_etc_selinux/selinux/vendor_seapp_contexts"
np_cil_file = "vendor_etc_selinux/selinux/nonplat_sepolicy.cil"#seversion < 28
np_seapp_file = "vendor_etc_selinux/selinux/nonplat_seapp_contexts"
mapping_dir = "system_etc_selinux/selinux/mapping"
sysver_cil_file = "vendor_etc_selinux/selinux/plat_pub_versioned.cil"
version_file ="vendor_etc_selinux/selinux/plat_sepolicy_vers.txt"
sys_seapp_file = "system_etc_selinux/selinux/plat_seapp_contexts"


class dev(object):
	"""docstring for dev"""
	def __init__(self, dev_name,**kw):
		super(dev, self).__init__()
		
		self.dev_name = dev_name
		self.finegrained_neal_list = [] #expanded neverallow 
		self.attri_dict = dict()
		self.finegrained_allow_list = [] #expanded allow
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



	def expand_typetrans(self,typetrans_list,attr_dict):
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

		

		#untrusted features
		if "untrusted_app" in self.typename  or "isolated_app" == self.typename or "shell" == self.typename:
			self.untrusted_domain = True  #untrusted_app\isolated_app\shell
		else:
			self.untrusted_domain = False


		
		#self.typetransition_path = [] #kernel,init,zygote,untrusted_app
		path = typetransition_lookup(devins.typetrans_dict,"kernel",arg)
		if path!=[]:
			if path[-1]!= arg:
				path.append(arg)

			self.typetransition_path = path

			self.typetransition_distance = self.typetransition_path.index(arg)
		
			exec_file = typetransition_file_lookup(devins.typetrans_dict,arg)
			self.exec_file_feature = obj_feature(exec_file)

		else:
			#1.vendor_init is forked by init label
			#2.others are forked by zygote
			if self.typename == "vendor_init":
				self.typetransition_path = ["init","vendor_init"]
				self.typetransition_distance = 1
				exec_file = 'init_exec'
				self.exec_file_feature = obj_feature(exec_file)

			else:
				self.typetransition_path = ["init","zygote"]+[arg]
				self.typetransition_distance = 2
				exec_file = 'zygote_exec'
				self.exec_file_feature = obj_feature(exec_file)

		#print self.typetransition_path,exec_file





class obj_feature(object):
	"""All features of an  object type"""
	def __init__(self, devins,arg):
		super(obj_feature, self).__init__()
		self.typename = arg
		self.fileflag = 0 #etc. 755
		self.owner = ""
		self.untrusted_file = False #create/write by an untrusted domain


	def filecontext_lookup():
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
	#print "Trying to find path from %s to %s recuresivly" % (start,end)
	if end == "kernel" or end == "su" or end =="crash_dump":
		return [end]

	for src_type in typetrans_dict:
		for entry in typetrans_dict[src_type]:
			if entry[1] == end:
				#print src_type,typetrans_dict[src_type],type(typetrans_dict[src_type])
				path += typetransition_lookup(typetrans_dict,start,src_type)
				if not src_type in path:
					path.append(src_type)

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
	devins = dev("Pixel",expanded_neal=False)
	sub_feature(devins,"servicemanager")