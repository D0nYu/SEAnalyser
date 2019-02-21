#/usr/bin/env python
#This file provide some funtion utils to deal with cil files
#such as :
#1.sys cilfile parse(get attribute/neverallow/allow rules dict),
#2.rules expand(use their attributes)
#3.and some trival rules check(neverallow and allow rules conflictions)
#
import os
import sys
import re
from main import gen_attribute_dic
from global_configs import *


def printlogo(str):
	print "*"*40
	print "%20s"%str
	print "*"*40

def split_class_perm(class_perm_set):
	_class = class_perm_set[0].strip("(")
	perm_list = []
	for i in range(1,len(class_perm_set)):
		perm_list.append(class_perm_set[i].strip("()"))
	#print _class
	#print perm_list

	return _class,perm_list



def allow_parser(content):
	#Get all allow rules in cil
	#Return a list of tuple [(d,t,c,p),(d,t,c,p)...]
	ret_list = []
	content_in_line = content.split("\n")
	for line in content_in_line:
		if r"(allow " in line :
			#do not consider allowx now
			rule_split = line.split()
			assert rule_split[0].strip("(") == "allow"
			domain = rule_split[1]
			_type = rule_split[2]
			claz = rule_split[3].strip("(")
			perm = rule_split[4::]
			expr_normalize(perm)
			ret_list.append((domain,_type,claz,perm))

	print "allow_rules:",len(ret_list)
	return ret_list


def expr_normalize(attr_list):
	#strip "()" and " " in cil rules"
	i = 0
	while i < len(attr_list):
		if attr_list[i].startswith('(') or attr_list[i].endswith(')'):
			attr_list[i] = attr_list[i].strip("()")

		i += 1

	while '' in attr_list:
		attr_list.remove('')


def expand_attr(attr_list):
	#return a tupul  
	#case 1:and + not attr:
	if ("and" in attr_list) and ("not" in attr_list):
		and_index = attr_list.index("and")
		not_index = attr_list.index("not")
		andset = set(attr_list[and_index+1:not_index])
		notset = set(attr_list[not_index+1::])
		return (andset,notset)

	if (not "and" in attr_list) and ("not" in attr_list):
		not_index = attr_list.index("not")
		andset = set()
		notset = set(attr_list[not_index+1::])
		return (andset,notset)

	if (not "and" in attr_list) and (not "not" in attr_list):
		andset = set(attr_list)
		notset = set()
		return (andset,notset)


def attr_parser(content):
	#return a dict of attribute such as:
	#{"attr_name": (andset,notset)}
	attribute_dic = dict()
	content_in_line = content.split("\n")
	for line in content_in_line:
		if (r'(typeattributeset ') in line:
			split_line = line.split()

			typeattributeset = split_line[0].strip("()")
			assert (typeattributeset == "typeattributeset")
			attr_name = split_line[1].strip("()")
			attr_contains = split_line[2::]
			i = 0
			#print attr_name
		
			expr_normalize(attr_contains)#strip '()' and ''
			#print attr_contains	
			if attribute_dic.get(attr_name) == None:
				#new attri
				attribute_dic[attr_name] = expand_attr(attr_contains)#give a list of attr (and ... not ...)
				
			else:
				#alread has this attribute in dict, then merge these sets
				#print attribute_dic[attr_name][0],expand_attr(attr_contains)[0]
				new_andset = attribute_dic[attr_name][0]|expand_attr(attr_contains)[0]
				new_notset = attribute_dic[attr_name][1]|expand_attr(attr_contains)[1]
				attribute_dic[attr_name] = (new_andset,new_notset)
			#return a entry in dict:{"attr":(totalset(),andset(),notset())}
	return attribute_dic


def syscil_parser(dev,cil_file):
	#KEY FUNCTION
	#cil_file = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/HUAWEI_P20/system_etc_selinux/selinux/plat_sepolicy.cil"
	#dev = "HUAWEI_P20"
	#seinfo_file = os.path.join(work_path,dev,seinfo_path)
	#attribute_dic = gen_attribute_dic(seinfo_file)
	with open(cil_file) as f:
		content = f.read()
		print "In file [%s]"%cil_file.split("/")[-1]
		attribute_dic = attr_parser(content) #Done
		never_allow_entry = never_allow_parser(content) #Done
		allow_entry = allow_parser(content) #Done
		typetrans_entry = normal_typetrans_parser(content)
	return (attribute_dic,never_allow_entry,allow_entry,typetrans_entry)

def never_allow_parser(content):
	#return a dict:{"te_filepath:[(domain,type,class,perm),(domain,type,class,perm),()]"}
	#not contains neverallowx!!
	ret_dict = dict()
	pattern = re.compile(r";;\* lmx.*[\s.()\w]*\(neverallow .*\n;;\* lme")
	result = pattern.findall(content)
	if result == []:
		print "Error while searching neverallow rules"
		return []

	for entry_neverallow in result:
		tefile_line = entry_neverallow.split("\n")[0]#';;* lmx 260 system/sepolicy/public/attributes'
		neverallow_line = entry_neverallow.split("\n")[2:-1]
		tefile_name = tefile_line.split()[-1]
		#print entry_neverallow
		assert "/sepolicy/" in tefile_name
		for rule in neverallow_line:
			assert 'neverallow' in rule.split()[0]
			domain = rule.split()[1]
			_type = rule.split()[2]
			claz = rule.split()[3].strip("(")
			perm = rule.split()[4::]
			expr_normalize(perm)
			if ret_dict.get(tefile_name) == None:
				ret_dict[tefile_name] = [(domain,_type,claz,perm)]
			else:
				ret_dict[tefile_name].append((domain,_type,claz,perm))
	
	return ret_dict

	

def diff_baseattr(attr,parse_result):
	pass

def diff_normalattr(attr,parse_result):
	#parse_result is a dict contains cil_parse result with dev as its key.
	#for target_dev in parse_result:
	pass

def attrdiff(ref_attr_dict,oem_attr_dict):
	#return all matched,modified,newly_added  attributes in this oem device
	#print "Attribute diff"
	print " ______________________________"
	print "|DEVICE:%4d attributes totally|"%len(ref_attr_dict)
	print "|DEVICE:%4d attributes totally|"%len(oem_attr_dict)
	print " ------------------------------"
	unmatched_list = []
	matched_list = []
	new_list = []
	for attr in oem_attr_dict:
		#search oem attributes in ref devices one by one
		#print attr
		if attr.startswith("base_typeattr_"):
			continue

		else:
			oem_value = oem_attr_dict[attr]
			ref_value = ref_attr_dict.get(attr)
			if ref_value == None:
				new_list.append(attr)
				continue

			else:
				if oem_value[0]-oem_value[1] == ref_value[0]-ref_value[1]:
					pass
				else:
					print "Get diff define:",attr
					print "OEM:",oem_value
					print "REF:",ref_value
					print "OEM-REF",(oem_value[0]-oem_value[1]) - (ref_value[0]-ref_value[1])
					print "REF-OEM",(ref_value[0]-ref_value[1]) - (oem_value[0]-oem_value[1])
					print "-----"
	print "NEW_LIST:",new_list

def neverallowdiff(ref_neal_dict,oem_neal_dict):
	print " ______________________________________"
	print "DEVICE REF:%4d nerverallow file totally"%len(ref_neal_dict)
	print "DEVICE OEM:%4d nerverallow file totally"%len(oem_neal_dict)
	print " --------------------------------------"
	simi_count = 0 
	diff_count = 0 
	for i in ref_neal_dict:
		if oem_neal_dict.get(i)!=None and len(ref_neal_dict[i]) == len(oem_neal_dict[i]):
			#print i
			simi_count +=1
		else:
			diff_count +=1
			print "OEM:%s"%i,oem_neal_dict.get(i)
			print "REF:%s"%i,ref_neal_dict[i]
	print simi_count, diff_count

def recursively_expand_attr(attr_name,attri_dict):
	#return a set 
	andset = set()
	notset = set()
	if attr_name == "all":
		attr_name = "domain"
		
	if attri_dict.get(attr_name)==None:
		#not an attribute but a normal context
		andset.add(attr_name)
		return andset #end of recursive

	else:
		#attribute define in attri_dict
		#print "DBG-attr:",attri_dict[attr_name]
		if attri_dict[attr_name][1] == set([]):
			#normal attribute not has a notset.(not base_typeattr)
			for attri in attri_dict[attr_name][0]:
				#print attr_name,attri
				andset|= recursively_expand_attr(attri,attri_dict)
			return andset

		else:
			#base_type that has not-attri set
			for andattri in attri_dict[attr_name][0]:
				andset|= recursively_expand_attr(andattri,attri_dict)
			for notattri in attri_dict[attr_name][1]:
				notset|= recursively_expand_attr(notattri,attri_dict)
			return (andset-notset)

def expand_single_rule(rule,attri_dict):
	#input a single tuple. return a list of tuples
	ret_list = []
	assert len(rule) == 4
	assert type(rule) == tuple
	src_name = rule[0]
	dst_name = rule[1]
	claz = rule[2]
	perms = rule[3]
	#print rule
	src_set = recursively_expand_attr(src_name,attri_dict)
	dst_set = recursively_expand_attr(dst_name,attri_dict)
	for src in src_set:
		for dst in dst_set:
			ret_list.append((src,dst,claz,perms,rule))

	
	return ret_list

def allow_expand(allow_list,attri_dict):
	#different with neverallow_expand.
	#input [(),(),(),] --- output [()()()()()()...]
	ret_list = []

	for rule in allow_list:
		for i in expand_single_rule(rule,attri_dict):
			ret_list.append(i)

	print "fine-grained allow : ",len(ret_list)
	return ret_list



def neverallow_expand(neal_dict,attri_dict):
	#expand all neverallow rules (in ref devices),return all neal rules in a new dict
	ret_dict = dict()
	count = 0 
	for te_files in neal_dict:
		for rule in neal_dict[te_files]:
			#print rule
			if ret_dict.get(te_files) == None:
				ret_dict[te_files] = expand_single_rule(rule,attri_dict)
			else :
				for i in expand_single_rule(rule,attri_dict):
					ret_dict[te_files].append(i)
			count += 1

	#print attri_dict
	
	fine_grained_count = 0
	for i in ret_dict:
		fine_grained_count +=len(ret_dict[i])
		#print i
		#print ret_dict[i],len(ret_dict[i])
	print "fine-grained neverallow rules:",fine_grained_count
	return ret_dict

'''
def attribute_calc(parsed_attri):
	#parsed_attri is a dict such like :
	#'base_typeattr_315': (set(['coredomain']), set(['init', 'ueventd', 'fsck']))
	#return a new dict saves calculated attributes
	ret_dict = dict()
	for attri in parsed_attri:
		andset = attri[0]
		notset = attri[1]
		get_detailed_attri
'''
#we transformed this dict into a new classified dict
#from {"domain.te":[(),(),()]} to {("domain,type,claz"):[([perms1,perms2],[file1,file2],[ne1,ne2]]}
def clasify_nealdic(old_neal_dict):
	ret_dict = dict()
	for file in old_neal_dict:
		for rule in old_neal_dict[file]:
			assert len(rule) == 5
			dict_key = (rule[0],rule[1],rule[2])

			if ret_dict.get(dict_key) == None:
				#print dict_key,type(dict_key)
				ret_dict[dict_key] = [[rule[3]],[file],[rule[4]]] #rule[4] is the original rule
			else:
				#merge with exisiting rules
				#print "Merging:",ret_dict[dict_key],set(rule[3])
				ret_dict[dict_key][0].append(rule[3])
				ret_dict[dict_key][1].append(file)
				ret_dict[dict_key][2].append(rule[4])
				#print "result:",ret_dict[dict_key]
				#exit()
	print "classified_FiNeal_dict:",len(ret_dict)
	return ret_dict

def lookup_nealdic(never_ref,rule):
	#check one rule in a call
	#Need to record where this neal comes from 
	#never_ref = [perm],[ori_file],[ori_rule]
	violate_perm = []
	key = (rule[0],rule[1],rule[2])

	if never_ref.get(key) == None:
		return None

	
	#check whether all allowed permissions violates neverallow:
	for perm in rule[3]:
		for neverperm in never_ref[key][0] :
			if (perm in neverperm) :
				violate_perm.append(perm)
	#check over
	if violate_perm == []:
		return None
	else:
		#print "(%s)-[%s:{%s}]->(%s) (vioNeals in :"\
		#	%(rule[0],rule[2],str(violate_perm),rule[1]),never_ref[key][1:3]
		return illeagal_filter(rule,violate_perm,never_ref[key])
		#never_rule_statistic is used to analysis the distribution of neals
		

		#return violate_perm


def illeagal_filter(rule,violate_perms,never_ref):
	# never_ref[1] file
	#never_ref[2] ori_never_rule
	for ne_rule in never_ref[2]:
			for violate_perm in violate_perms:
				if violate_perm in ne_rule[3]:		
					#print "(%s)-[%s:{%s}]->(%s) (vioNeals againest :"\
					#%(rule[0],rule[2],str(violate_perms),rule[1])+str(ne_rule)
					return str(ne_rule)
				

def check_illeagal(never_ref,allow_list):
	#not used;use oem_checker.neverallow_check_rule() instead
	print "Find illeagal rules in NEAL dic:"
	count = 0
	for allow_rule in allow_list:
		#return the neverallow rule.
		lookup_result = lookup_nealdic(never_ref,allow_rule)
		if lookup_result!= None:
			count += 1
			
	print "illeagal rules totally:",count




def cildiff():
	parse_result = dict()
	dev_list = ["Pixel","HUAWEI_P20","mi8se","HUAWEI_Mate20","HUAWEI_BACAL00"]
	oem_dev_list = dev_list[1::]
	ref_dev = dev_list[0] #the first one in dev_list is our reference device.
	for dev in dev_list:
		parse_result[dev] = syscil_parser(dev)


	ref_dev_attrs = parse_result[ref_dev][0]
	#print ref_dev_attrs
	#print "RefDev(%s) attrs:"%ref_dev
	#print ref_dev_attrs
	print len(ref_dev_attrs)
	
	for oemdev in oem_dev_list:
		print " %s  -^-^-^- %s"%(ref_dev,oemdev)

		attrdiff(parse_result[ref_dev][0],parse_result[oemdev][0])
		neverallowdiff(parse_result[ref_dev][1],parse_result[oemdev][1])
	
		print "^^^^^^^^"


def cil_collect_parse():
	parse_result = dict()
	parse_result_np = dict()
	dev_list = ["Pixel","HUAWEI_P20","mi8se","HUAWEI_Mate20","HUAWEI_BACAL00"]
	oem_dev_list = dev_list[1::]
	ref_dev = dev_list[0] #the first one in dev_list is our reference device.
	#Core function to analyse cil file.
	#Get [0]attribute  [1]neverallow [2]allow
	#cil_parser will only do string analysis.
	for dev in dev_list:
		parse_result[dev] = syscil_parser(dev)
		parse_result_np[dev] = npcil_parser(dev)

	return (parse_result,parse_result_np)
	#aosp_sys_allow_rules = parse_result["Pixel"][2]


	

def count_illegalrules_result(file):
	with open(file) as f:
		neal_list = []
		for line in f:
			if ":('" in line:
				bracket_idx = line.index(":('") + 1 
				neal = line[bracket_idx::]
				neal_list.append(neal)

	neal_statistic = dict()		
	for neal in neal_list:
		if neal_statistic.get(neal)==None:
			neal_statistic[neal] = neal_list.count(neal)

	print sorted(neal_statistic.items(),key=lambda a:a[1])
	print "Totally:%d"%len(neal_statistic)


#---------------------------
#vendor cil file parser
def normalcil_parser(dev,cil_file):
	#Used to parse normal cil file(not platform.cil).
	#In these cil files, we dont need to get neverallow file (patterns like ;;lme;;lmx)
	#attribute_dic = gen_attribute_dic(seinfo_file)
	#
	with open(cil_file) as f:
		content = f.read()
		print "In file [%s]"%cil_file.split("/")[-1]
		attribute_dic = normal_attr_parser(content) #Done
		never_allow_entry = normal_never_allow_parser(content) #Done
		allow_entry = normal_allow_parser(content) #Done
		typetrans_entry = normal_typetrans_parser(content)

	return (attribute_dic,never_allow_entry,allow_entry,typetrans_entry)

def normal_typetrans_parser(content):
	#return a list ot tuple
	ret_list = []
	pattern = re.compile(r"\(typetransition .*process.*\)")
	result = pattern.findall(content)
	if result ==[]:
		print "No typetransition in this file"
		return ret_list

	for line in result:
		trans = line.strip("()")
		split_trans = trans.split()
		assert 'typetransition'==split_trans[0]
		assert len(split_trans) == 5
		sub = split_trans[1]
		obj = split_trans[2]
		opt = split_trans[3]
		transto = split_trans[4]
		entry = (sub,obj,opt,transto)
		ret_list.append(entry)

	return ret_list

def normal_never_allow_parser(content):
	tefile_name = "nonplat_sepolicy.cil"
	ret_dict = dict()
	pattern = re.compile(r"\(neverallow .*")
	result = pattern.findall(content)
	if result == []:
		print "No neverallow rules in this file"
		return []

	
	for rule in result:
		assert 'neverallow' in rule.split()[0]
		domain = rule.split()[1]
		_type = rule.split()[2]
		claz = rule.split()[3].strip("(")
		perm = rule.split()[4::]
		expr_normalize(perm)
		if ret_dict.get(tefile_name) == None:
			ret_dict[tefile_name] = [(domain,_type,claz,perm)]
		else:
			ret_dict[tefile_name].append((domain,_type,claz,perm))

	return ret_dict

def normal_attr_parser(content):
	#same as sys cil
	return attr_parser(content)

def normal_allow_parser(content):
	#same as sys cil
	return allow_parser(content)

def parse_result_np(dev):
	cil_file = os.path.join(work_path,dev,ven_cil_file)
	if not os.path.exists(cil_file):
		cil_file = os.path.join(work_path,dev,np_cil_file)

	with open(cil_file) as f:
		content = f.read()
		np_attribute_dic = np_attr_parser(content) #Done
		np_never_allow_entry = np_never_allow_parser(content) #Done
		np_allow_entry = np_allow_parser(content) #TODO
		
	return (np_attribute_dic,np_never_allow_entry,np_allow_entry)
		
#Merge platform,vendor,and mapping cil
def attr_merge(allattrlist):
	#input : dict[attr_name] = (andset,notset)
	ret_dict = allattrlist[0]
	for partofattr in allattrlist:
		if partofattr == allattrlist[0]:
			continue

		for attr in partofattr:
			if ret_dict.get(attr)==None:
				ret_dict[attr] = partofattr[attr]
			else:
				newandset = ret_dict[attr][0]|partofattr[attr][0]
				newnotset = ret_dict[attr][1]|partofattr[attr][1]
				ret_dict[attr] = (newandset,newnotset)

	return ret_dict



def allow_merge():
	pass

if __name__ == '__main__':
	#Used for teest

	dev_list = ["Pixel","HUAWEI_P20","mi8se","HUAWEI_Mate20","HUAWEI_BACAL00"]
	(parse_result,parse_result_np) = cil_collect_parse()
	#finegrained_neverallow_ref_dic stores all neverallow rules in recent Google device
	#all attributes will be expanded to fine-grained domains/types

	#calculated_attributes will generate a specific entry for andset-notset

	#calculated_attributes = attribute_calc(parse_result[ref_dev][0])
	# *The key of neal dict is .te file name , which is not convinent to lookup.
	# *But might be used when tracking rules we interested in 
	finegrained_neverallow_ref_dic = neverallow_expand(parse_result[ref_dev][1],parse_result[ref_dev][0]) #(nev,attr)
	# So we transformed this dict into a new classified dict
	# from {"domain.te":[(),(),()]} to {("domain,type,claz"):(["perms1","perms2"],te_file)}
	classified_FiNeal_dict = clasify_nealdic(finegrained_neverallow_ref_dic)

	#Check all illegal rules in OEM that violate NEALs in newest AOSP 
	for dev in dev_list:
		printlogo(dev)
		finegrained_allow_list = allow_expand(parse_result[dev][2],parse_result[dev][0])
		#check all the rules in oem device which violate againest AOSP neverallow rules
		check_illeagal(classified_FiNeal_dict,finegrained_allow_list)
	#count_illegalrules_result("illegal_rules.result")