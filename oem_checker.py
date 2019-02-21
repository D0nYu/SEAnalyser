#This script is mainly used to filt all the rules OEM added.
#functions in cilparser might be used
import os
import numpy as np

import cilparser
from cilclass import *
from rules_statistic import *
from tfidf_calc import *
import sys


outputdir = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/SEanalyser/raw_policy_tobe_ana/"
vioneal_outputdir = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/SEanalyser/raw_policy_tobe_ana/vioneal"
dev_list = ["Pixel","HUAWEI_P20","mi8se","HUAWEI_Mate20","HUAWEI_BACAL00"]
oem_dev_list = dev_list[1::]

def get_diff_allow_list_types(refdev,tardev,**kw):
	#return a list of featured rules(a list of "rule" class) between aosp types
	print "Get diffing rules now"
	ret_list = []
	same_rule_list = []
	src_rule_set = set()
	ref_allow_set = set()
	target_allow_set = set()
	for i in refdev.finegrained_allow_list:
		for perm in i.perms:
			ref_allow_set.add((i.domain,i._type,i.claz,perm))

	for fr in tardev.finegrained_allow_list:
		for pm in fr.perms:
			if "include_oem_types" in kw and kw["include_oem_types"] == True:
				#all types including oem types not shown in ref device will be returned 
				if (not (fr.domain,fr._type,fr.claz,pm) in ref_allow_set):
					ret_list.append(fr)
					#print diff rules:
					#print "---"
					#fr.show(perm=pm)
					#src_rule_set.add(str(fr.src_rule.tuple_type()))
					#fr.src_rule.show()
			else : #all oem defined types will not shown in the result. 
					#aka:only types connected and defined in aosp will be returned 
				if (not (fr.domain,fr._type,fr.claz,pm) in ref_allow_set) and \
				(fr.domain in refdev.domset and fr._type in refdev.typeset):
					ret_list.append(fr)

	'''
	print "-----statics for src_rules-----:"
	for src_rule in src_rule_set:
		print src_rule

	print len(src_rule_set)
	'''
	print len(ret_list)
	
	return ret_list

	
def get_attr(dev_instance,typename):
	ret_list = []

	for attr in dev_instance.attri_dict:
		if typename in dev_instance.attri_dict[attr].contained_typeset and not (typename+"_"+dev_instance.seversion.replace(".","_"))==attr:
			ret_list.append(attr)

	ret_list.sort()
	return ret_list


def write_raw_policy_to_ana():
	ref_devins = dev(ref_dev)
	print oem_dev_list
	for oem_dev in oem_dev_list:
		all_target_rules = get_diff_allow_list_types(ref_devins,dev(oem_dev))
		output_filepath = os.path.join(outputdir,oem_dev)
		print "Writing to %s"%output_filepath
		with open(output_filepath,"w") as f:
			rules_dict = dict()
			for target_rule in all_target_rules:
				if rules_dict.get(repr(target_rule.src_rule)) == None:
					rules_dict[repr(target_rule.src_rule)] = set()
					rules_dict[repr(target_rule.src_rule)].add(repr(target_rule))
				else:
					rules_dict[repr(target_rule.src_rule)].add(repr(target_rule))

			f.write(repr(len(rules_dict))+"\n")
			f.write(repr(rules_dict))


def belongsto(_type,attri,attri_dict):
	#check whether this type belongs to the attr.(or identical)
	if _type==attri:
		return True

	if attri_dict.get(attri)!=None:
		if _type in attri_dict[attri].contained_typeset:
			return True
		else:
			return False


def neverallow_check_rule(never_ref,fine_ins,attri_dict):
	#arg[0]:<rule> ;	arg[1]:<finegrained_rule> ;	 	arg[2]:dict of <attribute>
	for fr in fine_ins:
		for neal in never_ref:
			if belongsto(fr.domain,neal.domain,attri_dict) and belongsto(fr._type,neal._type,attri_dict)\
			and fr.claz==neal.claz and (set(fr.perms)&set(neal.perms)!=set()):
				return neal
	return None
	



def neverallow_check():
	#return a list of tuple [(allowrule, violated neal),...]
	print "writing policy to file"
	ret_list = []
	ref_devins = dev(ref_dev)
	ref_attri_dict = ref_devins.attri_dict
	never_ref = cilparser.neverallow_expand(ref_devins.merged_neal,ref_devins.merged_attr)
	classified_never_ref = cilparser.clasify_nealdic(never_ref)
	for d in oem_dev_list:
		print "DEV:",d
		featured_policy_filepath = os.path.join(outputdir,d)
		output_vioneal_filepath = os.path.join(vioneal_outputdir,d)
		#never_ref = ref_devins.finegrained_neal_list #<type 'rule'>
	
		with open(featured_policy_filepath) as f:
			with open(output_vioneal_filepath,"w") as fout:
				neal_count = 0 
				rule_count = 0
				for line in f:
					#preparing args for check_illeagal
					rule_count += 1
					if rule_count% 1000 ==0:
						print "%d rules scanded!\n"%rule_count 
					rule = eval(line) #<type 'tuple'>
					fine_rules = cilparser.expand_single_rule(rule,ref_devins.merged_attr)
					for fr in fine_rules:
						check_result = cilparser.lookup_nealdic(classified_never_ref,fr)#return violated neal
						if check_result!=None:
							break

					if check_result==None:
						continue
					else:
						neal_content = (rule,check_result)
						fout.write(repr(neal_content)+"\n")


def get_related_rules(fr,ref_ins):
	#fr :('dubaid','dubai_service','service_manager',['add', 'find']) defined in oem
	#Get all related rules in pixel:
	fr_domain = fr[0]
	fr_type = fr[1]
	fr_claz = fr[2]
	fr_perms = fr[3]
	allow_sub = get_target_finegrained_rules(ref_ins,_type=fr_type,claz=fr_claz,perms=fr_perms)
	
	allow_obj = get_target_finegrained_rules(ref_ins,domain=fr_domain,claz=fr_claz,perms=fr_perms)

	
	neverallow_sub = get_target_finegrained_neals(ref_ins,_type=fr_type,claz=fr_claz,perms=fr_perms)
	neverallow_obj = get_target_finegrained_neals(ref_ins,domain=fr_domain,claz=fr_claz,perms=fr_perms)

	return (list(set(allow_sub)),list(set(allow_obj)),list(set(neverallow_sub)),list(set(neverallow_obj)))

def check_raw_policy():
	ref_ins = dev(ref_dev,expanded_neal = True)
	tfidf_ins = tfidf_calc(ref_ins)
	for d in oem_dev_list:
		#oem_ins = dev(d, expanded_neal= True)
		featured_policy_filepath = os.path.join(outputdir,d)
		with open(featured_policy_filepath) as f:
			for line in f:
				if not line.startswith(r"{"):
					dic_lenth = eval(line.strip("\n"))
					continue
				raw_rule_dict = eval(line)
			
				print len(raw_rule_dict)
				count = 0
				for src_rule in raw_rule_dict:
					count += 1
					src_score = 0 
					fine_rules_set = eval(repr(raw_rule_dict[src_rule]))
					for fr in fine_rules_set:
						print "--------------------------"
						print "[Target_rule]:\033[1;35m %s\033[0m!"%str(fr)
						src_sub = eval(fr)[0]
						src_feature = sub_feature(ref_ins,src_sub)
						#print repr(src_feature)

						related_rules = get_related_rules(eval(fr),ref_ins)#a tuple of list()
						subs = get_subs(related_rules)
						print "Number of related_rules(allow,neverallow)(%d,%d)"%(len(subs[0]),len(subs[1]))
						if len(subs[0])>= 5 and len(subs[1])>= 5:
							print "[Allow Subs]:\n",len(subs[0])
							#calc allow weights among subs
							#Get a weight list for each feature
							distance_dict = dict()
							neverallowdistance_dict = dict()
							allow_weight = tfidf_ins.calc_allow_weight(subs[0]) 
							print "[ALLOW_SUBS]:"
							print subs[0]
							print "[ALLOW_WEIGHT]:"
							print allow_weight

							for allowsub in subs[0] :#calc distance between src_sub and related_allow subs
								feature = sub_feature(ref_ins,allowsub)
								distance_dict[allowsub] = tfidf_ins.calc_distance(src_feature,feature,allow_weight)
							print "[ALLOW_DISTANCE]:"
							print distance_dict

							print "[Neverallow Subs]:\n",len(subs[1])

							neverallow_weight = tfidf_ins.calc_neverallow_weight(subs[1])
							print "[NEVERALLOW_SUBS]:"
							print subs[1]
							print "[NEVERALLOW_WEIGHT]:"
							print neverallow_weight

							for neverallowsub in subs[1] :
								feature = sub_feature(ref_ins,neverallowsub)
								neverallowdistance_dict[neverallowsub] = tfidf_ins.calc_distance(src_feature,feature,neverallow_weight)
							print "[NEVERALLOW_DISTANCE]:"
							
							print distance_dict
							print "--------------------------"
							if count >= 10:
								exit()



def get_subs(related_rules):
	related_allow_types = []
	related_neverallow_types = []
	for i in related_rules[0]:
		related_allow_types.append(i.domain)
	for j in related_rules[2]:
		related_neverallow_types.append(j.domain)

	return list(set(related_allow_types)),list(set(related_neverallow_types))

def get_feature(ref_dev,typename):
	#feature_list:
	#[0:domain,1:mlstrustedsubject,2:coredomain,3:appdomain,4:untrusted_app_all,5:netdomain,
	#6:bluetoothdomain,7:binderservicedomain,8:halserverdomain,9:halclientdomain]

	feature_list = [0]*10
	feature_domain_lookuplist = ["domain","mlstrustedsubject","coredomain","appdomain","untrusted_app_all",\
								"netdomain","bluetoothdomain","binderservicedomain","halserverdomain","halclientdomain"]

	attr_list = get_attr(ref_dev,typename)
	for attr in attr_list:
		for lookup_entry in feature_domain_lookuplist:
			if attr==lookup_entry:
				idx = feature_domain_lookuplist.index(lookup_entry)
				feature_list[idx] = 1

	type_transition_feature =[]


	return feature_list


if __name__ == '__main__':
	#write_raw_policy_to_ana()
	#neverallow_result = neverallow_check()
	'''	
	ref_ins = dev("Pixel")
	allowsubs = get_target_finegrained_rules(ref_ins,_type="app_data_file",claz='dir',perms=['getattr'])
	print allowsubs
	exit()
	'''

	check_raw_policy()
