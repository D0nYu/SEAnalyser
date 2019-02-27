#This script is mainly used to filt all the rules OEM added.
#functions in cilparser might be used
import os
import numpy as np

import cilparser
from cilclass import *
from rules_statistic import *
from tfidf_calc import *
import sys
import random
from sklearn import feature_extraction
from sklearn.feature_extraction.text import CountVectorizer 
from sklearn.feature_extraction.text import TfidfTransformer

outputdir = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/SEanalyser/raw_policy_tobe_ana/"
vioneal_outputdir = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/SEanalyser/raw_policy_tobe_ana/vioneal"
dev_list = ["Pixel","HUAWEI_P20","mi8se","HUAWEI_Mate20","HUAWEI_BACAL00"]
oem_dev_list = dev_list[1::]



def get_diff_allow_list_types(refdev,tardev,**kw):
	#return a dict of featured rules(a list of "rule" class) between aosp types
	print "Get diffing rules now"
	ret_dict = dict()

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
				#aka,oem defined types will be include
				if (not (fr.domain,fr._type,fr.claz,pm) in ref_allow_set):
					if ret_dict.has_key(repr(fr.src_rule)):
						ret_dict[repr(fr.src_rule)].append((fr.domain,fr._type,fr.claz,pm))
					else:
						ret_dict[repr(fr.src_rule)] = list()
						ret_dict[repr(fr.src_rule)].append((fr.domain,fr._type,fr.claz,pm))
					#ret_list2.append((fr.domain,fr._type,fr.claz,pm))
					#print diff rules:
					#print "---"
					#fr.show(perm=pm)
					#src_rule_set.add(str(fr.src_rule.tuple_type()))
					#fr.src_rule.show()
			else : 
				#all oem defined types will not shown in the result. 
				#aka:only types connected and defined in aosp will be returned 
				if (not (fr.domain,fr._type,fr.claz,pm) in ref_allow_set) and \
				(fr.domain in refdev.domset and fr._type in refdev.typeset):
					if ret_dict.has_key(repr(fr.src_rule)):
						ret_dict[repr(fr.src_rule)].append((fr.domain,fr._type,fr.claz,pm))
					else:
						ret_dict[repr(fr.src_rule)] = list()
						ret_dict[repr(fr.src_rule)].append((fr.domain,fr._type,fr.claz,pm))

	'''
	print "-----statics for src_rules-----:"
	for src_rule in src_rule_set:
		print src_rule

	print len(src_rule_set)
	'''
	print len(ret_dict)
	
	return ret_dict

	
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

		#all_target_rules[0] is fr,all_target_rules[1] is the tuple of (d,t,c,p)
		output_filepath = os.path.join(outputdir,oem_dev)
		print "Writing to %s"%output_filepath
		with open(output_filepath,"w") as f:
			#rules_dict = dict()
			#for target_rule in all_target_rules:
			#	if rules_dict.get(repr(target_rule.src_rule)) == None:
			#		rules_dict[repr(target_rule.src_rule)] = set()
			#		rules_dict[repr(target_rule.src_rule)].add(repr(target_rule))
			#	else:
			#		rules_dict[repr(target_rule[0].src_rule)].add(repr(target_rule))

			f.write(repr(len(all_target_rules))+"\n")
			f.write(repr(all_target_rules))
		


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
	fr_perm = fr[3]
	#print [type(f) for f in fr]
	allow_sub = get_target_finegrained_rules(ref_ins,_type=fr_type,claz=fr_claz,perm=fr_perm)
	
	#allow_obj = get_target_finegrained_rules(ref_ins,domain=fr_domain,claz=fr_claz,perm=fr_perm)
	allow_obj = []
	
	neverallow_sub = get_target_finegrained_neals(ref_ins,_type=fr_type,claz=fr_claz,perm=fr_perm)
	#neverallow_obj = get_target_finegrained_neals(ref_ins,domain=fr_domain,claz=fr_claz,perm=fr_perm)
	neverallow_obj = []
	return (list(set(allow_sub)),list(set(allow_obj)),list(set(neverallow_sub)),list(set(neverallow_obj)))

def get_random_subdict(inputdict,num):
	ret_dict = dict()
	for i in range(num):
		key = random.choice(inputdict.keys())
		ret_dict[key] = inputdict[key]
	return ret_dict

def app_simi_judge(src_feature,tar_feature):
	sensitive_feature_list = ["mlstrustedsubject","untrusted_app_all"]
	if src_feature["untrusted_app_all"]==True and tar_feature["untrusted_app_all"] ==True:
		#all untrusted app(_25/_27)
		return 1


def simi_judge(ref_ins,src_sub,tar_sub):
	#src_sub in oem and allowsub in ref_ins
	src_feature = sub_feature(ref_ins,src_sub)
	tar_feature = sub_feature(ref_ins,tar_sub)
	if src_feature["appdomain"] != tar_feature["appdomain"]:
		return 0 

	#Do app simi calc
	if src_feature["appdomain"] == True:
		return app_simi_judge(src_feature,tar_feature)
	#Do sys proc simi calc
	else:
		return sysproc_simi_judge(src_feature,tar_feature)

def get_common_obj(ref_dev,sub1,sub2):
	fr_list1 = [fr for fr in get_target_finegrained_rules(ref_dev,domain=sub1)]
	fr_list2 = [fr for fr in get_target_finegrained_rules(ref_dev,domain=sub2)]
	for fr1 in fr_list1:
		for fr2 in fr_list2:
			if (fr1._type == fr2._type) and (fr1.claz==fr2.claz) and ("getattr" not in fr1.perms):
				print fr1
				print fr2




def check_raw_policy():
	
	#ignore this permissions
	unimportant_perm_list = ["getattr","lock","map","rename","setattr","search","link","unlink"]
	ref_ins = dev(ref_dev,expanded_neal = False,fr_dict=True)
	#ref_ins = dev(ref_dev,expanded_neal = False) #use False for test
	tfidf_ins = tfidf_calc(ref_ins)
	for d in oem_dev_list:
		#oem_ins = dev(d, expanded_neal= False)
		featured_policy_filepath = os.path.join(outputdir,d)
		with open(featured_policy_filepath) as f:
			for line in f:
				if not line.startswith(r"{"):
					dic_lenth = eval(line.strip("\n"))
					continue
				#print line
				raw_rule_dict = eval(line)
				print len(raw_rule_dict)
				test_raw_rule_dict = get_random_subdict(raw_rule_dict,20)
				
				count = 0
				for src_rule in test_raw_rule_dict:
					count += 1
					src_score = 0 
					fine_rules_set = eval(repr(test_raw_rule_dict[src_rule]))
					for fr in fine_rules_set:
						if fr[3] in unimportant_perm_list:
							continue

						print "--------------------------"
						print "[Target_rule]:\033[1;34m %s\033[0m!"%str(fr)
						src_sub = fr[0]
						 
						src_feature = sub_feature(ref_ins,src_sub)
						#print repr(src_feature)

						#when we dont have fr_dict:
						related_rules = get_related_rules(fr,ref_ins)#a tuple of list()
						subs_old = get_subs(related_rules)
						print subs_old
						#now we can directly get it from dict:
						allowsubs = ref_ins.finegrained_allow_dict.get(repr((fr[1],fr[2],fr[3])))  #allow subs
						neverallowsubs = ref_ins.finegrained_neal_dict.get(repr((fr[1],fr[2],fr[3]))) 
						if allowsubs == None:
							allowsubs = []
						else:
							allowsubs = list(set(allowsubs))
						if neverallowsubs == None:
							neverallowsubs = []
						else:
							neverallowsubs = list(set(neverallowsubs))
						print allowsubs,neverallowsubs
						exit()

						print "Number of related_rules(allow,neverallow)(%d,%d)"%(len(allowsubs),len(neverallowsubs))
						if len(allowsubs)>= 1 and len(neverallowsubs)>= 0:
							print "[Allow Subs]:\n",len(allowsubs)
							#calc allow weights among subs
							#Get a weight list for each feature
							allow_distance_dict = dict()
							neverallow_distance_dict = dict()
							allow_weight = tfidf_ins.calc_allow_weight(allowsubs) 
							print "[ALLOW_SUBS]:"
							print allowsubs
							print "[ALLOW_WEIGHT]:"
							print allow_weight

							for allowsub in allowsubs :#calc distance between src_sub and related_allow subs
								feature = sub_feature(ref_ins,allowsub)
								allow_distance_dict[allowsub] = tfidf_ins.calc_distance(src_feature,feature,allow_weight)
							print "[ALLOW_DISTANCE]:"
							print sorted(allow_distance_dict.items(),key=lambda item:item[1])

							print "[Neverallow Subs]:\n",len(neverallowsubs)

							neverallow_weight = tfidf_ins.calc_neverallow_weight(neverallowsubs)
							print "[NEVERALLOW_SUBS]:"
							print neverallowsubs
							print "[NEVERALLOW_WEIGHT]:"
							print neverallow_weight

							for neverallowsub in neverallowsubs :
								feature = sub_feature(ref_ins,neverallowsub)
								neverallow_distance_dict[neverallowsub] = tfidf_ins.calc_distance(src_feature,feature,neverallow_weight)
							print "[NEVERALLOW_DISTANCE]:"
							
							print sorted(neverallow_distance_dict.items(),key=lambda item:item[1])
							print "--------------------------"
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

def gen_basic_classification_dict(devins):
	#devins = dev("Pixel",expanded_neal=False)
	TFvalueset = [True,False]
	feature_class_list = ["appdomain","mlstrustedsubject","halserverdomain"]
	keys = []
	for v1 in TFvalueset:
		for v2 in TFvalueset:
			for v3 in TFvalueset:
				keys.append(tuple((v1,v2,v3)))

	classification_dict = dict()
	for feature in feature_class_list:
		for key in keys:
			classification_dict[key] = list()
			for dom in devins.domset:
				feature_ins = sub_feature(devins,dom)
				if feature_ins.feature_dict["domain"]==True \
				and feature_ins.feature_dict["appdomain"]==key[0] \
				and feature_ins.feature_dict["mlstrustedsubject"]==key[1] \
				and feature_ins.feature_dict["halserverdomain"]==key[2]:
					classification_dict[key].append(dom)

	return classification_dict



	


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
