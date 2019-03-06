#This script is mainly used to filt all the rules OEM added.
#functions in cilparser might be used
from __future__ import division
import os
import numpy as np
import sys
import random,time
from sklearn import feature_extraction
from sklearn.feature_extraction.text import CountVectorizer 
from sklearn.feature_extraction.text import TfidfTransformer


import cilparser
from cilclass import *
from rules_statistic import *
from tfidf_calc import *
from global_configs import *


#outputdir = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/SEanalyser/raw_policy_tobe_ana/"
#vioneal_outputdir = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/SEanalyser/raw_policy_tobe_ana/vioneal"
#dev_list = ["Pixel","HUAWEI_P20","mi8se","HUAWEI_Mate20","HUAWEI_BACAL00"]
#oem_dev_list = dev_list[1::]

threshold_sim = 0.93
threshold_cover = 0.95

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
	#TOO SLOW. NOT USE NOW
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

def normalize(typelist,typename):
	if typelist == None:
		return typelist

	typeset = set(typelist)
	if typename in typeset:
		typeset.remove(typename)

	return list(typeset)


def get_related_subobj(ref_ins,fr):
	allowsubs = ref_ins.fr_tuple2domain_allow_dict.get((fr[1],fr[2],fr[3]))  #allow subs
	neverallowsubs = ref_ins.fr_tuple2domain_neverallow_dict.get((fr[1],fr[2],fr[3])) 
	allowobjs = ref_ins.fr_tuple2type_allow_dict.get((fr[0],fr[2],fr[3]))
	neverallowobjs = ref_ins.fr_tuple2type_neverallow_dict.get((fr[0],fr[2],fr[3]))
	allowsubs = normalize(allowsubs,fr[1]) #exclude duplicate and types opt on itself
	neverallowsubs = normalize(neverallowsubs,fr[1])
	allowobjs = normalize(allowobjs,fr[0])
	neverallowobjs = normalize(neverallowobjs,fr[0])
	return allowsubs,neverallowsubs,allowobjs,neverallowobjs

def find_nearest(ref_ins,candidate_list,fr,src_fr_list,**kw):
	#fr is the original fr to be assessed. ('hal_drm_widevine','media_data_file','dir','ioctl')
	#When 'target' == sub, candidate_list is a list contains all domains that can do (dir,ioctl) on "media_data_file"
	#this function is used to find the nearest domain to fr[0] in candidate_list
	#the similiarity is calculated by the num of allow_objs (src_set in args)
	#
	print "related %s:"%kw["target"]
	print candidate_list
	if kw == None or not kw.has_key("target"):
		print "Need target: sub/obj,Abort."
		exit()
	if candidate_list ==None :
		print "candidate_list == None"
		return "Nop"
	if src_fr_list==None:
		print "src_fr_list ==None "
		return "Nop" 

	candidate_list = set(candidate_list)
	
	if kw["target"]	== "sub":
		src_fr_set = set(src_fr_list)
		for cand in candidate_list:
			cand_fr_set = set(ref_ins.fr_tuple2type_allow_dict.get((cand,fr[2],fr[3])))
			Intersection = len(cand_fr_set&src_fr_set)
			Union = len(cand_fr_set|src_fr_set)-1 #exclued the assessing rule
			print "Simi(%s-%s on [%s,%s]): %d/%d "%(cand,fr[0],fr[2],fr[3],Intersection,Union)
			if cand==fr[0]:
				print "cand:",cand_fr_set
				print "src:",src_fr_set
				exit()

	if kw["target"] == 'obj':
		src_fr_set = set(src_fr_list)
		for cand in candidate_list:
			cand_fr_set = set(ref_ins.fr_tuple2domain_allow_dict.get((cand,fr[2],fr[3])))
			Intersection = len(cand_fr_set&src_fr_set)
			Union = len(cand_fr_set|src_fr_set)
			print "Simi(%s-%s): %d/%d "%(cand,fr[0],Intersection,Union)

def assessment(judge_result,fr):
	label = [] #return the label as assessment on this fr
	relative_subs = judge_result[0] #in relative_subs[0] is sim_sub list, [1]is lower sub list,[2] is higher sub list
	relative_objs = judge_result[1]
	relative_neal_subs = judge_result[2]
	relative_neal_objs = judge_result[3]

	#### Precheck 
	if fr[0] == fr[1] or fr[0] in fr[1]:
		label.append("Allow (private access)")
		return label
	###Level 1 check
	if (fr[0] in relative_subs[0]) and (fr[1] in relative_objs[0]):
		#which means fr is totally same as known rules in aosp
		#this should NEVER HAPPEN in OEM rules check result
		label.append("ALLOW (ori)")
		return label #No need to check more
	if (fr[0] in relative_neal_subs[0]) and (fr[1] in relative_neal_objs[0]):
		label.append("Not Allow (ori)")
		return label #No need to check more
	#### Level 2 check
	if (relative_subs[0]!=[]) or (relative_objs[0]!=[]):
		label.append("Allow(simi)")
		return label #No need to check more
	if (relative_neal_subs[0]!=[] or relative_neal_objs[0]!=[]):
		label.append("Not Allow(simi)")
		return label #No need to check more

	###	Level 3 check
	if (relative_neal_subs[2]!=[] or relative_neal_objs[1]!=[]):
		#a higher domain is not allowed OR a lower type is not allowed,Thus the fr is illegal
		label.append("Not Allow (higher domain or lower type neal found)")
	if (relative_subs[1]!=[] or relative_objs[2]!=[]):
		label.append("Allow (lower domain or higher type allow found)")
	
	if label!=[]:
		return label
	else:
		label.append("Not Allow (unrelated)")



def check_raw_policy():
	illegal_list = []
	unrelated_list = []
	legal_list = []
	unsure_list = []
	#ignore this permissions
	unimportant_perm_list = ["getattr","lock","map","rename","setattr","search","link","unlink"]
	ref_ins = dev(ref_dev,expanded_neal = True,fr_domain_dict=True,fr_type_dict=True)
	#ref_ins = dev(ref_dev,expanded_neal = False) #use False for test
	#tfidf_ins = tfidf_calc(ref_ins)

	for d in oem_dev_list:
		#oem_ins = dev(d, expanded_neal= False)
		print "-*-*-*-*-*-*-*-*-*-*-*"
		print "Device:",d
		featured_policy_filepath = os.path.join(outputdir,d)
		check_result_filepath = os.path.join(outputdir,"vioneal",d)
		with open(featured_policy_filepath) as f,open(check_result_filepath,'w') as fout:
			for line in f:
				if not line.startswith(r"{"):
					dic_lenth = eval(line.strip("\n"))
					continue
				#print line
				raw_rule_dict = eval(line)
				print "Totally input rules:%d"%len(raw_rule_dict)

				test_raw_rule_dict = get_random_subdict(raw_rule_dict,10) #used for test
				#test_raw_rule_dict = raw_rule_dict # release
				count = 0
				large_rule_list = []
				for src_rule in test_raw_rule_dict:
					print "--------------------------"
					#time1 = time.clock()
					if count % 20 == 0 :
						print "%d rules have been scaned"%count

					count += 1
					src_score = 0 
					fine_rules_set = eval(repr(test_raw_rule_dict[src_rule]))
					fr_list = fine_rules_set
					fr_num = len(fine_rules_set)
					
					if fr_num>=30:
						large_rule_list.append(src_rule)
						print "Too many finegrained rules for %s"%str(src_rule)
						print "Randomly select 10 rules to measure"
						fr_count = 0 
						while fr_count < 10:
							fr_count += 1
							fr = random.choice(fine_rules_set)
							fr_list.append(fr)
						fine_rules_set = fr_list
					
					#Check fr in fine_rules_set one by one
					for fr in fine_rules_set:
						#fr_count += 1
						if fr[3] in unimportant_perm_list:
							continue

						
						print "[Target_rule]:%s(from %s)"%(str(fr),src_rule)
						#fout.write("[Target_rule]:%s\n"%str(fr))
						src_sub = fr[0]
						src_obj = fr[1]

						sort_result = sorting_hat(ref_ins,fr)

						assess_result = assessment(sort_result,fr)
						raw_policy_check_result_dict[fr] = assess_result
						'''
						hasSimAllow = (relative_subs!=[[],[]] or relative_objs !=[[],[]])
						hasSimNeal = (relative_neal_subs!=[[],[]] or relative_neal_objs!=[[],[]])
						#Assess by judgement result
						relative_subobj = (relative_subs,relative_objs,relative_neal_subs,relative_neal_objs)
						if hasSimNeal and not hasSimAllow:
							#No similiar allow but has similiar neverallow
							print "[Illegal for sure]:",relative_subobj
							illegal_list.append(fr)
							continue
						if hasSimAllow and not hasSimNeal:
							print "[Legal for sure]:",relative_subobj
							legal_list.append(fr)
							continue
						if not hasSimAllow and not hasSimNeal:
							print "[Seems unrelated]:",relative_subobj
							unrelated_list.append(fr)
							continue
						if hasSimAllow and hasSimNeal:
							print "[Unsure]:",relative_subobj
							unsure_list.append(fr)
							continue
						if fr_count>=30:
							print "Too many finegrained rules for %s"%str(src_rule)
							break
						'''
		print raw_policy_check_result_dict
		
		#end of device d



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


def calc_dom_simi(devins,domA,domB):

	#print "DomA:%s,DomB:%s"%(domA,domB)
	#fr_list1 = get_target_finegrained_rules(devins,domain=domA)
	#fr_list2 = get_target_finegrained_rules(devins,domain=domB)
	#behavior1 = [ (fr._type,fr.claz) for fr in fr_list1 ]
	#behavior2 =  [ (fr._type,fr.claz) for fr in fr_list2 ]
	behavior1 = devins.fr_domain2tuple_allow_dict.get(domA)
	behavior2 = devins.fr_domain2tuple_allow_dict.get(domB)
	if behavior1 == None or behavior2 == None:
		print "Get behavior failed for (%s,%s)"%(domA,domB)
		return (0,0,0)

	A = set(behavior1)&set(behavior2)
	B = set(behavior1)|set(behavior2)

	#print "A-B", set(behavior1)-set(behavior2)
	#print "B-A", set(behavior2)-set(behavior1)
	#print "Coverage to A: %d/%d = %f"%(len(A),len(set(behavior1)),len(A)/len(set(behavior1)))
	#print "Coverage to B: %d/%d = %f"%(len(A),len(set(behavior2)),len(A)/len(set(behavior2)))
	#print "Jaccard Sim:%d/%d = %f"%(len(A),len(B),len(A)/len(B))
	#print time.clock()-time1
	return (len(A)/len(set(behavior1)),len(A)/len(set(behavior2)),len(A)/len(B))

def calc_type_simi(devins,typeA,typeB):
	#print "TypeA:%s,TypeB:%s"%(typeA,typeB)
	
	behavior1 = devins.fr_type2tuple_allow_dict.get(typeA)
	behavior2 = devins.fr_type2tuple_allow_dict.get(typeB)
	if behavior1 == None or behavior2 == None:
		print "Get behavior failed"
		return (0,0,0)

	A = set(behavior1)&set(behavior2)
	B = set(behavior1)|set(behavior2)
	#print "A-B", set(behavior1)-set(behavior2)
	#print "B-A", set(behavior2)-set(behavior1)
	#print "Coverage to A: %d/%d = %f"%(len(A),len(set(behavior1)),len(A)/len(set(behavior1)))
	#print "Coverage to B: %d/%d = %f"%(len(A),len(set(behavior2)),len(A)/len(set(behavior2)))
	#print "Jaccard Sim:%d/%d = %f"%(len(A),len(B),len(A)/len(B))
	#print time.clock()-time1
	return (len(A)/len(set(behavior1)),len(A)/len(set(behavior2)),len(A)/len(B))

def simi_classify(simi):
	#similiarity = (A&B/A,A&B/B, A&B/A|B) where B is ref_sub(allow) and A is sub to be assessed
	# return value:
	# 1:A is similiar to B sim[2]>threshold
	# 2:sim[1]> threshold,which means the target_sub(A) is higher than ref_sub(B)
	#						or target_obj(A) is lower than ref_obj 
	# 3:sim[0]> threshold, which means target(A) is lower than ref_sub(B)
	assert len(simi) == 3
	#if simi[2] == 1:
		#same
		#return 0 
	if simi[2]>threshold_sim or (simi[1]>threshold_cover and simi[0]>threshold_cover):
		return 1 #A is SIMILIAR to B
	if simi[1]>threshold_cover: #and simi[1]>1.5*simi[0]:
		return 2 #A dominate B 
	if simi[0]>threshold_cover:
		return 3 #A(fr,the target type) is dominated by B(ref)

def IsTypeRelative(simi):
	assert len(simi) == 3
	#if simi[2] == 1:
		#same
		#return 0 

	if simi[2]>threshold_sim or (simi[1]>threshold_cover and simi[0]>threshold_cover):
		return 1 #A(fr) is SIMILIAR to B (ref)
	if simi[1]>threshold_cover: #and simi[1]>1.5*simi[0]:
		return 2 #A(fr,the target type) dominate B(ref) when 
	if simi[0]>threshold_cover:
		return 3 #A(fr,the target type) is dominated by B(ref)

def sorting_hat(devins,fr):
	#Found all relative(simi,cover,covered) types in related_subobj based on its simi
	#fr = ('untrusted_app','debugfs_tracing','file','write')
	subobjs = get_related_subobj(devins,fr)
	allowsubs = subobjs[0]
	neverallowsubs = subobjs[1]
	allowobjs = subobjs[2]
	neverallowobjs = subobjs[3]
	#[0]save the simi/ori sub, [1]save the higher subs/lower objs
	#[2] save the lower subs/higher objs (l)
	relative_subs = [[],[],[]] 
	relative_objs = [[],[],[]]
	relative_neal_subs = [[],[],[]]
	relative_neal_objs = [[],[],[]]
	if allowsubs!=None:
		for sub in allowsubs:
			simi = calc_dom_simi(devins,fr[0],sub)
			sub_class_result = simi_classify(simi)
			if sub_class_result == 1 :#simi
				relative_subs[0].append(sub)
			if sub_class_result == 2 : #fr[0] is higher than sub
				relative_subs[1].append(sub) # save in lower list
			if sub_class_result == 3:
				relative_subs[2].append(sub) # save in higher sub list

	if allowobjs != None:
		for obj in allowobjs:
			simi = calc_type_simi(devins,fr[1],obj)
			obj_class_result = simi_classify(simi)
			if obj_class_result == 1:
				relative_objs[0].append(obj)
			if obj_class_result == 2:
				relative_objs[2].append(obj) #save in higher obj list
			if obj_class_result == 3:
				relative_objs[1].append(obj) #save in lower obj list

	if neverallowsubs!= None:
		for sub in neverallowsubs:
			simi = calc_dom_simi(devins,fr[0],sub)
			sub_class_result = simi_classify(simi)
			if sub_class_result == 1 :#simi
				relative_neal_subs[0].append(sub)
			if sub_class_result == 2 : #fr[0] is higher than sub
				relative_neal_subs[1].append(sub) # save in lower list
			if sub_class_result == 3:
				relative_neal_subs[2].append(sub) # save in higher sub list

	if neverallowobjs!= None:
		for obj in neverallowobjs:
			simi = calc_type_simi(devins,fr[1],obj)
			obj_class_result = simi_classify(simi)
			if obj_class_result == 1:
				relative_neal_objs[0].append(obj)
			if obj_class_result == 2:
				relative_neal_objs[2].append(obj) #save in higher obj list
			if obj_class_result == 3:
				relative_neal_objs[1].append(obj) #save in lower obj list


	return relative_subs,relative_objs,relative_neal_subs,relative_neal_objs

if __name__ == '__main__':
	#write_raw_policy_to_ana()
	#neverallow_result = neverallow_check()
	'''	
	ref_ins = dev("Pixel")
	allowsubs = get_target_finegrained_rules(ref_ins,_type="app_data_file",claz='dir',perms=['getattr'])
	print allowsubs
	exit()
	'''
	devins = dev("Pixel",expanded_neal = False,fr_domain_dict=True,fr_type_dict=True)	
	#testdomset = ["system_server","dumpstate","irqbalance","incidentd","perfprofd","shell","thermal-engine","untrusted_app"]
	#testdomset = ["hal_drm_widevine","move-widevine-data-sh","mediaserver","audioserver","untrusted_app","init"]
	illegal_num = 0 
	illegal_rules =[]
	for i in range(50):
		if i %20 ==0 :
			print "%d rules has been checked"%i
		fr_ins = random.choice(devins.finegrained_allow_list)
		fr = (fr_ins.domain,fr_ins._type,fr_ins.claz,random.choice(fr_ins.perms))
		sort_result = sorting_hat(devins,fr)
		#print fr
		#print judge_result
		print "-------"
		if judge_result[0] == [[fr_ins.domain],[]] and judge_result[1]==[[fr_ins._type],[]]:
			illegal_num +=1
			illegal_rules.append(fr)
	print illegal_rules
	print illegal_num
	exit()
		#assessment(judge_result)
	#judgement(devins,fr)
	#exit()

	check_raw_policy()
