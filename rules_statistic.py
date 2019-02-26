import cilparser
from cilclass import *
from oem_checker import *

outputdir = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/SEanalyser/raw_policy_tobe_ana/"
vioneal_outputdir = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/SEanalyser/raw_policy_tobe_ana/vioneal"
related_outputdir = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/SEanalyser/raw_policy_tobe_ana/related_rules_cases"
ref_dev = "Pixel"
dev_list = ["Pixel","HUAWEI_P20","mi8se","HUAWEI_Mate20","HUAWEI_BACAL00"]
oem_dev_list = dev_list[1::]

#This py is used to prove the existance of MinimumNecessarySet:
#all domains have same permission on certain type ALWAYS have same attribute set.
def get_target_finegrained_neals(devins,**kw):
	ret_list = []
	condition = True
	for r in devins.finegrained_neal_list:
		if "domain" in kw:
			condition1 = r.domain == kw["domain"]
		else:
			condition1 = True
		if "_type" in kw:
			condition2 = r._type == kw["_type"]
		else:
			condition2 = True
		if "claz" in kw:
			condition3 = r.claz == kw["claz"]
		else:
			condition3 = True
		if "perm" in kw:
			condition4 = kw["perm"] in r.perms
		else:
			condition4 = True

		if condition1 and condition2 and condition3 and condition4:
			ret_list.append(r)

	return ret_list


def get_target_finegrained_rules(devins,**kw):
	
	ret_list = []
	condition = True
	for r in devins.finegrained_allow_list:
		if "domain" in kw:
			condition1 = ((r.domain == kw["domain"]) and (r.domain !="su")) #exclude su type
		else:
			condition1 = True
		if "_type" in kw:
			condition2 = r._type == kw["_type"]
		else:
			condition2 = True
		if "claz" in kw:
			condition3 = r.claz == kw["claz"]
		else:
			condition3 = True
		if "perm" in kw:
			condition4 = kw["perm"] in r.perms
		else:
			condition4 = True

		if condition1 and condition2 and condition3 and condition4:
			ret_list.append(r)

	return ret_list

def get_doms_have_different_attr(ref_devins,oem_devins):
	pubdomset = ref_devins.domset& oem_devins.domset
	for pubdom in pubdomset:
		print pubdom

	print len(pubdomset)
	count = 0 
	for dom in pubdomset:
		if len(get_attr(ref_devins,dom))!=len(get_attr(oem_devins,dom)):
			print dom
			print "ref",get_attr(ref_devins,dom)
			print "oem",get_attr(oem_devins,dom)
			count += 1
	print count

def show_target_dom_attr(devins,_type,claz,perm):
	result = get_target_finegrained_rules(devins,_type=_type,claz=claz,perm=perm)
	for r in result:
		r.show();r.src_rule.show()
		print get_attr(devins,r.domain)
		print "---"
	print len(result)
	
def get_all_related_rules(ref_devins,target_rule):
	domain = target_rule[0]
	_type = target_rule[1]
	claz = target_rule[2]
	perms = target_rule[3]
	allow_list = []
	neal_list = []
	if "file" in claz and "read" in perms :#consider only file read now
		perm = "read"
		allow_list.append(get_target_finegrained_rules(ref_devins,_type=_type,claz=claz,perm=perm))
		allow_list.append(get_target_finegrained_rules(ref_devins,domain=domain,claz=claz,perm=perm))
		neal_list.append(get_target_finegrained_neals(ref_devins,_type=_type,claz=claz,perm=perm))
		neal_list.append(get_target_finegrained_neals(ref_devins,domain=domain,claz=claz,perm=perm))
	return allow_list,neal_list

def do_collecting_realted_rule(ref_devins,rule):
	pass


def get_all_related_rules_in_file():
	ref_devins = dev("Pixel")

	#never_ref = cilparser.neverallow_expand(ref_devins.merged_neal,ref_devins.merged_attr)
	#classified_never_ref = cilparser.clasify_nealdic(never_ref) 
	#print classified_never_ref
	for d in oem_dev_list:
		print "========DEV==========:",d
		featured_policy_filepath = os.path.join(outputdir,d)
		output_related_rules_filepath = os.path.join(related_outputdir,d)
		with open(featured_policy_filepath) as f:
			with open(output_related_rules_filepath,"w") as fout:
				rule_count = 0
				for line in f:
					#preparing args for check_illeagal
					rule_count += 1
					if rule_count% 50 ==0:
						print "%d rules scanded!\n"%rule_count 
					rule = eval(line) #<type 'tuple'>
					#do_collecting_realted_rule(ref_devins,rule)
					fout.write("rules:"+repr(rule)+"\n")
					fine_rules = cilparser.expand_single_rule(rule,ref_devins.merged_attr)
					for fr in fine_rules:
						fout.write("	\nfine_rules:"+repr(fr[0:4])+ "from "+repr(fr[4])+"\n")
						related_rules = []
						related_rules = get_all_related_rules(ref_devins,fr)
						fout.write("	======== Allow list:%d ====\n"%len(related_rules[0]))
						fout.write("	"+repr(related_rules[0])+"\n")
						fout.write( "	======== Neverallow list:%d ====\n"%len(related_rules[1]))
						fout.write("	"+repr(related_rules[1])+"\n")
		
	exit()



if __name__ == '__main__':
	ref_devins = dev("Pixel")
	target_rule = eval("('isolated_app','cust_data_file','lnk_file',['read'])")
	related_rules = get_all_related_rules(ref_devins,target_rule)
	print "\n======== Allow list:%d ====\n"%(len(related_rules[0][0])+len(related_rules[0][1]))
	print related_rules[0]
	print "\n======== Neverallow list:%d ====\n"%(len(related_rules[1][0])+len(related_rules[1][1]))
	print related_rules[1]
	