#coding:utf-8
import numpy as np
from sklearn import svm
from oem_checker import *

def make_one_hot(devins,domset):
	raw_feature = []
	behaviorset = set()
	for dom in domset:
		fr_list = get_target_finegrained_rules(devins,domain=dom)
		behaviorset |= set([ (fr._type,fr.claz) for fr in fr_list ])
		
	behavior_list = list(behaviorset)
	
	for dom in domset:
		pass


if __name__ == '__main__':
	devins = dev(ref_dev,expanded_neal = False,fr_domain_dict=True,fr_type_dict=True)
	testdomset = ["system_server","dumpstate","irqbalance","incidentd","perfprofd","shell","thermal-engine","untrusted_app"]
	make_one_hot(devins,testdomset)