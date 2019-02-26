from __future__ import division
from cilclass import *
from global_configs import *
from sklearn.feature_extraction import DictVectorizer
import numpy as np
import time,math,logging

class tfidf_calc(object):
	"""docstring for ClassName"""
	def __init__(self, refdev_ins):
		super(tfidf_calc, self).__init__()
		print "Init tf-idf"
		#values used for tfidf calc.
		self.refdev_ins = refdev_ins
		self.feature_dict = self.get_feature_dict()

		global_freq_dict = self.get_global_freq_dict()
		#returned dict: [("domains",True):0.98,("userlevel","root"):0.38...]
		self.global_allow_freq_dict = global_freq_dict[0]
		self.global_neverallow_freq_dict = global_freq_dict[1]
		self.num_allow_rules = len(refdev_ins.finegrained_allow_list)
		self.num_neverallow_rules = len(refdev_ins.finegrained_neal_list)
		print "Tf-idf value initialized"

	def get_feature_dict(self):
		ret_dict = dict()
		for domain in self.refdev_ins.domset:
			if ret_dict.get(domain) == None:
				ret_dict[domain] = sub_feature(self.refdev_ins,domain).feature_dict
		return ret_dict

	def get_global_freq_dict(self):
		ret_allow_dict = dict()
		ret_neverallow_dict = dict()

		for feature in feature_dict_keys:
			#print "Feature:",feature
			if feature == "userlevel":
				for feature_value in ["root","system","shell", "app_shared","app","isolated","vendor"]:
					ret_allow_dict[(feature,feature_value)] = self.freq_calc_rules(feature,feature_value,self.refdev_ins.finegrained_allow_list)
					ret_neverallow_dict[(feature,feature_value)] = self.freq_calc_rules(feature,feature_value,self.refdev_ins.finegrained_neal_list)
					
			else:
				ret_allow_dict[(feature,True)] = self.freq_calc_rules(feature,True,self.refdev_ins.finegrained_allow_list)
				ret_neverallow_dict[(feature,True)] = self.freq_calc_rules(feature,True,self.refdev_ins.finegrained_neal_list)
				#ret_allow_dict[(feature,False)] = self.freq_calc_rules(feature,False,self.refdev_ins.finegrained_allow_list)
				#ret_neverallow_dict[(feature,False)] = self.freq_calc_rules(feature,False,self.refdev_ins.finegrained_neal_list)
		return ret_allow_dict,ret_neverallow_dict


	def freq_calc_rules(self,feature,value,target_list):
		#calc sum(feature = value) /
		total_sum = len(target_list)
		count_i = 0
		for rule in target_list:
			#print repr(rule),feature
			if self.feature_dict[rule.domain][feature] == value:
				count_i+=1
		#print "%d/%d = %.3f"%(count_i,total_sum,count_i/total_sum)
		return count_i/total_sum

	def freq_calc_subs(self,kv,sub_list):
		#calc sum(feature = value) /
		total_sum = len(sub_list)
		if total_sum == 0:
			return 0 
		count_i = 0
		for sub in sub_list:
			if self.feature_dict[sub][kv[0]] == kv[1]:
				count_i+=1
		#print "%d/%d = %.3f"%(count_i,total_sum,count_i/total_sum)
		return count_i/total_sum

	def calc_allow_weight(self,subs):#subs is a list of all related subjects
		#Wi = TFi * IDFi
		#OUT weight_dict = {"domain",True):w1,"("domain",False):w2}
		#IN subs:
		weight_dict = dict()
		for kv in self.global_allow_freq_dict:
			#kv[0] = feature_name ; kv[1] = value
			tf = self.freq_calc_subs(kv,subs)
			if tf == 0 :
				#logging.warning("tf =0 for %s"%str(kv))
				weight_dict[kv] = 0
			else:
				precise = 0
				if self.global_allow_freq_dict[kv] > precise:
					idf = math.log(1/self.global_allow_freq_dict[kv])
				else :
					logging.debug("Not enough case for (%s)"%str(kv[0]))
					idf = 0
				weight_dict[kv] = tf * idf 
			logging.debug("Get weight[%s]:%.3f"%(str(kv),weight_dict[kv]))
		weight_dict[("appdomain",True)] = 10
		return weight_dict
			
	def calc_neverallow_weight(self,subs):#subs is a list of all related subjects
		#Wi = TFi * IDFi
		#OUT weight_dict = {"domain",True):w1,"("domain",False):w2}
		#IN subs:
		weight_dict = dict()
		for kv in self.global_neverallow_freq_dict:
			#kv[0] = feature_name ; kv[1] = value
			tf = self.freq_calc_subs(kv,subs)
			if tf == 0 :
				logging.warning("tf =0 for %s"%str(kv))
				weight_dict[kv] = 0
			else:
				precise = 0 
				if self.global_neverallow_freq_dict[kv] > precise:
					#enough cases for this feature	
					idf = math.log(1/self.global_neverallow_freq_dict[kv])
				else:
					logging.debug("Not enough case for (%s)"%str(kv[0]))
					idf = 0

				weight_dict[kv] = tf * idf #

			logging.debug("Get weight[%s]:%.3f"%(str(kv),weight_dict[kv]))
		
		weight_dict[("appdomain",True)] = 10

		return weight_dict
			
	def weight_dict_vectorize(self,weight_dict):
		#weight < 1/e will be set to 0
		ret_vec = [0] * 17

		#for f in weight_dict:
		#	if self.global_allow_freq_dict[f]<0.1 and self.global_neverallow_freq_dict[f]<0.1:
		#		weight_dict[f] = 0

		#attr_feature weights (ordered):
		#"domain","mlstrustedsubject","coredomain","appdomain","untrusted_app_all",\
		#"netdomain","bluetoothdomain","binderservicedomain","halserverdomain","halclientdomain",\
		#"untrusted_domain"
		ret_vec[0] = weight_dict[("domain",True)]
		ret_vec[1] = weight_dict[("mlstrustedsubject",True)]
		ret_vec[2] = weight_dict[("coredomain",True)]
		ret_vec[3] = weight_dict[("appdomain",True)]
		ret_vec[4] = weight_dict[("untrusted_app_all",True)]
		ret_vec[5] = weight_dict[("netdomain",True)]
		ret_vec[6] = weight_dict[("bluetoothdomain",True)]
		ret_vec[7] = weight_dict[("binderservicedomain",True)]
		ret_vec[8] = weight_dict[("halserverdomain",True)]
		ret_vec[9] = weight_dict[("halclientdomain",True)]
		ret_vec[10] = weight_dict[("untrusted_domain",True)]

		#userlevel_feature weights:(ordered):
		#root,system,shell,app_shared,app,isolated. (000000 for unknown)
		ret_vec[11] = weight_dict[("userlevel","root")]
		ret_vec[12] = weight_dict[("userlevel","system")]
		ret_vec[13] = weight_dict[("userlevel","shell")]
		ret_vec[14] = weight_dict[("userlevel","app_shared")]
		ret_vec[15] = weight_dict[("userlevel","app")]
		ret_vec[16] = weight_dict[("userlevel","isolated")]

		return ret_vec


	def calc_distance(self,src_feature,target_feature,weight_dict):
		weight_dict_vec = self.weight_dict_vectorize(weight_dict)
		#print src_feature.feature_vector
		#print target_feature.feature_vector
		#print weight_vec
		weight_array = np.array(weight_dict_vec)
		a1 = np.array(src_feature.feature_vector) 
		a2 = np.array(target_feature.feature_vector)
		a1_weight = np.multiply(a1,weight_array)
		a2_weight = np.multiply(a2,weight_array)
		cosine_distance = np.dot(a1_weight, a2_weight) / (np.sqrt(np.dot(a1_weight,a1_weight)) * np.sqrt(np.dot(a2_weight,a2_weight)))
		return cosine_distance

if __name__ == '__main__':
	refdev_ins = dev("Pixel",expanded_neal=False)
	#print "untrusted_app" in refdev_ins.domset
	tfidf_ins = tfidf_calc(refdev_ins)
	print tfidf_ins.global_allow_freq_dict
	print tfidf_ins.global_neverallow_freq_dict

	#print repr(tfidf_calc.global_allow_freq_dict)
	#print repr(tfidf_calc.global_neverallow_freq_dict)
	test_subs = ["isolated_app","untrusted_v2_app","logger_app","priv_app"]
	test_subs2 = ["untrusted_v2_app","logger_app","priv_app","bluetooth","system_server",\
				"radio","traceur_app","qcneservice","profman","hardware_info_app","runas",\
				"wfc_activation_app","system_app","shell","untrusted_app_27","untrusted_app_25",\
				]
	test_feature_list = [sub_feature(refdev_ins,sub).feature_dict for sub in test_subs ]

	#print tfidf_ins.global_neverallow_freq_dict[('halclientdomain', True)]
