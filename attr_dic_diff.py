import main

dev1 = "Pixel"
dev2 = "HUAWEI_P20"

if __name__ == '__main__':
	seinfo1 = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/%s/vendor_etc_selinux/selinux/seinfo_all"%dev1
	seinfo2 = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/%s/vendor_etc_selinux/selinux/seinfo_all"%dev2

 	attribute_dic1 = main.gen_attribute_dic(seinfo1)
 	attribute_dic2 = main.gen_attribute_dic(seinfo2)	

 	for attr in attribute_dic1:
 		if attribute_dic2.has_key(attr):
 			list1_len = len(attribute_dic1[attr])
 			list2_len = len(attribute_dic2[attr])
 			if (list2_len>list1_len) :
 				for domain in attribute_dic2[attr]:
 					#each attr is set to several domains
 					if (domain in attribute_dic1[attr]):
 						print "Found attr diff:[attr]--%s:[domain]--%s\n"% (attr,domain)

 		else :
 			print "Found OEM define attr:%s\n"% attr



