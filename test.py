import os
work_path = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/"
#

sys_cil_file = "system_etc_selinux/selinux/plat_sepolicy.cil"
ven_cil_file = "vendor_etc_selinux/selinux/nonplat_sepolicy.cil"
seinfo_path = "vendor_etc_selinux/selinux/seinfo_all"

if __name__ == '__main__':
	attri_def_set = set()
	attri_assign_set = set()
	attri_assign_list = []
	dev = "Pixel"
	cil_file = os.path.join(work_path,dev,sys_cil_file)
	with open(cil_file) as f:
		content = f.read().split("\n")
		for line in content:
			if "(typeattribute " in line:
				attribute_define_name = line.strip("()").split(" ")[-1]
				attri_def_set.add(attribute_define_name)

			if "(typeattributeset " in line:
				attri_assign_name = line.strip("()").split(" ")[1]
				attri_assign_set.add(attri_assign_name)
				attri_assign_list.append(attri_assign_name)


	for i in attri_assign_list:
		count = attri_assign_list.count(i)
		if count > 1:
			print i,count

	print len(attri_def_set),len(attri_assign_set),len(attri_assign_list)
