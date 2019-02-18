import os

#Save all configs
#Root directory
work_path = "/Users/Don/Desktop/Learning_Exercise/SEAndroid/"

#Customize work_path where cil related files are saved.

sys_cil_file = "system_etc_selinux/selinux/plat_sepolicy.cil"
ven_cil_file = "vendor_etc_selinux/selinux/vendor_sepolicy.cil"#seversion >= 28
ven_seapp_file = "vendor_etc_selinux/selinux/vendor_seapp_contexts"
np_cil_file = "vendor_etc_selinux/selinux/nonplat_sepolicy.cil"#seversion < 28
np_seapp_file = "vendor_etc_selinux/selinux/nonplat_seapp_contexts"
mapping_dir = "system_etc_selinux/selinux/mapping"
sysver_cil_file = "vendor_etc_selinux/selinux/plat_pub_versioned.cil"
version_file ="vendor_etc_selinux/selinux/plat_sepolicy_vers.txt"
sys_seapp_file = "system_etc_selinux/selinux/plat_seapp_contexts"
sysrc_directory = "sysrc_files"
venrc_directory = "venrc_files"
rootrc_directory = "rootrc_files"
filesystem_path = "filesystem.txt"
#Set output dir where policy entries to be analysed
outputdir = os.path.join(work_path,"SEanalyser/raw_policy_tobe_ana/")
vioneal_outputdir = os.path.join(outputdir,"vioneal")
related_outputdir = os.path.join(outputdir,"related_rules_cases")
usr2proc_mapping = os.path.join(outputdir,"ref_usr2proc_mapping")

#Set ref_dev and devices to be analysed
ref_dev = "Pixel"
dev_list = ["Pixel","HUAWEI_P20","mi8se","HUAWEI_Mate20","HUAWEI_BACAL00"]
oem_dev_list = dev_list[1::]


#Set path of runtime rc files 
