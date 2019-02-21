#Buil up the mapping between secontext and runtime information of process
# 
#Global configs of related files:(All these files are extracte from Pixel,seversion 28,Android P)
import os
import re
import cilclass
import inspect
from global_configs import *


def seapp_mapping(seapp_file_list):
	#return a dict contains mapping between domain and user
	ret_dict = dict()
	for seapp_file in seapp_file_list:
		with open(seapp_file) as f:
			for line in f:
				user = ''
				domain = ''
				for entry in line.split():	
					if "user=" in entry:#normal domain
						user = entry.split("=")[-1]
					if "domain=" in entry: #system_server domain
						domain = entry.split("=")[-1]
				if domain == '':
					print "illegal line in %s(no domain in line)"%line

				if domain=="system_server":
					ret_dict[domain] = "system"
				else:
					ret_dict[domain] = user

	return ret_dict

def fslookup(fs_handler,exec_filepath):
	#get secontext based on exec_file from filesystem.txt
	#
	fs_handler.seek(0,0)

	exec_dirpath = os.path.dirname(exec_filepath)
	exec_filename = os.path.basename(exec_filepath)
	pattern = re.compile(r"[\d]{4}-[\d]{2}-[\d]{2} [\d]{2}:[\d]{2} "+exec_filename+"\n")
	exec_filelabel = ''
	found_path_status = 0
	for line in fs_handler:
		if line.strip().startswith("."+exec_dirpath+":"):
			found_path_status = 1
			continue
		if len(line.split())>=8:#file entry line
			if (line.strip().split()[8] == exec_filename) and ("->" not in line) and found_path_status== 1:
				exec_filelabel = line.split()[4]
				#print "Get label:",exec_filelabel,exec_filelabel == ''
				break

	if exec_filelabel == '':
		print "Exec file not found in fs:",exec_filepath,exec_dirpath,exec_filepath
		return exec_filelabel
	else:
		return exec_filelabel.split(":")[2]



def exec_file_lookup(execfile_context):
	#get file lelated process secontext based on its exec_file secontext(from typetransition).
	pass


def create_exec2usr_dict(rc_dir_path_list):
	#create mapping from all rc files in a dict
	#process executed by init need the dict
	#ret_dict-{exec_file_context:user}

	unsure_list = []
	unknown_exec = []
	ret_dict = dict()
	fs_handler = open(os.path.join(work_path,ref_dev,filesystem_path))
	for rc_dir_path in rc_dir_path_list:
		rcfile_list = os.listdir(rc_dir_path)
		
		#print rcfile_list
		for file in rcfile_list:
			absfilepath = os.path.join(rc_dir_path,file)
			print "Collecting :%s"%absfilepath
			with open(absfilepath) as f:
				entris = f.read().split("\n\n")
				for entry in entris:
					#Get user for a service entry
					user = ''
					lines = [line.strip() for line in entry.split("\n")]
					for line in lines:
						if line.startswith("#"):
							continue
						if line.startswith("service"):
							#print line
							#default of proc user is root
							user = 'root'
							exec_filepath = line.split()[2]
							continue				
						
						if line.strip().startswith("user"):
							#found a user line
							user = line.split()[-1]
					
					if user == '' :
						continue
					else:
						execfile_context =  fslookup(fs_handler,exec_filepath)
						#print execfile_context
						if execfile_context == '':
							print "Error while running fslookup ",absfilepath,exec_filepath
							execfile_context = str(os.path.basename(exec_filepath))+"_exec(guess)"
							print "Guess %s 's secontext as :%s "%(exec_filepath,execfile_context)
						
							#typename = exec_file_lookup(execfile_context)
						if execfile_context != '': #BUG_ON()
							ret_dict[execfile_context] = user
						else :
							unknown_exec.append(exec_filepath)
							#ret_dict["unknown exec"] = user


	fs_handler.close()
	#print "unsure list (mostlikely be root):",unsure_list
		
	print "unknown list (should not has item):",unknown_exec
	#print "exec2usr dict:",ret_dict #no adbd entry in this dict
	return ret_dict


def create_proc2exec_dict(devins):
	ret_dict = dict()
	for proc in devins.typetrans_dict:
		for types in devins.typetrans_dict[proc]:
		#types[0] = exec_type types[1]=proc_type
			ret_dict[types[1]] = types[0]

	return ret_dict


def create_usr2proc_mapping(devins):
	final_dict = dict()
	print "Initializing usr2proc_mapping dict for init-forked process"
	proc2exec_dict = create_proc2exec_dict(devins) #
	rc_dir_path_list = [os.path.join(work_path,ref_dev,sysrc_directory),os.path.join(work_path,ref_dev,venrc_directory),\
						os.path.join(work_path,ref_dev,rootrc_directory)]

	exec2usr_dict = create_exec2usr_dict(rc_dir_path_list) #original
	#exec2usr_dict = create_exec2usr_dict([os.path.join(work_path,ref_dev,rootrc_directory)])
	for proc in proc2exec_dict:
		print "exec_type:",proc2exec_dict.get(proc)
		print "user:",exec2usr_dict.get(proc2exec_dict.get(proc))
		final_dict[proc] = exec2usr_dict.get(proc2exec_dict.get(proc))
	with open(usr2proc_mapping,"w") as f:
		f.write(repr(final_dict))



def lookupdict(typename):
	with open(usr2proc_mapping) as f:
		usr2proc_dict = eval(f.read())
	return usr2proc_dict.get(typename)
	



#core function
def runtime_feature_collector(devins,trans_path):
	#exported function used by cilclass init (when sub_feature is initialized)
	if trans_path == ["unknown"]:
		#not a process's domain
		#such as *_tmpfs domain releted to fs operation rules
		return "not_proc"
	if not ("init" in trans_path):
		#print "No init in Trans",trans_path
		#crash_dump,su,dumpstate...
		return "root"
	if not os.path.exists(usr2proc_mapping):
		create_usr2proc_mapping(devins)

	idx = len(trans_path)-1
	if idx == 0 :
		print "Innormal trans_path %s"%str(trans_path)
		return "root"
	typename = trans_path[idx]
	parent = trans_path[idx-1]

	if typename == "init" or typename =="vendor_init":
		user = "root"
		return user

	if parent == "zygote":
		#look up seapp file
		user = seapp_info.get(typename)
		return user


	else:
		#look up rc file
		user = lookupdict(typename)	
		#print "lookupdict user:",user
		#user might be None when this type is not defined in rc files or has no exec_file in filesystem
		if user != None:
			return user
		if parent != "init":
			#same as parent's user.recursivly call itself to get parent's user
			return runtime_feature_collector(devins,trans_path[0:-1])
		else:
			#Not rc file record in all its paths
			#Maybe not used in this device but still remained in the policy file
			return "Unknown"
#function ends
######

seapp_info = seapp_mapping([os.path.join(work_path,ref_dev,sys_seapp_file),os.path.join(work_path,ref_dev,ven_seapp_file)])

######
#used for testing 
if __name__ == '__main__':
	#os.system("rm "+usr2proc_mapping)

	devins = cilclass.dev(ref_dev)
	testcase = [['kernel','init', 'adbd'],["kernel","init","zygote","platform_app"],['kernel', 'init', 'drmserver'],\
	['kernel','init', 'asdfasdfasdf'],["kernel",'init','incident_helper'],['kernel', 'init', 'hal_tv_input_default'],['kernel', 'init']]
	for i in testcase:
		print runtime_feature_collector(devins,i)
	
