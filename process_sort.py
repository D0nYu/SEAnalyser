import os

class process_entry(object):
	"""docstring for process_entry"""
	def __init__(self, label,uid,pid,ppid):
		super(process_entry, self).__init__()
		self.label = label
		self.uid = uid
		self.pid = pid
		self.ppid = ppid

	def __str__(self):
		return "[%s;%s;%s;%s]"%(self.label,self.uid,self.pid,self.ppid)

	


def parse_psfile(psfile):
	ret_list = []
	with open(psfile) as f:
		for line in f :
			if line.startwith("LABEL") :
				continue
			label = line.split()[0]
			uid = line.split()[1]
			pid = line.split()[2]
			ppid = line.split()[3]
			ret_list.append(process_entry(label,uid,pid,ppid))
	return ret_list


def create_pstree(proc_list):
	#class proc_entry in the input list
	pass


if __name__ == '__main__':
	psfile = "ps_p20"
	proc_list = parse_psfile(psfile)
	create_pstree(proc_list)