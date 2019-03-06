from __future__ import division

import matplotlib.pyplot as plt
from oem_checker import *
from random import choice

def draw(data1,data2):
	plt.xlabel("Similiarity/Coverage")
	plt.title("cumulative histogram")
	plt.hist(data1,50,density=True,histtype='step',cumulative=True,alpha=0.75,rwidth=0.8,label='Similiarity')
	plt.hist(data2,50,density=True,histtype='step',cumulative=True,alpha=0.75,rwidth=0.8,label='Coverage')

	plt.xlim((0,1))
	#plt.ylim((0,1))

	my_x_ticks = np.arange(0, 1, 0.1)
	#my_y_ticks = np.arange(0, 1, 0.1)
	plt.xticks(my_x_ticks)
	plt.grid(True)
	plt.legend(loc="right")
	#plt.yticks(my_y_ticks)
	plt.show()

if __name__ == '__main__':
	#testdata = [0.1,0.2,0.92,0.81,0.24,0.525,0.657,0.789,0.799,0.45]
	#draw(testdata)
	#exit()

	devins = dev("Pixel",expanded_neal = False,fr_domain_dict=True,fr_type_dict=True)
	#domset = devins.domset
	domset = devins.attri_dict["domain"].contained_typeset
	domset = [dom for dom in domset if not dom.endswith("_28_0")]
	typeset = devins.attri_dict["file_type"].contained_typeset
	typeset = [_type for _type in typeset if not _type.endswith("_28_0")]
	count = 0
	simi_list = []
	coverage_list = []
	while count <=5000:
		count +=1
		dom1=choice(domset)
		dom2=choice(domset)
		if dom1=="su" or dom2=="su" or dom1==dom2 :
			count = count -1
			continue
		calc_result = calc_dom_simi(devins,dom1,dom2)
		if calc_result[2]>threshold_sim:
			print dom1,dom2
		simi_list.append(calc_result[2])
		coverage_list.append(calc_result[0])
	#print simi_list

	draw(simi_list,coverage_list)

		


