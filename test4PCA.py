from sklearn.decomposition import PCA
import numpy as np

#feature_list:
#[0:domain,1:mlstrustedsubject,2:coredomain,3:appdomain,4:untrusted_app_all,5:netdomain,
#6:bluetoothdomain,7:binderservicedomain,8:halserverdomain,9:halclientdomain,10:update_engine_common]

def pcatest(n_components):
	X = np.array([[1,1,1,0,0,0,0,0,0,0,0],[1,1,0,0,0,0,0,0,0,0,0],\
				[1,0,1,0,0,0,0,0,0,0,0],[1,1,1,0,0,1,0,0,0,1,0],\
				[1,1,1,1,0,1,0,0,0,0,0],[1,0,1,1,0,0,0,0,0,0,0],\
				[1,1,1,0,0,0,0,0,0,0,0],[1,1,0,0,0,0,0,0,0,0,0]])

	pca = PCA(n_components = n_components)
	print "---fit_transform----"
	print pca.fit_transform(X)
	print "-------"
	print pca.explained_variance_ratio_
	print "-------"
	print pca.explained_variance_ 

