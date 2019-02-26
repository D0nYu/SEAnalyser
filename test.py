from sklearn import feature_extraction
from sklearn.feature_extraction.text import CountVectorizer 
from sklearn.feature_extraction.text import TfidfTransformer  
from cilclass import *

dev_ins = dev("Pixel")
testcase1 = ['domain coredomain ']


corpus = ['aaa,ccc ;aaa aaa', 
          'aaa aaa', 
          'aaa aaa aaa', 
          'aaa aaa aaa aaa',
          'aaa bbb aaa bbb aaa',
          'ccc aaa aaa ccc aaa'
         ]

vectorizer = CountVectorizer() 

X = vectorizer.fit_transform(corpus)
  
word = vectorizer.get_feature_names()  
print word
print X.toarray()

transformer = TfidfTransformer()
tfidf = transformer.fit_transform(X)

print tfidf.toarray()
