# Author:   Samuel Marchal samuel.marchal@aalto.fi
# Copyright 2015 Secure Systems Group, Aalto University, https://se-sy.org/
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys,statistics

from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report
from sklearn import metrics
import pandas as pd
import numpy as np
import pickle


def build_gb(train,features,name):

    trai, _  = pd.factorize(train['label'])
    clf = GradientBoostingClassifier(n_estimators=500,max_depth=3)#(n_estimators=300,max_depth=3)
    clf.fit(train[features], trai)
    f = open("gb_model_" + name + ".pkl",'wb')
    pickle.dump(clf,f)
    f.close()


def predict_gb(test,features,name):

    tes, _ = pd.factorize(test['label'])
    f = open("gb_model_" + name + ".pkl",'rb')
    clf = pickle.load(f)
    f.close()

    mode = 101 # 1: use threshold / 10: print features importance / 100: print missclassified instances

    if mode % 10 == 1:
        threshold = .7
    else:
        threshold = .5

    preds = clf.predict_proba(test[features])
    prediction = np.array([])
    for x in np.nditer(preds[:,1]):
        if x < threshold:
            prediction = np.append(prediction,0)
        else:
            prediction = np.append(prediction,1)


    i = 0
    hr_feat = set()

    for x in np.nditer(clf.feature_importances_):
        if x >= .015 or x <-.02:
            hr_feat.add(i)
            if mode % 100 >=10:
                print(str(i) + " " + str(x))
        i+= 1
  
  
    #metric computation
    false = test[test['label'] != prediction]

    negative = len(test[test['label'] == 0].index)#
    positive = len(test[test['label'] == 1].index)
    fp = len(false[false['label'] == 0].index)
    fn = len(false[false['label'] == 1].index)
    tp = positive - fn
    tn = negative - fp


    fprate = float(fp) / float(negative)
    precision = float(tp) / float(tp+fp)
    recall = float(tp) / float(tp+fn)
    accuracy = float(tp+tn) / float(tp+tn+fp+fn)
    f1 = (2*precision*recall) / (precision + recall)
    
    print(negative,fp,fn,tp,tn,fprate,precision,recall,accuracy,f1)
    print(metrics.precision_recall_fscore_support(test['label'], prediction, average='binary'))


    print("\nGradient Boosting classification results:")
    print(pd.crosstab(test['label'], prediction, rownames=['actual'], colnames=['preds']))
    print("\n")
    print(classification_report(test['label'], prediction))
    

    test["score"] = preds[:,1]
    if mode % 1000 >=100:
        fw = open("intel-res-kiran.csv",'w')
        one = np.array([1]*test.shape[0])

        for index, row in test[test['label'] == one].iterrows():
            fw.write(str(row["start_url"])+","+str(row["score"])+"\n")#+","+str(row["land_url"])+","+str(row["score"])+"\n")#,"land_url","score"]]))
        fw.close()

        
        #print(test[test['label'] != prediction][["start_url"]]),"label","score"]])
        #fw.write(str(test[test['label'] == one][["start_url","land_url","score"]]))

    return fp,fn,tp,tn, hr_feat



# Chelsea added to make automation easier
def build_predict(mode, benign_pkl, phishing_pkl, model_name):
    leg = pd.read_pickle(benign_pkl)
    phish = pd.read_pickle(phishing_pkl)
    exp = model_name

    pd.set_option('display.max_rows', 10000)
    pd.set_option('display.max_columns', 10000)
    np.set_printoptions(threshold=10000)

    feat_vect = pd.concat([leg, phish], ignore_index=True)
    feat_vect = feat_vect.fillna(0)

    features = feat_vect.columns
    features = features.drop(["start_url", "label"])

    features_norm = features

    if int(mode) == 0:
        build_gb(feat_vect, features, exp)

    else:
        fp, fn, tp, tn, other = predict_gb(feat_vect, features, exp)
        return fp, fn, tp, tn


if __name__=="__main__":

    if len(sys.argv) < 5:
        print("build_model.py mode(0:learn/1:predict) legit phish exp_name")
    else:
        #loading

        mode = sys.argv[1]
        leg = pd.read_pickle(sys.argv[2])
        phish = pd.read_pickle(sys.argv[3])
        exp = sys.argv[4]

        pd.set_option('display.max_rows', 10000)
        pd.set_option('display.max_columns', 10000)
        np.set_printoptions(threshold=10000)
        
        
        feat_vect = pd.concat([leg,phish],ignore_index=True)
        feat_vect = feat_vect.fillna(0)

        features = feat_vect.columns
        features = features.drop(["start_url","label"])


        features_norm = features

        if int(mode) == 0:
            build_gb(feat_vect,features,exp)

        else:
            predict_gb(feat_vect,features,exp)

