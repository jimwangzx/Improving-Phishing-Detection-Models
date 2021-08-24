#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import numpy as np
from sklearn import decomposition
#from sklearn.externals import joblib
import joblib
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder

import model
import feature_extract

from website_fetcher import DLROOT


model_path = DLROOT + '/saved_models/forest_pca.pkl'
model_path_dt = '/home/chelsea/PycharmProjects/phishing/scripts_m1/saved_models/forest_pca_dt.pkl'

x_path = '/home/chelsea/PycharmProjects/phishing/scripts_m1/data/X.txt'
y_path = '/home/chelsea/PycharmProjects/phishing/scripts_m1/data/Y.txt'

x_path_dt = '/home/chelsea/PycharmProjects/phishing/scripts_m1/data/X_dt.txt'
y_path_dt = '/home/chelsea/PycharmProjects/phishing/scripts_m1/data/Y_dt.txt'

no_of_components = 0.95

def parse_options():
    parser = argparse.ArgumentParser(description="running analysis...", prefix_chars='-+/')
    parser.add_argument('-t', '--html', type=str,
                        help='A html source data to extract features')
    parser.add_argument('-i', '--img', type=str,
                        help='A image data to extract features')
    args = parser.parse_args()
    return args

# def load_model():
#     #print("starting prediction....")
#     X = np.loadtxt(x_path)
#     print (X.shape)
#
#     scaler = MinMaxScaler()
#     X_rescaled = scaler.fit_transform(X)
#
#     pca = decomposition.PCA(n_components=no_of_components)
#     pca.fit(X_rescaled)
#
#     #print ("PCA fitted")
#
#     forest = None
#
#     try:
#         forest = joblib.load(model_path)
#     except:
#
#         print("Existing model cannot be used, maybe the sklearn version problem?")
#         print("We begin to retrain the model")
#         X = np.loadtxt(x_path)
#         Y = np.loadtxt(y_path)
#         print ("X shape", X.shape)
#
#         scaler = MinMaxScaler()
#         X_rescaled = scaler.fit_transform(X)
#
#         pca2 = decomposition.PCA(n_components=no_of_components)
#         pca2.fit(X_rescaled)
#         X = pca2.transform(X_rescaled)
#
#         print("X shape after PCA", X.shape)
#
#         forest = model.tree_model_train_and_save(X, Y)
#     return {'model': forest, 'pca': pca}

# Chelsea added for HistGradientBoostingClassifier
def load_model():
    #print("starting prediction....")
    # With column transformer / one hot encoding
    # X = column_transform()
    # Without
    X = np.loadtxt(x_path)
    print(X.shape)

    scaler = MinMaxScaler()
    X_rescaled = scaler.fit_transform(X)

    forest = None

    try:
        forest = joblib.load(model_path)
    except:

        print("Existing model cannot be used, maybe the sklearn version problem?")
        print("We begin to retrain the model")
        X = np.loadtxt(x_path)
        Y = np.loadtxt(y_path)
        print ("X shape", X.shape)

        scaler = MinMaxScaler()
        X_rescaled = scaler.fit_transform(X)

        forest = model.tree_model_train_and_save(X, Y)
    return {'model': forest}

def load_model_dt():
    #print("starting prediction....")
    X = np.loadtxt(x_path)
    print (X.shape)

    scaler = MinMaxScaler()
    X_rescaled = scaler.fit_transform(X)

    pca = decomposition.PCA(n_components=no_of_components)
    pca.fit(X_rescaled)

    #print ("PCA fitted")

    forest = None

    try:
        forest = joblib.load(model_path_dt)
    except:

        print("Existing model cannot be used, maybe the sklearn version problem?")
        print("We begin to retrain the model")
        X = np.loadtxt(x_path)
        Y = np.loadtxt(y_path)
        print ("X shape", X.shape)

        scaler = MinMaxScaler()
        X_rescaled = scaler.fit_transform(X)

        pca2 = decomposition.PCA(n_components=no_of_components)
        pca2.fit(X_rescaled)
        X = pca2.transform(X_rescaled)

        print("X shape after PCA", X.shape)

        forest = model.tree_model_train_and_save(X, Y)
    return {'model': forest, 'pca': pca}

def predict_min(domain, clf, pca):
    if clf == None or pca == None:
      print("Error: Model/PCA not initialized")
      return
    #print(domain)
    #print(content_html)
    v = feature_extract.extract_domain_features(domain)
    if not v:
        print("Fail to extract feature vectors.")
        return

    # Chelsea changed since do not need pca for now
    # new_v = pca.transform(np.asarray(v).reshape(1, -1))
    p_prob = clf.predict_proba(np.asarray(v).reshape(1, -1))
    p = clf.predict(np.asarray(v).reshape(1, -1))
    #print ("Prediction: ----" + str(p.tolist()[0]) + "----" + str(p_prob.tolist()[0]))

    return {'decission': int(p.tolist()[0]), 'prob': p_prob.tolist()[0], 'heuristics': str(v)}

# Chelsea added for HistGradientBoostingClassifier
def predict_min(domain, clf):
    if clf == None:
      print("Error: Model not initialized")
      return
    v = feature_extract.extract_domain_features(domain)
    if not v:
        print("Fail to extract feature vectors.")
        return
    # With column transformer / one hot encoding
    # x_test = np.array(v).reshape(1, -1)
    # x_test_transform = ct.transform(x_test).toarray()
    # p_prob = clf.predict_proba(x_test_transform.reshape(1, -1))
    # p = clf.predict(x_test_transform.reshape(1, -1))

    # Without
    p_prob = clf.predict_proba(np.asarray(v).reshape(1, -1))
    p = clf.predict(np.asarray(v).reshape(1, -1))

    #print ("Prediction: ----" + str(p.tolist()[0]) + "----" + str(p_prob.tolist()[0]))

    return {'decission': int(p.tolist()[0]), 'prob': p_prob.tolist()[0], 'heuristics': str(v)}

def predict(domain):
    print("starting prediction....")
    X = np.loadtxt(x_path)
    print (X.shape)

    scaler = MinMaxScaler()
    X_rescaled = scaler.fit_transform(X)

    pca = decomposition.PCA(n_components=no_of_components)
    pca.fit(X_rescaled)

    print ("PCA fitted")

    forest = None

    try:
        forest = joblib.load(model_path)
    except:

        print("Existing model cannot be used, maybe the sklearn version problem?")
        print("We begin to retrain the model")
        X = np.loadtxt(x_path)
        Y = np.loadtxt(y_path)
        print ("X shape", X.shape)

        scaler = MinMaxScaler()
        X_rescaled = scaler.fit_transform(X)

        pca2 = decomposition.PCA(n_components=no_of_components)
        pca2.fit(X_rescaled)
        X = pca2.transform(X_rescaled)
        print("X shape after PCA", X.shape)

        forest = model.tree_model_train_and_save(X, Y)

    v = feature_extract.extract_domain_features(domain)
    if not v:
        print("Fail to extract feature vectors.")
        return

    # Chelsea changed since don't need pca for now
    # new_v = pca.transform(np.asarray(v).reshape(1, -1))
    p_prob = forest.predict_proba(np.asarray(v).reshape(1, -1))
    p = forest.predict(np.asarray(v).reshape(1, -1))
    print ("Prediction: ----" + str(p.tolist()[0]) + "----" + str(p_prob.tolist()[0]))

    return p 

def predict_dt(domain):
    x_path = '/home/chelsea/PycharmProjects/phishing/scripts_m1/data/X.txt'
    y_path = '/home/chelsea/PycharmProjects/phishing/scripts_m1/data/Y.txt'

    print("starting prediction....")
    X = np.loadtxt(x_path)
    print (X.shape)

    scaler = MinMaxScaler()
    X_rescaled = scaler.fit_transform(X)

    pca = decomposition.PCA(n_components=no_of_components)
    pca.fit(X_rescaled)

    print ("PCA fitted")

    forest = None

    try:
        forest = joblib.load(model_path_dt)
    except:

        print("Existing model cannot be used, maybe the sklearn version problem?")
        print("We begin to retrain the model")
        X = np.loadtxt(x_path)
        Y = np.loadtxt(y_path)
        print ("X shape", X.shape)

        scaler = MinMaxScaler()
        X_rescaled = scaler.fit_transform(X)

        pca2 = decomposition.PCA(n_components=no_of_components)
        pca2.fit(X_rescaled)
        X = pca2.transform(X_rescaled)
        print("X shape after PCA", X.shape)

        forest = model.tree_model_train_and_save(X, Y)

    v = feature_extract.feature_vector_extraction(domain)
    if not v:
        print("Fail to extract feature vectors.")
        return

    print("##### HEURISTICs: ")
    print(v)

    new_v = pca.transform(np.asarray(v).reshape(1, -1))
    p_prob = forest.predict_proba(new_v)
    p = forest.predict(new_v)
    print ("Prediction: ----" + str(p.tolist()[0]) + "----" + str(p_prob.tolist()[0]))

    #return p
    return {'decission': int(p.tolist()[0]), 'prob': p_prob.tolist()[0]}



'''
def main():
    args = parse_options()

    img = os.path.abspath(args.img)
    html = os.path.abspath(args.html)

    print ("Run the prediction...")
    predict(img, html)

    return


if __name__ == "__main__":

    sys.exit(main())
'''
