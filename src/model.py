#!/usr/bin/env python
# -*- coding: utf-8 -*-


import numpy as np

from sklearn.model_selection import *

from sklearn.neighbors import KNeighborsClassifier
from sklearn import svm

from sklearn.metrics import *
from sklearn.experimental import enable_hist_gradient_boosting
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, HistGradientBoostingClassifier
from sklearn import linear_model
from sklearn import decomposition

from sklearn.naive_bayes import GaussianNB

from matplotlib import pyplot as plt

from sklearn import tree
from sklearn.tree import DecisionTreeClassifier
import graphviz
import pandas as pd

model_path = '/home/chelsea/PycharmProjects/phishing/scripts_m1/saved_models/forest_pca.pkl'
model_path_dt = '/home/chelsea/PycharmProjects/phishing/scripts_m1/saved_models/forest_pca_dt.pkl'

# feature_name_list = ['is_pop_dom_in_domain','is_sensitive_keyword_in_domain','has_out_of_position_tlds','longest_word_in_dom_ratio','has_digits','has_hyphens','randomness_score','domain_length', 'sen_input_feilds','has_bad_action_fields','has_popular_terms_in_tfidf','hash_pop_dom_in_copyright','has_links_to_login_pages']
feature_name_list = ['is_pop_dom_in_domain', 'is_sensitive_keyword_in_domain', 'has_out_of_position_tlds',
                     'has_hyphens_digits', 'domain_length', 'nb_of_dots_in_domain', 'randomness_score',
                     'longest_word_in_str']  # ,'hash_pop_dom_in_copyright', 'has_links_to_login_pages']

n_components = 0.95

max_depth = 7
test_size = 0.25


# this is to get score using cross_validation
def get_scroe_using_cv(clt, X, y):
    scores = cross_val_score(clt, X, y, cv=10)

    print("Accuracy: %0.2f (+/- %0.2f)" % (scores.mean(), scores.std() * 2))


# Ref: https://towardsdatascience.com/understanding-decision-trees-for-classification-python-9663d683c952
def tune_depth_of_dt(X, y):
    max_depth_range = list(range(1, 20))

    accuracy = {}

    print("Evaluating depth of DecisionTreeClassifier...")
    for depth in max_depth_range:
        clf = DecisionTreeClassifier(max_depth=depth,
                                     random_state=0)
        clf.fit(X, y)
        score = clf.score(X, y)
        accuracy[depth] = score

    print(accuracy)
    print('---------------------------------')


# Ref: https://towardsdatascience.com/understanding-decision-trees-for-classification-python-9663d683c952
# def get_feature_importances(X, y):
#   global depth
#   clf = DecisionTreeClassifier(max_depth = depth,
#           random_state = 0)
#   clf.fit(X, y)
#   importances = pd.DataFrame({'feature':X,'importance':np.round(clf.feature_importances_,3)})
#   importances = importances.sort_values('importance',ascending=False)
#   print("Feature importances of DecisionTreeClassifier...")
#   indices = np.argsort(importances)[::-1]
# Print the feature ranking
#   for f in range(X.shape[1]):
#        print("%d. feature %d (%f)" % (f + 1, indices[f], importances[indices[f]]))

#   print('---------------------------------')

def get_my_pecision_recall(clt, X, y):
    global test_size
    random_state = np.random.RandomState(42)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=0)  # random_state)

    clt = clt.fit(X_train, y_train)

    probas_ = clt.predict_proba(X_test)
    predictions = clt.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    precision, recall, _ = precision_recall_curve(y_test, probas_[:, 1])

    auc_pr = auc(recall, precision)

    print(str(clt) + " --- precision score :%f" % auc_pr + " --- Accuracy: " + str(accuracy))
    return precision, recall, auc_pr


def precision_recall_curve_draw(X, y):
    # KNN
    global max_depth
    knn = KNeighborsClassifier(algorithm='auto', leaf_size=30,
                               metric='minkowski', n_neighbors=5, p=2, weights='uniform')
    # decision tree
    # dtree = DecisionTreeClassifier( criterion='entropy', min_samples_leaf=4, min_samples_split=5,
    #                                random_state=None, splitter='best')
    svmrbf = svm.SVC(C=1.0, cache_size=200, class_weight=None, coef0=0.0, degree=3, kernel='rbf',
                     max_iter=-1, probability=True, random_state=None,
                     shrinking=True, tol=0.001, verbose=False)
    # random forest
    rforest = RandomForestClassifier(bootstrap=True, criterion='gini', max_depth=None, max_features='auto',
                                     class_weight='balanced',
                                     min_samples_leaf=1, min_samples_split=5, n_estimators=50, n_jobs=1,
                                     oob_score=False, random_state=0)

    dtree = DecisionTreeClassifier(max_depth=max_depth, random_state=0)

    p_knn, r_knn, auc_knn = get_my_pecision_recall(knn, X, y)
    # p_dtree, r_dtree, auc_dtree = get_my_pecision_recall(dtree, X, y)
    p_rforest, r_rforest, auc_rforest = get_my_pecision_recall(rforest, X, y)
    p_svmrbf, r_svmrbf, auc_svmrbf = get_my_pecision_recall(svmrbf, X, y)
    p_dtree, r_dtree, auc_dtree = get_my_pecision_recall(dtree, X, y)

    plt.clf()
    plt.plot(r_svmrbf, p_svmrbf, 'y.--', label='SVM auc=%0.3f' % auc_svmrbf)
    plt.plot(r_knn, p_knn, 'r^--', label='KNN auc=%0.3f' % auc_knn)
    # plt.plot(r_dtree, p_dtree, 'b>--', label ='Decision Tree auc=%0.3f'% auc_dtree)
    plt.plot(r_rforest, p_rforest, 'go--', label='RF auc=%0.3f' % auc_rforest)
    plt.plot(r_dtree, p_dtree, 'b*--', label='DT auc=%0.3f' % auc_dtree)
    plt.grid()
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.0])
    plt.xlabel('recall rate')
    plt.ylabel('precision rate')
    plt.title('precision-recall curve')
    plt.legend(loc="lower right")
    # plt.show()
    plt.savefig('./roc_curve.jpg')
    del X
    del y


def get_fpr_tpr(clt, x, y):
    global test_size
    print("\n")
    print(clt)

    random_state = np.random.RandomState(0)
    X_train, X_test, y_train, y_test = train_test_split(x, y, test_size=test_size, random_state=0)  # random_state)

    clt = clt.fit(X_train, y_train)
    y_pred = clt.predict(X_test)

    # accuracy score
    _accuracy_score = accuracy_score(y_test, y_pred)
    print("Accuracy score {}".format(_accuracy_score))

    pred = clt.predict(X_test)
    fp, fn = 0, 0
    for i, c in enumerate(pred):
        if c == 1 and y_test[i] == 0:
            fp += 1
        if c == 0 and y_test[i] == 1:
            fn += 1
    print("False positive: %f" % (float(fp + 0.0) / len(y_test)))
    print("False negative: %f" % (float(fn + 0.0) / len(y_test)))

    # roc curve
    probas_ = clt.predict_proba(X_test)
    # print (probas_)
    # draw_confusion_matrix(y_test,y_pred)

    # print probas_
    fpr, tpr, thresholds = roc_curve(y_test, probas_[:, 1])
    # print (fpr, tpr,thresholds)
    roc_auc = auc(fpr, tpr)
    print("Area under the ROC curve : %f" % roc_auc)
    return fpr, tpr, roc_auc


# Ref: https://scikit-learn.org/stable/modules/tree.html
def draw_decission_tree(x, y):
    global feature_name_list
    global max_depth
    # dtree = DecisionTreeClassifier( criterion='entropy', min_samples_leaf=4, min_samples_split=5,
    #                                random_state=None, splitter='best')
    # def print_fpr_tpr(fpr_dtree, tpr_dtree):
    #    for i, j in zip(fpr_dtree, tpr_dtree):
    #        print (str(i)+","+str(j))

    print("Processing decission tree....")
    # Ref: https://towardsdatascience.com/scikit-learn-decision-trees-explained-803f3812290d
    # Ref: https://pypi.org/project/graphviz/
    # clf = DecisionTreeClassifier(max_depth=5, random_state=None, splitter='best')
    ###clf = DecisionTreeClassifier(random_state=99)
    clf = DecisionTreeClassifier(max_depth=max_depth, random_state=0)
    # clf = DecisionTreeClassifier( criterion='entropy', min_samples_leaf=4, min_samples_split=5,
    #                                random_state=None, splitter='best')

    clf.fit(x, y)

    # print("Deceission tree")
    # get_scroe_using_cv(clf, x, y)
    # fpr_dtree, tpr_dtree, auc_dtree = get_fpr_tpr(clf, x, y)
    # print ("============= Decission Tree ================")
    # print_fpr_tpr(fpr_dtree, tpr_dtree)

    # Ref: https://scikit-learn.org/stable/modules/tree.html
    tree.plot_tree(clf)

    # feature_name_list = ['no_of_forms', 'is_title_not_empty', 'use_of_unsafe_anchors', 'iframes_with_invisible_borders', 'external_css', 'forms_with_empty_actions', 'number_of_hyperlinks']
    # feature_name_list = ['no_of_forms', 'login_info_in_input_fields', 'is_title_empty', 'brand_in_html', 'brand_in_img', 'domain_no_of_consec_chars', 'domain_shannon_entropy', 'domain_number_of_hyphens', 'domain_number_of_digits', 'domain_length', 'domain_min_lev_distance']
    ##feature_name_list = ['is_pop_dom_in_domain','is_sensitive_keyword_in_domain','has_out_of_position_tlds','longest_word_in_dom_ratio','has_digits','has_hyphens','randomness_score','dom_length','sen_input_feilds','has_bad_action_fields','has_popular_terms_in_tfidf','hash_pop_dom_in_copyright','has_links_to_login_pages']

    # dot_data = tree.export_graphviz(clf, out_file='./dtree.txt')
    dot_data = tree.export_graphviz(clf, out_file=None, filled=True, class_names=["phishing", "benign"], rounded=True,
                                    feature_names=feature_name_list)
    # dot_data.render('./decission_tree.gv', view=True)
    graph = graphviz.Source(dot_data)
    graph.render(filename='dtree', format='png')


def draw_confuse_matrix(x, y, clt=None):
    global test_size
    if clt is None:
        clt = RandomForestClassifier(bootstrap=True, criterion='gini', max_depth=None, max_features='auto',
                                     class_weight='balanced',
                                     min_samples_leaf=1, min_samples_split=5, n_estimators=50, n_jobs=1,
                                     oob_score=False, random_state=0)
    print(clt)

    random_state = np.random.RandomState(0)
    X_train, X_test, y_train, y_test = train_test_split(x, y, test_size=test_size, random_state=random_state)

    clt = clt.fit(X_train, y_train)
    y_pred = clt.predict(X_test)
    cm = confusion_matrix(y_test, y_pred)

    print(cm)

    # Show confusion matrix in a separate window
    """
    plt.matshow(cm)
    plt.title('Confusion matrix')
    plt.colorbar()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    plt.show()
    """


def train_and_draw_roc(X_original, y):
    global max_depth
    bayes = GaussianNB()
    # KNN
    knn = KNeighborsClassifier(algorithm='auto', leaf_size=30,
                               metric='minkowski', n_neighbors=5, p=2, weights='uniform')

    # decision tree
    # dtree = DecisionTreeClassifier( criterion='entropy', min_samples_leaf=4, min_samples_split=5,
    #                                random_state=None, splitter='best')

    svmrbf = svm.SVC(C=1.0, cache_size=200, class_weight=None, coef0=0.0, degree=3, kernel='rbf',
                     max_iter=-1, probability=True, random_state=None,
                     shrinking=True, tol=0.001, verbose=False)

    rforest = RandomForestClassifier(bootstrap=True, criterion='gini', max_depth=None, max_features='auto',
                                     class_weight='balanced',
                                     min_samples_leaf=1, min_samples_split=5, n_estimators=50, n_jobs=1,
                                     oob_score=False, random_state=0)

    logit = linear_model.LogisticRegression()

    dtree = DecisionTreeClassifier(max_depth=max_depth, random_state=0)
    # dtree.fit(x, y)

    # def print_fpr_tpr(fpr_knn, tpr_knn):
    #    for i, j in zip(fpr_knn, tpr_knn):
    #        print (str(i)+","+str(j))

    X = np.asarray(X_original)
    print("Train shape {}".format(X.shape))
    # print ("1-label: {}".format(sum(1 for i in Y if i==1)))
    print("1-label: {}".format(sum(1 for i in y if i == 1)))

    # print ("KNN")
    # get_scroe_using_cv(knn, X, y)

    # print ("DT")
    # get_scroe_using_cv(dtree, X, y)

    # print ("RF")
    # get_scroe_using_cv(rforest, X, y)

    # print ("SVM")
    # get_scroe_using_cv(svmrbf, X, y)

    # print ("Lstrestreeeogit")
    # get_scroe_using_cv(logit, X, y)

    # print("Deceission tree")
    # get_scroe_using_cv(dtree, X, y)

    # fpr_knn, tpr_knn, auc_knn = get_fpr_tpr(knn, X, y)

    # print ("=============KNN================")
    # print_fpr_tpr(fpr_knn,tpr_knn)

    # print ("=============================")
    # fpr_dtree, tpr_dtree, auc_dtree = get_fpr_tpr(dtree, X, y)
    # fpr_rforest, tpr_rforest, auc_rforest = get_fpr_tpr(rforest, X, y)

    # print ("=============Random Forest================")
    # print_fpr_tpr(fpr_rforest, tpr_rforest)

    # fpr_svm, tpr_svm, auc_svm = get_fpr_tpr(svmrbf, X, y)

    # print ("=============SVM================")
    # print_fpr_tpr(fpr_svm, tpr_svm)

    # print ("=============================")

    # fpr_nb, tpr_nb, auc_nb = get_fpr_tpr(bayes, X, y)

    # print ("=============NB================")
    # print_fpr_tpr(fpr_nb, tpr_nb)
    # fpr_dtree, tpr_dtree, auc_dtree = get_fpr_tpr(dtree, X, y)
    # print ("=============Decission Tree================")
    # print_fpr_tpr(fpr_dtree, tpr_dtree)

    # fpr_dtree, tpr_dtree, auc_dtree = get_fpr_tpr(clf, x, y)


def train_and_draw_roc_for_different_set_features(X_original, y):
    global n_components
    # random forest
    rforest = RandomForestClassifier(bootstrap=True, criterion='gini', max_depth=None, max_features='auto',
                                     class_weight='balanced',
                                     min_samples_leaf=1, min_samples_split=5, n_estimators=50, n_jobs=1,
                                     oob_score=False, random_state=0)

    X = np.asarray(X_original)
    X1 = np.delete(X, np.s_[988:], axis=1)  # only image

    X2 = np.delete(X, np.s_[0:988], axis=1)  # only text
    X2 = np.delete(X2, np.s_[988:], axis=1)

    X3 = np.delete(X, np.s_[0:1976], axis=1)  # only form

    print(np.array_equal(X1, X2))
    print("only image", X1.shape)
    print("only text", X2.shape)
    print("only form", X3.shape)

    print("TOTAL Train shape {}".format(X.shape))
    # print ("1-label: {}".format(sum(1 for i in Y if i==1)))

    # get_scroe_using_cv(dtree, X, y)
    # plt.clf()

    Xs = [X, X1, X2, X3]
    color = ['b', 'g', 'r', 'y']
    l = ['All', 'Image Only', 'Text only', 'Form only']
    print("RF")
    i = 0
    for Xx, c in zip(Xs, color):
        print("============={}=============".format(l[i]))
        print("Train shape {}".format(Xx.shape))
        pca = decomposition.PCA(n_components)
        pca.fit(Xx)
        Xx = pca.transform(Xx)
        get_scroe_using_cv(rforest, Xx, y)
        fpr_rforest, tpr_rforest, auc_rforest = get_fpr_tpr(rforest, Xx, y)
        print("===================\n\n")
        s = " %.3f" % auc_rforest
        label = l[i] + s
        # plt.plot(fpr_rforest, tpr_rforest, c+'o--', label = label)
        i += 1

    """
    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlim([-0.02, 1.02])
    plt.ylim([-0.02, 1.02])
    plt.xlabel('FPR(False Positive Rate)',fontsize=20)
    plt.ylabel('TPR(True Positive Rate)',fontsize=20)
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.grid()
    plt.show()
    del X
    del y
    """


def tree_model_train_and_save_dt(x, y, clf=None):
    global feature_name_list
    global max_depth
    x = np.asarray(x)

    # random forest parameters
    if clf is None:
        # random forest
        # forest = RandomForestClassifier(bootstrap=True, criterion='gini', max_depth=None, max_features='auto',
        #                                 class_weight='balanced',
        #                                 min_samples_leaf=5, min_samples_split=5, n_estimators=50, n_jobs=1,
        #                                 oob_score=False, random_state=42)
        '''
        clf = DecisionTreeClassifier(criterion='gini', max_depth=None, max_features='auto',
                                         class_weight='balanced',
                                         min_samples_leaf=5, min_samples_split=5,
                                         random_state=42)
        '''
        clf = DecisionTreeClassifier(max_depth=max_depth, random_state=0)  # criterion='gini')
    # get_scroe_using_cv(forest, x, y)
    clf.fit(x, y)

    # from sklearn.externals import joblib
    import joblib
    joblib.dump(clf, model_path_dt)

    tree.plot_tree(clf)
    ###feature_name_list = ['is_pop_dom_in_domain','is_sensitive_keyword_in_domain','has_out_of_position_tlds','longest_word_in_dom_ratio','has_digits','has_hyphens','randomness_score','dom_length','sen_input_feilds','has_bad_action_fields','has_popular_terms_in_tfidf','hash_pop_dom_in_copyright','has_links_to_login_pages']
    dot_data = tree.export_graphviz(clf, out_file=None, filled=True, class_names=["phishing", "benign"], rounded=True,
                                    feature_names=feature_name_list)
    graph = graphviz.Source(dot_data)
    graph.render(filename='dtree_ext', format='png')


def tree_model_train_and_save(x, y, forest=None):
    x = np.asarray(x)

    # random forest parameters
    if forest is None:
        # random forest
        # forest = RandomForestClassifier(bootstrap=True, criterion='gini', max_depth=None, max_features='auto',
        #                                  class_weight={0:.7, 1:.3},
        #                                  min_samples_leaf=1, min_samples_split=5, n_estimators=50, n_jobs=1,
        #                                  oob_score=False, random_state=0)

        # forest = RandomForestClassifier(bootstrap=True, criterion='gini', max_depth=None, max_features='auto',
        #                                 class_weight={0:.7, 1:.3},
        #                                 min_samples_leaf=3, min_samples_split=8, n_estimators=250, n_jobs=1,
        #                                 oob_score=False, random_state=0)

        forest = GradientBoostingClassifier(max_depth=None, min_samples_leaf=3, min_samples_split=8, n_estimators=250,
                                            random_state=0, max_features='auto')
        # forest = HistGradientBoostingClassifier(max_depth=None, min_samples_leaf=3,
        #                                     random_state=0)
    get_scroe_using_cv(forest, x, y)
    forest.fit(x, y)

    # from sklearn.externals import joblib
    import joblib
    joblib.dump(forest, model_path)


    importances = forest.feature_importances_
    # std = np.std([tree.feature_importances_ for tree in forest.estimators_], axis=0)
    indices = np.argsort(importances)[::-1]

    # Print the feature ranking
    print("Feature ranking:")

    for f in range(x.shape[1]):
        print("%d. feature %d (%f)" % (f + 1, indices[f], importances[indices[f]]))

    # Plot the feature importances of the forest
    """
    plt.figure()
    plt.title("Feature importances")
    plt.bar(range(x.shape[1]), importances[indices],
            color="r", yerr=std[indices], align="center")
    plt.xticks(range(x.shape[1]), indices)
    plt.xlim([-1, x.shape[1]])
    plt.show()
    """
    return forest


'''
if __name__ == "__main__":
    X = np.loadtxt("./data/X.txt")
    Y = np.loadtxt("./data/Y.txt")
    print ("X shape", X.shape)

    pca = decomposition.PCA(n_components=100)
    pca.fit(X)
    X = pca.transform(X)
    print ("X shape after PCA", X.shape)

    print (sum(1 for i in Y.tolist() if i ==1))

    tree_model_train_and_save(X, Y)
'''
