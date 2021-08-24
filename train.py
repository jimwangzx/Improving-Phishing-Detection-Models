#!/usr/local/bin/python3.8

import warnings



import WORD_TERM_KEYS

warnings.filterwarnings('ignore')

import sys, os
import subprocess
import traceback

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import mysql.connector
from mysql.connector import Error

import numpy as np

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
sys.path.append('*60scripts_m1/Gibberish-Detector')

import feature_extract
import model
import predict


from pytz import timezone

tz = timezone('EST')

import signal


try:
    import Image
except ImportError:
    from PIL import Image


import WORD_TERM_KEYS_MOD


FILTER_KEYS = WORD_TERM_KEYS.FILTER_KEYS
FILTER_BRANDS = WORD_TERM_KEYS_MOD.WORD_TERM_BRAND

components = 0.95



# Ref: https://stackoverflow.com/questions/2281850/timeout-function-if-it-takes-too-long-to-finish
class timeout:
    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        signal.alarm(0)


mysql_user = 'root'
mysql_pwd = 'mysql'
mysql_db = 'phishing_results_schema'

record_limit = 2000
data_dir = '/home/chelsea/PycharmProjects/phishing/scripts_m1/data/'


mal_dir = '/home/chelsea/PycharmProjects/phishing/out/ph_updated_src/'
benign_dir = '/home/chelsea/PycharmProjects/phishing/out/bn_updated_src_a/'


ct = ColumnTransformer([('encoder', OneHotEncoder(handle_unknown = 'ignore'), [0])], remainder='passthrough')
# x = open(data_dir + 'X.txt', 'r')
# list_of_lists = []
# for line in x:
#     import re
#
#     row = []
#     stripped_line = line.strip()
#     line_list = stripped_line.split()
#     for feat_val in line_list:
#         if re.match(r'^[-]?[0-9]*[.]?[0-9]+$', feat_val):
#             feat_val = float(feat_val)
#         row.append(feat_val)
#     list_of_lists.append(row)
# x_train = np.array(list_of_lists, dtype=object)
# ct.fit(x_train)


def create_db():
    global pghost
    global db
    global postgres_user
    global db_create_sql_file

    print("Creating database/tables (if not exist)")

    cmd = '/opt/lampp/bin/mysql -u ' + mysql_user + ' -p' + mysql_pwd + ' < ' + db_create_sql_file
    print("Running command => " + cmd)
    output = subprocess.getoutput(cmd)
    print(output)
    print('--------------------------------------')

    """ Connect to MySQL database """
    print("Connecting to mysql database [phishing_results_schema]...")
    conn = None
    try:
        conn = mysql.connector.connect(host='127.0.0.1',
                                       database='phishing_results_schema',
                                       port='3306',
                                       user='root',
                                       password='mysql',
                                       raise_on_warnings=True)
        if conn.is_connected():
            print('Connected to MySQL database - phishing_results_schema')
            return conn

    except Error as e:
        print(str(e))
        traceback.print_exc(file=sys.stdout)


def connect_result():
    """ Connect to MySQL database """
    # print("Connecting to mysql database [phishing_results_schema]...")
    conn = None
    try:
        conn = mysql.connector.connect(host='127.0.0.1',
                                       database='phishing_results_schema',
                                       port='3306',
                                       user='root',
                                       password='mysql',
                                       raise_on_warnings=True)
        if conn.is_connected():
            # print('Connected to MySQL database - phishing_results_schema')
            return conn

    except Error as e:
        print(str(e))
        traceback.print_exc(file=sys.stdout)


def is_unicode(content):
    try:
        if content: content.decode("utf-8")
    except Exception as e:
        return 0
    return 1


def delete_file(path):
    if os.path.exists(path):
        os.remove(path)


def append_to_file(path, entry):
    with open(path, 'a+') as the_file:
        the_file.write(entry + '\n')


def list_to_str(ele_list):
    if ele_list:
        return ' '.join(map(str, ele_list))
    return ''


def has_numbers(input_string):
    return any(char.isdigit() for char in input_string)


def generate_data():
    phishing = open("/var/tmp/chelsea/phishing_train.txt", "r")
    benign = open("/var/tmp/chelsea/benign_train.txt", "r")

    timeout_val = 10
    # delete data files
    delete_file(data_dir + 'X.txt') # /home/chelsea/PycharmProjects/phishing/scripts_m1/data/X.txt
    delete_file(data_dir + 'Y.txt') # /home/chelsea/PycharmProjects/phishing/scripts_m1/data/Y.txt

    counter = 0

    # Extract features from phishing domains
    while True:
        try:
            res_str = ""
            with timeout(seconds=timeout_val):
                # Get next line from file
                domain = phishing.readline().strip()

                # if line is empty
                # end of file is reached
                if not domain:
                    break
                res = feature_extract.extract_domain_features(domain)
                res_str = list_to_str(res)

                append_to_file(data_dir + 'X.txt', res_str)
                append_to_file(data_dir + 'Y.txt', "1")
                counter += 1
            # if counter >= 250:
            #     break
            print("PHISHING:", counter)

        except Exception as e:
            print(str(e))
            traceback.print_exc(file=sys.stdout)
            pass

    counter = 0

    # Extract features from benign domains
    while True:
        try:
            res_str = ""
            with timeout(seconds=timeout_val):
                # Get next line from file
                domain = benign.readline().strip()

                # if line is empty
                # end of file is reached
                if not domain:
                    break
                res = feature_extract.extract_domain_features(domain)
                res_str = list_to_str(res)

                append_to_file(data_dir + 'X.txt', res_str)
                append_to_file(data_dir + 'Y.txt', "0")
                counter += 1
            # if counter >= 250:
            #     break
            print("BENIGN:", counter)

        except Exception as e:
            print(str(e))
            traceback.print_exc(file=sys.stdout)
            pass

    phishing.close()
    benign.close()



def column_transform():
    x = open(data_dir + 'X.txt', 'r')
    list_of_lists = []
    for line in x:
        import re
        row = []
        stripped_line = line.strip()
        line_list = stripped_line.split()
        for feat_val in line_list:
            if re.match(r'^[-]?[0-9]*[.]?[0-9]+$', feat_val):
                feat_val = float(feat_val)
            row.append(feat_val)
        list_of_lists.append(row)
    x_train = np.array(list_of_lists)

    # ct = ColumnTransformer([('encoder', OneHotEncoder(), [2])], remainder='passthrough')
    x_train_transform = ct.fit_transform(x_train).toarray()
    print(x_train_transform)
    x.close()
    return x_train_transform



def predict_site(domain):
   prd_res = predict.predict(domain)
   print(prd_res)
   return prd_res   # Chelsea added


def build_model():
    global components

    # With column transformer / one hot encoding
    # X = column_transform()
    # Without
    X = np.loadtxt(data_dir + 'X.txt')

    Y = np.loadtxt(data_dir + 'Y.txt')

    print("X shape", X.shape)
    print("Y shape", Y.shape)

    model.tree_model_train_and_save(X, Y)






def main(argv):
    # generate_data()
    build_model()

    # total = 0
    # phish = 0
    # res_obj = predict.load_model()  # Chelsea changed to predict.load_model() (without dt)
    # model = res_obj['model']
    # f = open("/var/tmp/chelsea/phishing_test.txt", "r")
    # right = open("/var/tmp/chelsea/phishing_test_TP.txt", "a")
    # while True:
    #     # Get next line from file
    #     domain = f.readline()
    #
    #     # if line is empty, end of file is reached
    #     if not domain:
    #         break
    #
    #     r = predict.predict_min(domain.strip(), model)
    #     # Chelsea alternative
    #     if r['prob'][1] > 0.75:
    #         phish += 1
    #         right.write(domain)
    #     # else:
    #     #     right.write(domain)
    #     total += 1
    #     print("Total domains:", total, phish/total)
    # f.close()
    # print("Total domains:", total)
    # print("Domains labeled phising:", phish)
    # print("Accuracy:", phish / total)



    # argv1 = sys.argv[1] if len(sys.argv) > 1 else ""
    # predict_site_t(argv1)


### MAIN ###
if __name__ == "__main__":
    # execute only if run as a script
    main(sys.argv[1:])

