README
======

Summary
-------
The goal of this program is (a) to identify if the webpage pointed by a given 
URL is a phishing website and (b) if it is identify its target.

Details
-------

With the modules in this directory you can:
(1) download the contents of a website given its URL (website_fetcher.py).
(2) extracts a set of 210 features form the website content that are relevant
    for phishing identification (build_feat_vec.py).
(3) build a phishing detection model based on features extracted from several phishing and clean webpages (build_model.py)
(4) classify a given webpage as phishing or legitimate and identify its target
    (build_model.py)

Details
-------

First you have to gather website data using the website_fetcher script. It will produce a JSON file containing the data required for feature extraction in addition to a screenshot of the website. Those will be placed in a “website/” directory at the same level as where the script is located. Prior to execute the script you must set the following environment variables: 

$ export NSPR_LOG_MODULES=timestamp,nsHttp:5,nsSocketTransport:5,nsStreamPump:5,nsHostResolver:5
$ export NSPR_LOG_FILE=ABSOLUTE_PATH_TO_SCRIPT/firefox_log.txt 

You have to set the second variable with the path to where the website_fetcher.py script is. This is very important to record the logged links. Then you can execute the fetcher script using this command where you just have to provide the URL of the website you want to fetch :

$ python3 website_fetcher.py www.huawei.com

Once you have fetched several websites with there associated JSON files in the website directory. You must extract features from these file using the build_feat_vec script that takes as argument 1) the directory where the JSON file are stored, 2) the prefix you want to name the output file with (pickle file) and 3 the label of webpage you extract features from (legitimate: 0, phishing: 1):

$ python3 build_feat_vec.py websites2 test python3 website_fetcher.py www.huawei.com
python3 build_feat_vec.py /home/chelsea/PycharmProjects/off-the-hook/websites benign_train 0


Finally you can train a model using the build_model script which takes as argument 0 for training, a pickle file resenting legitimate websites (extracted with build_feat_vec) and a pickle file resenting phishing websites (extracted with build_feat_vec). The last argument is the name of the model (pickle file too). 

$ python3 build_model.py mode(0:learn/1:predict) legit phish model_name
python3 build_model.py 0 benign_train_fvm.pkl phishing_train_fvm.pkl model

Test on phishtank + alexa
python3 build_model.py 1 benign_test_fvm.pkl phishing_test_fvm.pkl model
python3 build_model.py 1 benign_test_FP_fvm.pkl phishing_test_fvm.pkl model
python3 build_model.py 1 benign_test_FP_fvm.pkl phishing_test_TP_fvm.pkl model
Test on new domains
python3 build_model.py 1 new_benign_test_2_fvm.pkl new_phishing_test_2_fvm.pkl model

Test on domains labeled phishing by first model
alexa + phishtank
python3 build_model.py 1 benign_FP_fvm.pkl phishing_TP_fvm.pkl model
New domains
python3 build_model.py 1 new_domains_FP_fvm.pkl new_domains_TP_fvm.pkl model

You can use the same script with mode 1 to get prediction results while providing a model_name pointing to a previously trained model.


Notes
-----
* Written in Python 3.
* Both of the modules mentioned above can also be used from the command line.
* Both modules are documented in docstrings. Check them out for more details.
* Any and all comments and bug reports are welcome!

Dependencies
------------
math
unidecode:unidecode
twisted.python
twisted.internet
autobahn.twisted.websocket
urllib.parse
json
pickle
hashlib
random
goslate
os
platform:architecture
sklearn:(some sub-modules)
requests
time.sleep
numpy
pandas 
statistics 
re 
publicsuffix
bs4.BeautifulSoup
datetime
collections

