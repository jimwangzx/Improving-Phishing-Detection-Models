import os
import shutil
from datetime import date
import sys
import pandas as pd
import pathlib
import predict
from build_model import build_predict
from website_fetcher import WebsiteFetcher
from get_phishing_domains import get_phishtank_domain
from get_tranco_domains import get_top_tranco_domains
from check_domain_with_vt import analyze_url_vt
from build_feat_vec import brands, current_milli_time, feature_vector
from extract_URL import Extractor
from website import Website
from website_fetcher import DLROOT

# Obtain today's date for naming all files and folders
today = date.today()
date = today.strftime("%b%d")


def get_phishing_domains(limit, phishing_domains):
    """
    Extracts phishing domains from Phishtank, verifies with VirusTotal that they have been
    flagged by at least five engines and saves them in a text file.

    Parameters
    ----------
    limit: int
        Number of domains to have saved in the text file.
    phishing_domains: str
        Name of the path to the text file in which the data is to be stored. By default, they
        are stored in the same directory as the script being run.

    Returns
    -------
    phishing_domains_VT_check: string
        Name of the path to the text file with phishing domains.
    """
    r = get_phishtank_domain()
    f = open(phishing_domains, "w")
    for domain, v in r.items():
        f.write(domain + '\n')
    f.close()

    # Perform initial filtering with VT to ensure that the domains are phishing
    f = open(phishing_domains, "r")
    phishing_domains_VT_check = phishing_domains[:-4] + "_VT_check.txt"
    domains = open(phishing_domains_VT_check, "a")
    count = 0
    while True:
        if count >= limit:
            break
        # Get next line from file
        url = f.readline().strip()
        # if line is empty, end of file is reached
        if not url:
            break
        r = analyze_url_vt(url)
        if 'mal_status' in r and 'phishing' in r['mal_status'] and r['mal_status']['phishing'] >= 5:
            domains.write(url + '\n')
            count += 1
            print(count, url)
    f.close()
    domains.close()
    return phishing_domains_VT_check


def get_benign_domains(limit, benign_domains):
    """
    Extracts benign domains from Tranco, and saves them in a text file.

    Parameters
    ----------
    limit: int
        Number of domains to have saved in the text file.
    benign_domains: str
        Name of the path to the text file in which the data is to be stored. By default,
        they are stored in the same directory as the script being run.
    """
    r = get_top_tranco_domains(limit)
    # Don't extract the top n domains since those were likely used for training. Note that limit > n.
    n = 3000
    count = 0
    f = open(benign_domains, "w")
    for domain in r:
        count += 1
        if count < n:
            continue
        f.write(domain + '\n')

    f.close()


def generate_JSON(domains_text_file, final_test_text_file, final_test_JSON_dir, test_size):
    """
    Generates JSON files and screenshots.
    Since there are request failures when capturing JSON files, the domains from which JSON files could
    be captured are appended to after_filtering_domains.txt, the code for which is in website_fetcher.py.
    This way, the same domains could be used with both our domain-based model and Off-the-Hook’s content-based model.

    Parameters
    ----------
    domains_text_file: str
        Name of the path to the initial text file containing domains from which we wish to extract JSON files.
    final_test_text_file: str
        Name of the path to the resulting text file which contains the domains for which JSON capture
        was successful, i.e., what after_filtering_domains.txt is renamed to.
    final_test_JSON_dir: str
        Name of the path to the directory containing the JSON files and screenshots of the domains.
    test_size: int
        Number of domains we wish to test on.
        Indicates the limit of the how many JSON files are generated.
    """
    f = open(domains_text_file, "r")
    while True:
        url = f.readline().strip()
        if not url:
            break
        print(url)

        fetcher = WebsiteFetcher(confirm=True)
        fetcher.fetch_and_save_data(url)

        with open(DLROOT + "/after_filtering_domains.txt") as test_domains:
            num_domains = sum(1 for _ in test_domains)
        if num_domains >= test_size:
            break
    f.close()

    # Rename the general file and folder used in website_fetcher
    after_filterting = DLROOT + "/after_filtering_domains.txt"   # File from website_fetcher.py that contains the final test domains
    shutil.move(after_filterting, final_test_text_file)
    
    websites_dir = DLROOT + "/websites/"
    shutil.move(websites_dir, final_test_JSON_dir)


def generate_pkl(websites_dir, prefix, target):
    """
    Generates pkl file from the JSON files
    Adapted from Off-the-Hook's build_feat_vec.py

    Parameters
    ----------
    websites_dir: str
        Name of the path to the directory containing the JSON files.
    prefix: str
        Name to be assigned to the pickle file generated.
    target: int
        Label of domains from which features were extracted (benign: 0, phishing: 1).
    """
    sys.setrecursionlimit(10000)
    websitedir = os.path.abspath(websites_dir)
    extractor = Extractor()
    label = int(target)
    feat_vec_temp = {}
    print(brands)

    i = 0

    pd.set_option('display.max_rows', 1000)

    for f in sorted(os.listdir(websitedir)):
        start_time = current_milli_time()

        if f.find(".json") > 0:
            print(websitedir + "/" + f)
            ws = Website(jspath=websitedir + "/" + f)
            intermediate = current_milli_time()
            feat_vect_site = feature_vector(extractor, ws)
            end_time = current_milli_time()
            feat_vect_site["start_url"] = f
            feat_vect_site["label"] = label
            feat_vec_temp[i] = feat_vect_site
            i += 1
            print(ws.starturl)

        elif f.find(".png") < 0:
            ws = Website(websitedir + "/" + f + "/sitedata.json")
            intermediate = current_milli_time()
            feat_vect_site = feature_vector(extractor, ws)
            end_time = current_milli_time()
            feat_vect_site["start_url"] = ws.starturl
            feat_vect_site["label"] = label
            feat_vec_temp[i] = feat_vect_site
            i += 1
            print(ws.starturl)

    featvecmat = pd.DataFrame(feat_vec_temp)
    print(featvecmat.shape)
    featvecmat.transpose().to_pickle(prefix + "_fvm.pkl")



if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Please include the number of domains with which you would like to test the stacked model.")
        exit(0)
    else:
        test_size = int(sys.argv[1])


    # GET BENIGN DATA
    benign_domains = f"/var/tmp/phishing/{date}_benign_domains.txt"
    get_benign_domains(3000 + test_size*2, benign_domains)

    benign_test_text_file = f"/var/tmp/phishing/{date}_benign_test.txt"
    benign_test_JSON_dir = DLROOT + f"/{date}_benign_test/"
    generate_JSON(benign_domains, benign_test_text_file, benign_test_JSON_dir, test_size)


    # # GET PHISHING DATA
    phishing_domains = f"/var/tmp/phishing/{date}_phishing_domains.txt"
    phishing_domains_VT = get_phishing_domains(test_size*2, phishing_domains)

    phishing_test_text_file = f"/var/tmp/phishing/{date}_phishing_test.txt"
    phishing_test_JSON_dir = DLROOT + f"/{date}_phishing_test/"
    generate_JSON(phishing_domains_VT, phishing_test_text_file, phishing_test_JSON_dir, test_size)


    # Our model level 1 prediction
    # Assumes model has been built
    total = 0
    phish = 0
    res_obj = predict.load_model()
    model = res_obj['model']

    f = open(benign_test_text_file, "r")

    # Filter out TN using Tranco as a whitelist
    TN_domains_text_file = benign_test_text_file[:-4] + "_TN.txt"
    TN_domains = open(TN_domains_text_file, "a")
    r = get_top_tranco_domains(1000000)
    while True:
        # Get next line from file
        domain = f.readline().strip()

        # if line is empty, end of file is reached
        if not domain:
            break

        p = predict.predict_min(domain.strip(), model)
        if p['prob'][1] > 0.75:
            phish += 1
        # If domain is labeled negative (benign) and domain is present in whitelist, domain is TN
        else:
            if domain in r:
                TN_domains.write(domain + "\n")
        total += 1
        print("Total domains:", total, phish/total)
    f.close()
    TN_domains.close()
    print("Total domains:", total)
    print("Domains labeled phising:", phish)
    print("Accuracy:", (total - phish) / total)


    # Separate FP and TN JSON files into separate folders
    benign_test_JSON_dir_TN = benign_test_JSON_dir[:-1] + "_TN/"
    f = open(TN_domains_text_file, "r")
    while True:
        # Get next line from file
        domain = f.readline().strip()

        # if line is empty, end of file is reached
        if not domain:
            break

        if not os.path.isdir(benign_test_JSON_dir_TN):
            os.makedirs(benign_test_JSON_dir_TN)
        shutil.move(benign_test_JSON_dir + domain + ".json", benign_test_JSON_dir_TN + domain + ".json")
        shutil.move(benign_test_JSON_dir + domain + ".png", benign_test_JSON_dir_TN + domain + ".png")
    f.close()

    benign_test_JSON_dir_FP = benign_test_JSON_dir[:-1] + "_FP/"
    shutil.move(benign_test_JSON_dir, benign_test_JSON_dir_FP)

    if len([f for f in os.listdir(benign_test_JSON_dir_FP) if os.path.isfile(os.path.join(benign_test_JSON_dir_FP, f))]) < 2:
        print("Not enough FP (minimum 2 required), cannot continue, exiting.")
        exit(0)



    websites_dir = benign_test_JSON_dir_FP
    prefix = f"{date}_benign_test_FP"
    target = 0
    generate_pkl(websites_dir, prefix, target)

    websites_dir = phishing_test_JSON_dir
    prefix = f"{date}_phishing_test"
    target = 1
    generate_pkl(websites_dir, prefix, target)


    # Off-the-Hook level 2 prediction
    mode = 1
    benign = f"{date}_benign_test_FP_fvm.pkl"
    phishing = f"{date}_phishing_test_fvm.pkl"
    model = "model"
    fp, fn, tp, tn = build_predict(1, benign, phishing, model)



    # Add the TN that were filtered out after level 1

    with open(benign_test_text_file) as f:
       total = sum(1 for _ in f)

    with open(TN_domains_text_file) as f:
       TN = sum(1 for _ in f)


    # STACKED MODEL RESULTS
    print("Stacked model results")
    print("FP", "FN", "TP", "TN", "Accuracy", sep='\t')
    tn = tn + TN
    accuracy = (tp+tn)/(fp+fn+tn+tp)
    print(fp, fn, tp, tn, accuracy, sep='\t')



