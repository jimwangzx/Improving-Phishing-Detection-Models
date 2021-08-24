import os
import sys
import pandas as pd

from build_feat_vec import brands, current_milli_time, feature_vector
from extract_URL import Extractor
from website import Website


# # Generate pkl file from the JSON files in the websites folder
#
# websites_dir = "phishing_train"
# prefix = "phishing_train"
# target = 1
#
# sys.setrecursionlimit(10000)
# websitedir = os.path.abspath(websites_dir)
# extractor = Extractor()
# label = int(target)
# feat_vec_temp = {}
# print(brands)
#
# i = 0
#
# pd.set_option('display.max_rows', 1000)
#
# for f in sorted(os.listdir(websitedir)):
#     start_time = current_milli_time()
#
#     if f.find(".json") > 0:
#         print(websitedir + "/" + f)
#         ws = Website(jspath=websitedir + "/" + f)
#         intermediate = current_milli_time()
#         feat_vect_site = feature_vector(extractor, ws)
#         end_time = current_milli_time()
#         # time_stats.write(str(intermediate-start_time) + "," + str(end_time-intermediate) + "\n")
#         feat_vect_site["start_url"] = f
#         feat_vect_site["label"] = label
#         feat_vec_temp[i] = feat_vect_site
#         i += 1
#         print(ws.starturl)
#
#     elif f.find(".png") < 0:
#         ws = Website(websitedir + "/" + f + "/sitedata.json")
#         intermediate = current_milli_time()
#         feat_vect_site = feature_vector(extractor, ws)
#         end_time = current_milli_time()
#         # time_stats.write(str(intermediate-start_time) + "," + str(end_time-intermediate) + "\n")
#         feat_vect_site["start_url"] = ws.starturl
#         feat_vect_site["label"] = label
#         feat_vec_temp[i] = feat_vect_site
#         i += 1
#         print(ws.starturl)
#
# # time_stats.close()
# featvecmat = pd.DataFrame(feat_vec_temp)
# print(featvecmat.shape)
# featvecmat.transpose().to_pickle(prefix + "_fvm.pkl")



if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Please include the path to the text file containing training domains.")
        exit(0)
    else:
        websites_dir = sys.argv[1]
        prefix = sys.argv[2]
        target = int(sys.argv[3])

        # Generate pkl file from the JSON files in the websites folder

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
                # time_stats.write(str(intermediate-start_time) + "," + str(end_time-intermediate) + "\n")
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
                # time_stats.write(str(intermediate-start_time) + "," + str(end_time-intermediate) + "\n")
                feat_vect_site["start_url"] = ws.starturl
                feat_vect_site["label"] = label
                feat_vec_temp[i] = feat_vect_site
                i += 1
                print(ws.starturl)

        # time_stats.close()
        featvecmat = pd.DataFrame(feat_vec_temp)
        print(featvecmat.shape)
        featvecmat.transpose().to_pickle(prefix + "_fvm.pkl")




