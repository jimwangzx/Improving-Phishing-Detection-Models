import os
import sys
import pandas as pd

import website_fetcher

from build_feat_vec import brands, current_milli_time, feature_vector
from extract_URL import Extractor
from website import Website


# Get JSON files for the domains predicted as phishing (both true positives and false positives) by the model


# Generate JSON files and screenshots
f = open("/var/tmp/chelsea/phishing_domains_Jul25_non-repeats_actual.txt", "r")
while True:
    # Get next line from file
    url = f.readline().strip()
    # if line is empty, end of file is reached
    if not url:
        break
    print(url)
    fetcher = website_fetcher.WebsiteFetcher(confirm=True)
    fetcher.fetch_and_save_data(url)
f.close()


