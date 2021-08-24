#!/usr/bin/python3.7

import sys, os, json
import subprocess
import traceback
#import psycopg2
#import postgresql
from datetime import datetime
import time
from datetime import timezone
import re

import csv
from collections import OrderedDict
from multiprocessing import Process
import random
import requests

from get_screenshot import get_screenshot

def get_phishtank_domain():
   print("Finding malicious domains from phishtank.....")
   key = '5f9311572449d07b87b8aff82548dcacc9e4b1dbe0d8b5829b34f4ec125dd8e9'
   url = 'http://data.phishtank.com/data/' + key + '/online-valid.json'

   url_dict  = {}

   try:
         response = requests.get(url)
         if response.status_code != 200:
             print(url + " returned non-200 status code")
             print(response)
             return
         resp_json = response.json()

         with open('/var/tmp/phishtank', 'w+', encoding='utf-8') as f:
             json.dump(resp_json, f, ensure_ascii=False, indent=4)

         ##############
         resp_json = None
         with open('/var/tmp/phishtank') as json_file:
             resp_json = json.load(json_file)

         for j_obj in resp_json:
            url_str = j_obj['url']
            re_url = re.search('://(.+?)/', url_str)
            #print(re_url + ' -- ' + url_str)
            if (re_url):
               dom_str = re_url.group(1)
               if (dom_str):
                   tmp_dom_str = dom_str
                   tmp_dom_str = tmp_dom_str.replace('www.','')

                   url_dict[tmp_dom_str] = url_str
         return url_dict
   except Exception as e:
      print(str(e))


# r = get_phishtank_domain()
# f = open("/var/tmp/chelsea/phishing_domains_Aug10.txt", "w")
# count = 0
# for domain, v in r.items():
#     # if count > 6000:
#     #     break
#     f.write(domain + '\n')
#     count += 1
# f.close()




# # Get 3000 phishing domains out of the 5000+ ones downloaded
# f = open("/var/tmp/chelsea/phishing_domains_jun3.txt", "r")
# phishing = open("/var/tmp/chelsea/phishing_domains_jun28.txt", "w")
# counter = 1
# while True:
#     # Get next line from file
#     domain = f.readline()
#
#     # if line is empty
#     # end of file is reached
#     if not domain:
#         break
#     phishing.write(domain)
#     counter += 1
#     if counter > 100:
#         break
# f.close()