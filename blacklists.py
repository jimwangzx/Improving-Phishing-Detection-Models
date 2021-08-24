import warnings
warnings.filterwarnings('ignore')

import sys, os, json
import subprocess
import traceback
#import psycopg2
#import postgresql
from datetime import datetime
import time
from datetime import timezone
import re

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import csv

import mysql.connector
from mysql.connector import Error

from collections import OrderedDict
from multiprocessing import Process
import random
import requests
from tranco import Tranco
import zipfile
import io
import random
from requests_html import HTMLSession

from pytz import timezone
tz = timezone('EST')

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')

def check_url(url):
   code = 999
   '''
   try:
       response = requests.head(url, verify=False, timeout=1)

       if int(str(response.status_code)[:1]) < 4: #if the url is up, the status code should not be 4xx or 5xxx
          code = response.status_code
   except Exception as e:
       print(str(e))
       pass

   return code
   '''
   try:
      session = HTMLSession(verify=False)
      r = session.get(arg, timeout=2)
      #if r.status_code == 200:
      if int(str(r.status_code)[:1]) < 4: #if the url is up, the status code should not be 4xx or 5xxx
         code = r.status_code
   except Exception as e:
      pass
   return code

def check_url_ext(dom):
   url = 'https://' + dom
   is_https = 0
   code = 999
   try:
      url = 'https://' + dom
      session = HTMLSession(verify=False)
      r = session.get(url,timeout=2)
      #if r.status_code == 200:
      if int(str(r.status_code)[:1]) < 4:
         is_https = 1
         code = r.status_code
   except Exception as e:
      print(str(e))
      pass

   if is_https == 0:
      try:
         url = 'http://' + dom
         session = HTMLSession(verify=False)
         r = session.get(url,timeout=2)
         is_https = 0
         code = r.status_code
      except Exception as e:
         #print(str(e))
         pass


   return {'is_https': is_https, 'code': code}



def get_tranco_domains(limit):
   t = Tranco(cache=True, cache_dir='.tranco')
   latest_list = t.list()
   top_list = latest_list.top(limit)
   dom_list = []
   for d in top_list:
      dom_list.append(d)
   return dom_list

def get_top_alexa_domains(limit):
   #Ref: https://hispar.cs.duke.edu/
   alexa_site_zip_url = 'http://s3.amazonaws.com/alexa-static/top-1m.csv.zip'

   download_path = 'data/downloads'
   download_file = download_path + '/' + 'alexa_urls.zip'
   cmd = "/usr/bin/wget --no-check-certificate " + alexa_site_zip_url + " -O " + download_file
   # print("Running command: " + cmd)
   output = subprocess.getoutput(cmd) #REMOVE
   time.sleep(1) #REMOVE

   top_urls = {}
   counter = 0

   zf = zipfile.ZipFile(download_file)
   for filename in zf.namelist():
      with zf.open(filename, 'r') as f:
         words = io.TextIOWrapper(f, newline=None)
         for line in words:
            line = line.strip()
            if not line: continue
            counter += 1
            if counter > limit: break
            line_list = line.split(',')
            top_urls[line_list[1]] = line_list[0]
   return top_urls


def get_hispar_urls(limit):
   #Ref: https://hispar.cs.duke.edu/
   hispar_site_zip_url = 'https://hispar.cs.duke.edu/latest.zip'

   download_path = '/var/tmp/downloads'
   download_file = download_path + '/' + 'hispar_urls.zip'
   cmd = "/usr/bin/wget --no-check-certificate " + hispar_site_zip_url + " -O " + download_file
   print("Running command: " + cmd)
   output = subprocess.getoutput(cmd) #REMOVE
   time.sleep(1) #REMOVE

   top_urls = {}
   counter = 0
   #Extract new domains from the zipped file
   #print("ZZZZ: " + download_file)
   zf = zipfile.ZipFile(download_file)
   for filename in zf.namelist():
      with zf.open(filename, 'r') as f:
         words = io.TextIOWrapper(f, newline=None)
         for line in words:
            line = line.strip()
            if not line: continue
            counter += 1
            if counter > limit: break
            re_url = re.search(':\/\/(.+?)\/', line)
            if re_url:
               d = re_url.group(1)
               re_url1 = re.search('(h\w+:\/\/.+)', line)
               if re_url1:
                  u = re_url1.group(1)

                  top_urls[u] = d
   return top_urls

def get_top_5k_cisco_domains():
   #Ref: https://stackoverflow.com/questions/59040974/python-wont-download-url-based-zip-file
   cisco_site_zip_url = 'http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip'

   download_path = '/var/tmp/downloads'
   download_file = download_path + '/' + 'cisco_top-5k.zip'
   cmd = "/usr/bin/wget " + cisco_site_zip_url + " -O " + download_file
   print("Running command: " + cmd)
   output = subprocess.getoutput(cmd) #REMOVE
   time.sleep(1) #REMOVE

   top_doms = {}
   counter = 0
   #Extract new domains from the zipped file
   with zipfile.ZipFile(download_file) as zf:
      with io.TextIOWrapper(zf.open("top-1m.csv"), encoding="utf-8") as f:
         for line in f.readlines():
            line = line.strip()
            if not line: continue
            counter += 1
            if counter > 5000: break 
            line_arr = line.split(',')
            if len(line_arr) == 2:
               dom_str = line_arr[1]
               #print(dom_str)
               top_doms[line_arr[1]] = line_arr[0]
   return top_doms

def get_top_cisco_domains(limit):
   #Ref: https://stackoverflow.com/questions/59040974/python-wont-download-url-based-zip-file
   cisco_site_zip_url = 'http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip'

   download_path = '/var/tmp/downloads'
   download_file = download_path + '/' + 'cisco_top-1m.zip'
   cmd = "/usr/bin/wget " + cisco_site_zip_url + " -O " + download_file
   print("Running command: " + cmd)
   output = subprocess.getoutput(cmd) #REMOVE
   time.sleep(1) #REMOVE

   top_doms = {}
   counter = 0
   #Extract new domains from the zipped file
   with zipfile.ZipFile(download_file) as zf:
      with io.TextIOWrapper(zf.open("top-1m.csv"), encoding="utf-8") as f:
         line_list = f.readlines()
         random.shuffle(line_list)
         for line in line_list:
            line = line.strip()
            if not line: continue
            counter += 1
            if counter > limit: break
            line_arr = line.split(',')
            if len(line_arr) == 2:
               dom_str = line_arr[1]
               #print(dom_str)
               top_doms[line_arr[1]] = line_arr[0]
   return top_doms

def get_openphish_domains():
   print("Finding malicious domains from openphish....")
   url = "https://openphish.com/feed.txt"

   url_dict  = {}

   top_cisco_domains = get_top_5k_cisco_domains()

   try:
         response = requests.get(url)
         if response.status_code != 200:
             print(url + " returned non-200 status code")
             print(response)
             return
         resp_text = response.text
         resp_text = resp_text.strip()

         if (resp_text):
             resp_text_list = resp_text.split("\n")
             #print(resp_text_list)

             for u in resp_text_list:
                  re_url = re.search('://(.+?)/', u)
                  if (re_url):
                     dom_str = re_url.group(1)
                     if (dom_str):
                         tmp_dom_str = dom_str
                         tmp_dom_str = tmp_dom_str.replace('www.','')

                         #res = [val for key, val in top_cisco_domains.items() if tmp_dom_str.endswith(key)]
                         #if not res:
                         url_dict[tmp_dom_str] = u
         return url_dict
         
   except Exception as e:
         print(str(e))
         traceback.print_exc(file=sys.stdout)

def get_phishtank_domains():
   print("Finding malicious domains from phishtank.....")
   key = '5f9311572449d07b87b8aff82548dcacc9e4b1dbe0d8b5829b34f4ec125dd8e9'
   url = 'http://data.phishtank.com/data/' + key + '/online-valid.json'

   url_dict  = {}

   top_cisco_domains = get_top_5k_cisco_domains()

   try:
         
         response = requests.get(url)
         if response.status_code != 200:
             print(url + " returned non-200 status code")
             print(response)
             return
         resp_json = response.json()

         with open('/var/tmp/phish', 'w+', encoding='utf-8') as f:
             json.dump(resp_json, f, ensure_ascii=False, indent=4)

         ##############
         resp_json = None
         with open('/var/tmp/phish') as json_file:
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

                   #res = [val for key, val in top_cisco_domains.items() if tmp_dom_str.endswith(key)] 
                   #if not res:
                      #print("#### " + tmp_dom_str)
                   url_dict[tmp_dom_str] = url_str
         return url_dict
                      

   except Exception as e:
         print(str(e))
         traceback.print_exc(file=sys.stdout)


