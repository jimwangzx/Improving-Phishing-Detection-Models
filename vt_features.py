#!/usr/local/bin/python3.8

import os, sys, re
import tldextract

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
import scanner1
import time
from statistics import mean

from dateutil import parser

import socket
import pyasn

def get_ip_from_domain(domain_name):
   ip = ""
   try:
      ip = socket.gethostbyname(domain_name)
   except Exception as e:
      pass
   return ip


def get_asn_from_ip(ip):
   asn = ""
   try:
      asndb = pyasn.pyasn('/var/tmp/phishing/data/ipasn.dat')
      r = asndb.lookup(ip)
      if len(r) == 2: asn = r[0]
   except Exception as e:
      pass
   return asn

def get_tld_plus_one(site):
    ext = tldextract.extract(site)
    return ext.registered_domain

def populate_whois(whois_str):
   whois_struct = {}

   whois_str_items = whois_str.split('\n')
   for item in whois_str_items:
      #print(item)
      item_list = item.split(':')
      if len(item_list) < 2: continue
      key = item_list[0].strip()
      key = key.lower()
      val = ':'.join(item_list[1:]).strip()

      if key == 'nserver': key = 'name server'
      #if key == 'name server': key = 'name server'
      if  "name server" in key:
         re_ns = re.search('(name server).+', key)
         if re_ns: key = re_ns.group(1)

      if key == "created": key = "creation date"
      if key == "create date": key = "creation date"
      if key == "registration time": key = "creation date"

      if key == 'paid-till': key = "expiry date"
      #if key == 'expiry date': key = "registrar registration expiration date"
      if key == "registrar registration expiration date": key = "expiry date"
      if key == 'registry expiry date': key = "expiry date"
      if key == 'expiration time': key = "expiry date"

      if key == 'registrant': key = "registrant name"
      if key == 'registrant contact email': key = "registrant email"

      # Chelsea added
      if key == 'domain registrar url': key = "registrar url"

      if key not in whois_struct: whois_struct[key] = []
      whois_struct[key].append(val)


   #print(whois_struct)
 
   #print(whois_struct)
   return whois_struct

#Average of the number of hours between IP turnovers for last 3 IP turnovers (max)
def avg_ip_turnover_period(resolutions_whois):
    prev_dt = ""
    prev_ip = ""

    data = []
    #print('---------------------------------')
    #print(resolutions_whois)
    for item in resolutions_whois:
        dt = item['date']
        ip = item['ip_address']

        if prev_dt == "": 
           prev_dt = dt
           prev_ip = ip
           continue

        if prev_ip == ip or prev_dt == dt: continue

        #print(str(dt) + " -- " + str(prev_dt) + " --- " + ip + " -- " + prev_ip)
     
        dt_diff = prev_dt - dt
        data.append(dt_diff)
        if len(data) == 3: break
        
        prev_dt = dt
        prev_ip = ip

    avg = 0
    if len(data) == 0: return -1
    if len(data) > 0: avg = int(mean(data))
    if avg > 0:
       avg = int(avg/(60*60)) #convert to number of hours

    return avg

'''
def has_mal_keywords_in_comments(comments):
    keywords = ["adult content", "bot networks", "malware", "command and control", "compromised", "suspicious", "phishing", "fraud", "scam", "illegal", "unethical", "weapons", "malicious", "shareware", "freeware", "spam", "spyware", "infection", "callhome"] 

    if len(comments) == 0: return -1

    for item in comments:
       for kw in keywords:
           if kw.lower() in item.lower():
                return 1
    return 0
'''

def has_phish_keywords_in_categores(categories):
    #keywords = ["adult content", "bot networks", "malware", "command and control", "compromised", "suspicious", "phishing", "fraud", "scam", "illegal", "unethical", "weapons", "malicious", "shareware", "freeware", "spam", "spyware", "infection", "callhome"]
    keywords = ['phish']

    if len(categories) == 0: return -1

    for item in categories.values():
       for kw in keywords:
           if kw.lower() in item.lower():
                return 1
    return 0

def extract_site_rank(data):
    if 'Alexa' in data and 'rank' in data['Alexa']:
        return data['Alexa']['rank']
    else:
        return -1

def extract_whois(data):
   result = {}
   #if len(data) == 0: return result

   #general info
   result["whois_ns"] = data["name server"] if "name server" in data else []

   epoch_time_now = int(time.time())
   _created_date = data["creation date"] if "creation date" in data else []
   #Ref: https://stackoverflow.com/questions/466345/converting-string-into-datetime
   created_date_epoch = -1
   created_date_obj = None
   if len(_created_date) > 0:
      try:
         created_date_obj = parser.parse(_created_date[0])
         if created_date_obj:
            created_date_epoch = int(created_date_obj.timestamp())
      except Exception as e:
         pass

   updated_date_epoch = -1
   updated_date_obj = None
   _updated_date = data["updated date"] if "updated date" in data else []
   if len(_updated_date) > 0:
      try:
         updated_date_obj = parser.parse(_updated_date[0])
         if updated_date_obj:
            updated_date_epoch = int(updated_date_obj.timestamp())
      except Exception as e:
          pass

   exp_date_epoch = -1
   exp_date_obj = None
   _exp_date = data["expiry date"] if "expiry date" in data else []
   if len(_exp_date) > 0:
      try:
         exp_date_obj = parser.parse(_exp_date[0])
         if exp_date_obj:
            exp_date_epoch = int(exp_date_obj.timestamp())
      except Exception as e:
          pass

   #registrant info
   result["whois_registrant_country"] = data["registrant country"] if "registrant country" in data else ""
   result["whois_registrant_city"] = data["registrant city"] if "registrant city" in data else ""
   result["whois_registrant_email"] = data["registrant email"] if "registrant cmail" in data else ""
   result["whois_registrant_name"] = data["registrant name"] if "registrant name" in data else ""
   result["whois_registrant_org"] = data["registrant organization"] if "registrant organization" in data else ""
   result["whois_registrant_phone"] = data["registrant phone"] if "registrant phone" in data else ""

   #registrar info
   result["whois_registrar"] = data["registrar"] if "registrar" in data else ""
   #result["_registry_exp_date"] = data["Registry Expiry Date"] if "Registry Expiry Date" in data else []

   #Tech info
   result["whois_tect_country"] = data["tech country"] if "tech country" in data else ""
   result["whois_tech_city"] = data["tech city"] if "tech city" in data else ""
   result["whois_tech_email"] = data["tech email"] if "tech email" in data else ""
   result["whois_tech_org"] = data["tech organization"] if "tech organization" in data else ""

   result["whois_time_since_dom_reg"] = int(round((epoch_time_now - created_date_epoch)/(60*60*24),0)) if created_date_epoch != -1 else -1
   result['whois_time_to_dom_exp'] = int(round((int(exp_date_epoch) - int(epoch_time_now))/(60*60*24),0)) if exp_date_epoch != -1 else -1
   result['whois_domain_life_span'] = int(round((exp_date_epoch - created_date_epoch)/(60*60*24),0)) if (created_date_epoch != -1 and exp_date_epoch != -1) else -1
   result['whois_week_day_of_reg'] = created_date_obj.weekday() if created_date_obj is not None else -1
   result['whois_hour_of_reg'] = created_date_obj.hour if created_date_obj is not None else -1 
   

   return result

def extract_reputation(result):
    return result

def extract_cert(data):
    result = {}
    if not data: return result

    cn = ""
    
    not_after_epoch = -1
    not_after_obj = None
    if 'validity' in data and 'not_after' in data['validity']:
        not_after = data['validity']['not_after']
        not_after_obj = parser.parse(not_after)
        not_after_epoch = int(not_after_obj.timestamp())

    not_before_epoch = -1
    not_before_obj = None
    if 'validity' in data and 'not_before' in data['validity']:
        not_before = data['validity']['not_before']
        not_before_obj = parser.parse(not_before)
        not_before_epoch = int(not_before_obj.timestamp())

    if 'issuer' in data and 'O' in data['issuer']:
        issuer_org = data['issuer']['O']

    result['cert_issuer_org'] = issuer_org
    result['cert_validity_period'] = int(round((not_after_epoch - not_before_epoch)/(60*60*24),0)) if (not_before_epoch != -1 and not_after_epoch != -1) else -1

    return result

#Type: 
#creation date empty OR resolution data missing = -1
#drop catch (registered within 5 days) = 2
#retread (registered after 5 days = 3
#otherwise, not a re-registration = 1
def find_registration_type(creation_date, resolutions_whois):
     #epoch_time_now = int(time.time())

     created_date_epoch = -1
     created_date_obj = None
     if len(creation_date) > 0:
        try:
           created_date_obj = parser.parse(creation_date[0])
           if created_date_obj:
              created_date_epoch = int(created_date_obj.timestamp())
        except Exception as e:
           pass

     if created_date_epoch == -1 or len(resolutions_whois) == 0: return -1

     for item in resolutions_whois:
        ts = item['date']
        if ts < created_date_epoch:
           interval = ts - created_date_epoch
           interval_days = interval/(60*60*24)
           if int(interval_days) >= 5: #nterval > 5 days
              return 3 #retread
           else:
              return 2 #drop-catch
     #domain_age = int(epoch_time_now-created_date_epoch)/(60*60*24)
     #if domain_age <= 14: #if domain registered within 14 days
     #   return 1 #new registration
     #else:
     #   return 4 #existing registration
     return 1 #not a re-registration
   
def process_heuristics(domain_name):
    result = {}
    heuristics = {}

    domain_name = get_tld_plus_one(domain_name)
    result['domain_name'] = domain_name

    if domain_name:
          ip = get_ip_from_domain(domain_name)
          if ip:
             asn = get_asn_from_ip(ip)
             heuristics["domain_asn"] = asn

    resolutions_whois = scanner1.resolutions_whois_domain_vt(domain_name)
    result['resolutions_whois'] = resolutions_whois

    resolutions_whois = result['resolutions_whois']
    avg_ip_turnover = avg_ip_turnover_period(resolutions_whois)

    '''
    comments = result['comments']
    mal_keywords_in_comments = has_mal_keywords_in_comments(comments)
    '''

    data = scanner1.analyze_domain_vt(domain_name)
    if 'result' in data and 'attributes' not in data['result']: return {}
    attributes = data['result']['attributes']

    whois = {}

    if 'whois' in attributes:
      whois = populate_whois(attributes['whois'])

    result['whois'] = whois
    result['popularity_ranks'] = attributes['popularity_ranks']
    result['reputation'] = attributes['reputation']
    result['last_analysis_stats'] = attributes['last_analysis_stats']
    result['categories'] = attributes['categories']
    result['last_https_certificate'] = attributes['last_https_certificate'] if 'last_https_certificate' in attributes else {}
    result['resolutions_whois_raw'] = resolutions_whois

    #result['last_analysis_results'] = attributes['last_analysis_results']


    creation_date = whois["creation date"] if "creation date" in whois else []
    registration_type = find_registration_type(creation_date , result['resolutions_whois_raw'])
    heuristics["registration_type"] = registration_type

    heuristics['avg_ip_turnover'] = avg_ip_turnover
    #heuristics['mal_keywords_in_comments'] = mal_keywords_in_comments

    popularity_ranks = result['popularity_ranks'] 
    heuristics['popularity_rank'] = extract_site_rank(popularity_ranks)

    reputation = result['reputation']
    heuristics['reputation'] = extract_reputation(reputation)

    categories = result['categories']
    heuristics['phish_keywords_in_categories'] = has_phish_keywords_in_categores(categories)

    whois = result['whois']
    heuristics.update(extract_whois(whois))

    ip_dict = {}
    asn_dict = {}
    if "name server" in whois:
       ns_list = whois["name server"]
       for ns in ns_list:
          ip = get_ip_from_domain(ns)
          if ip: 
             ip_dict[ip] = 1
             asn = get_asn_from_ip(ip)
             if asn: asn_dict[asn] = 1 

    heuristics["whois_ns_ip_list"] = list(ip_dict.keys())
    heuristics["whois_ns_asn_list"] = list(asn_dict.keys())

    cert = result['last_https_certificate']
    heuristics.update(extract_cert(cert))

    #print("---------------------")
    #print(heuristics)
    return {'raw': result, 'heuristics': heuristics}


