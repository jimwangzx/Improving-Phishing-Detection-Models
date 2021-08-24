#!/usr/bin/python3.7
import warnings
warnings.filterwarnings('ignore')


import sys, os, json
import subprocess
import traceback

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from base64 import urlsafe_b64encode

#Ref: https://pypi.org/project/virustotal-python/
from virustotal_python import Virustotal


from pytz import timezone
tz = timezone('EST')

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/lib')
#from heuristics import extract_heuristics

vt_api_key = '3d4ed5043e0130894e142a6663d091d9703227ccf7a90d23d93b661d841aa105'

def submit_url_to_vt(url):
   command_str = "/usr/bin/curl -s --request POST --url https://www.virustotal.com/api/v3/urls --header 'x-apikey: " + vt_api_key + "' --form url='" + url + "'"
   output = subprocess.getoutput(command_str)
   #print(output)

   id_str = ""
   try:
      output_obj = json.loads(output)
      if "data" in output_obj and "id" in output_obj["data"]:
         id_str = output_obj["data"]["id"]
   except Exception as e:
        pass

   return id_str

def analyze_url_from_vt(id_str):
   command_str = "/usr/bin/curl -s --request GET --url https://www.virustotal.com/api/v3/analyses/" + id_str + " --header 'x-apikey: " + vt_api_key + "'"
   output = subprocess.getoutput(command_str)

   return output

def analyze_url_vt(url):
   # v3 example
   vtotal = Virustotal(API_KEY=vt_api_key, API_VERSION="v3")
   #vtotal = Virustotal(API_KEY=vt_api_key, API_VERSION="v2")

   '''
   # v2 example
   try:
    # Send a URL to VirusTotal for analysis
    resp = vtotal.request("url/scan", params={"url": url}, method="POST")
    url_resp = resp.json()
    # Obtain scan_id
    scan_id = url_resp["scan_id"]
    # Request report for URL analysis
    analysis_resp = vtotal.request("url/report", params={"resource": scan_id})
    print(analysis_resp.response_code)
    pprint(analysis_resp.json())
   except Error as err:
    print(f"An error occurred: {err}\nCatching and continuing with program.")
   '''
   # v3 example
   result = {}
   try:
      # Send URL to VirusTotal for analysis
      resp = vtotal.request("urls", data={"url": url}, method="POST")
      # URL safe encode URL in base64 format
      # https://developers.virustotal.com/v3.0/reference#url
      url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
      # Obtain the analysis results for the URL using the url_id
      analysis_resp = vtotal.request(f"urls/{url_id}")
      #print(json.dumps(analysis_resp.data))
      #pprint(analysis_resp.object_type)
      analysis_data = analysis_resp.data
      if 'attributes' in analysis_data and 'last_analysis_stats' in analysis_data['attributes']:
      #    lbl_list = analysis_data['attributes']['last_analysis_stats']
      #    for lbl in lbl_list:
      #       if lbl_list[lbl] > 0 and lbl not in ['harmless', 'undetected', 'timeout']: result.append(lbl)
          engine_list = analysis_data['attributes']['last_analysis_results']
          #print(engine_list.values())
          #for engine in list(engine_list):
          #   print(engine)
          engine_list_vals = list(engine_list.values())
          #print(engine_list_vals[3])
          for item in engine_list_vals:
                 #print(item)
                 item_res = item['result']
                 item_cat = item['category']
                 if item_cat not in ['harmless', 'undetected', 'timeout']: 
                     if item_res not in result:
                         result[item_res] = 1
                     else:
                         result[item_res] += 1

   except Exception as err:
      #print(f"An error occurred: {err}\nCatching and continuing with program.")
      #traceback.print_exc(file=sys.stdout)
      pass
   #return list(result.keys())
   return result


#-----------------------------

def analyze_domain_vt(domain):
   vtotal = Virustotal(API_KEY=vt_api_key, API_VERSION="v3")

   result = {}
   analysis_data = {}
   try:
      # Send URL to VirusTotal for analysis
      analysis_resp = vtotal.request(f"domains/{domain}")
      analysis_data = analysis_resp.data

      if 'attributes' in analysis_data and 'last_analysis_stats' in analysis_data['attributes']:
          engine_list = analysis_data['attributes']['last_analysis_results']
          engine_list_vals = list(engine_list.values())
          for item in engine_list_vals:
                 item_res = item['result']
                 item_cat = item['category']
                 if item_cat not in ['harmless', 'undetected', 'timeout']:
                     if item_res not in result:
                         result[item_res] = 1
                     else:
                         result[item_res] += 1


   except Exception as err:
      pass

   return {'mal_status': result, 'result': analysis_data}

def comments_domain_vt(domain):
   vtotal = Virustotal(API_KEY=vt_api_key, API_VERSION="v3")

   result = []
   analysis_data = {}
   try:
      # Send URL to VirusTotal for analysis
      analysis_resp = vtotal.request(f"domains/{domain}/comments")
      analysis_data = analysis_resp.data

      for item in analysis_data:
          attr = item['attributes']
          if not attr: continue
          text = attr['text']
          result.append(text)

   except Exception as err:
      pass

   return result

def hist_whois_domain_vt(domain):
   vtotal = Virustotal(API_KEY=vt_api_key, API_VERSION="v3")

   result = []
   analysis_data = {}
   try:
      # Send URL to VirusTotal for analysis
      analysis_resp = vtotal.request(f"domains/{domain}/historical_whois")
      analysis_data = analysis_resp.data

      for item in analysis_data:
          attr = item['attributes']
          if not attr: continue
          struct = attr['whois_map']
          result.append(struct)

   except Exception as err:
      pass

   return result

def resolutions_whois_domain_vt(domain):
   vtotal = Virustotal(API_KEY=vt_api_key, API_VERSION="v3")

   result = []
   analysis_data = {}
   try:
      # Send URL to VirusTotal for analysis
      analysis_resp = vtotal.request(f"domains/{domain}/resolutions")
      analysis_data = analysis_resp.data

      for item in analysis_data:
          attr = item['attributes']
          if not attr: continue
          r = attr
          result.append(r)

   except Exception as err:
      pass

   return result


#site = 'http://rm-uk-delivery-fee.com'
#site = 'http://lankapage.com'
#r = analyze_url_vt(site)
#print(r)
