#!/usr/bin/python3.7

from base64 import urlsafe_b64encode


#Ref: https://pypi.org/project/virustotal-python/
from virustotal_python import Virustotal



vt_api_key = "b4837f3abbd2ff89b9c28c6d463ff99c7a510e596c7b8936503b9a10a6583ac4"

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
   '''
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
   return {'mal_status': result, 'result': analysis_data}
    '''

   # Chelsea
   result = {}
   analysis_data = None
   try:
       # Send URL to VirusTotal for analysis
       resp = vtotal.request("urls", data={"url": url}, method="POST")
       url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
       analysis_resp = vtotal.request(f"urls/{url_id}")
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



# Pretty print
def pprint(dictionary, indent=0):
   for key, value in dictionary.items():
      if isinstance(value, dict):
         print('\t' * indent + str(key))
         pprint(value, indent+1)
      else:
         print('\t' * indent + str(key) + ': ' + str(value))

# Pretty write to file
def pwrite(file, dictionary, indent=0):
   for key, value in dictionary.items():
      if isinstance(value, dict):
         file.write('\t' * indent + str(key) + '\n')
         pwrite(file, value, indent+1)
      else:
         file.write('\t' * indent + str(key) + ': ' + str(value) + '\n')

# r = analyze_url_vt('fuckmywifeblog.com')
# print(r['result']['attributes']['reputation'])



# f = open("/var/tmp/chelsea/phishing_domains_Jul25_non-repeats.txt", "r")
# # vt_info = open("/var/tmp/chelsea/vt_phishing_domains.txt", "a")
# domains = open("/var/tmp/chelsea/phishing_domains_Jul25_non-repeats_actual.txt", "a")
# count = 1
# while True:
#     # Get next line from file
#     url = f.readline().strip()
#     # if line is empty, end of file is reached
#     if not url:
#         break
#     r = analyze_url_vt(url)
#     if 'mal_status' in r and 'phishing' in r['mal_status'] and r['mal_status']['phishing'] >= 5:
#         # vt_info.write(str(r) + '\n\n')
#         domains.write(url + '\n')
#         print(count, url)
#         count += 1
# f.close()
# # vt_info.close()
# domains.close()


# f = open("/var/tmp/chelsea/alexa_domains_3000.txt", "r")
# output = open("/var/tmp/chelsea/vt_alexa_domains.txt", "a")
# count = 1
# while True:
#     if count > 2058:
#         break
#     # Get next line from file
#     url = f.readline().strip()
#     print(url)
#     # if line is empty, end of file is reached
#     if not url:
#         break
#     r = analyze_url_vt(url)
#     output.write(str(r) + '\n\n')
#     count += 1
# f.close()
# output.close()

# f = open("/var/tmp/chelsea/alexa_domains.txt", "r")
# output = open("/var/tmp/chelsea/vt_alexa_domains_formatted.txt", "a")
# while True:
#     # Get next line from file
#     url = f.readline().strip()
#
#     # if line is empty
#     # end of file is reached
#     if not url:
#         break
#     r = analyze_url_vt(url)
#     pwrite(output, r)
# f.close()

