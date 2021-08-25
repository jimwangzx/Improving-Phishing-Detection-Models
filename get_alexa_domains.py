#!/usr/bin/python3.7
import pathlib
import subprocess
import sys
import time
import zipfile
import io



def get_top_alexa_domains(limit):
   #Ref: https://hispar.cs.duke.edu/
   alexa_site_zip_url = 'http://s3.amazonaws.com/alexa-static/top-1m.csv.zip'

   download_path = 'data/downloads'
   download_file = download_path + '/' + 'alexa_urls.zip'
   cmd = "/usr/bin/wget --no-check-certificate " + alexa_site_zip_url + " -O " + download_file
   print("Running command: " + cmd)
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



# Write alexa domains to file.
if __name__ == '__main__':
   if len(sys.argv) < 2:
        print("Please include the number of phishing domains you would like to extract.")
        exit(0)
   else:
      benign_size = int(sys.argv[1])
      r = get_top_alexa_domains(3000)
      count = 0
      pathlib.Path("/var/tmp/phishing/").mkdir(parents=True, exist_ok=True)
      f = open("/var/tmp/phishing/benign_domains.txt", "a")
      for domain, v in r.items():
         if count >= benign_size:
            break
         f.write(domain + "\n")
         count += 1
      f.close()


