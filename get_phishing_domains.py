#!/usr/bin/python3.7

import json
import pathlib
import re
import sys

import requests

from check_domain_with_vt import analyze_url_vt


def get_phishtank_domain():
    print("Finding malicious domains from phishtank.....")
    key = '5f9311572449d07b87b8aff82548dcacc9e4b1dbe0d8b5829b34f4ec125dd8e9'
    url = 'http://data.phishtank.com/data/' + key + '/online-valid.json'

    url_dict = {}

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
            # print(re_url + ' -- ' + url_str)
            if (re_url):
                dom_str = re_url.group(1)
                if (dom_str):
                    tmp_dom_str = dom_str
                    tmp_dom_str = tmp_dom_str.replace('www.', '')

                    url_dict[tmp_dom_str] = url_str
        return url_dict
    except Exception as e:
        print(str(e))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Please include the number of phishing domains you would like to extract.")
        exit(0)
    else:
        phishing_size = int(sys.argv[1])

        # Write phishtank domains to file.
        p = get_phishtank_domain()
        pathlib.Path("/var/tmp/phishing/").mkdir(parents=True, exist_ok=True)
        f = open("/var/tmp/phishing/phishing_domains.txt", "w")

        count = 0
        for domain, v in p.items():
            if count >= phishing_size:
                break

            # Check with VT that the domains are categorized as phishing by at least 5 engines
            # and write those domains to another file.
            r = analyze_url_vt(domain)
            if 'mal_status' in r and 'phishing' in r['mal_status'] and r['mal_status']['phishing'] >= 5:
                f.write(domain + '\n')
                count += 1
                print(count, domain)
        f.close()
