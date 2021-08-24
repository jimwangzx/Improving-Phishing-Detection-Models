#!/usr/local/bin/python3.8

import os, re, sys

import hashlib
import json
import os
import re
import requests
import logging
import sys
import time
import urllib

import traceback

from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

from selenium.webdriver.firefox.options import Options

from requests_html import HTMLSession

from signal import signal, SIGINT
from sys import exit

import datetime

def get_screenshot(url, dirname):
        #sitedata = {}
        try:
            # f = open("/var/tmp/phishing/failed_alexa_screenshots.txt", "a") Chelsea
            options = Options()
            options.headless = True
            driver = webdriver.Firefox(options=options)
            driver.set_page_load_timeout(60)

            domain = ""
            re_url = re.search('://(.+?)/', url)
            if re_url: domain = re_url.group(1)
            if domain: domain = domain.replace('www.','')


            driver.maximize_window()
            driver.get(url)

            #landurl = driver.current_url
            #sitedata['landurl'] = landurl
            #logger.info("FATAL error in fetching landing url with webdriver:", sys.exc_info()[0])
            #return {}, None
            screenshot = driver.save_screenshot(dirname + "/" + domain + ".png" )
            #title = driver.title
            #sitedata['title'] = title
            #source = driver.page_source
            #sitedata['source'] = source

            #elem = driver.find_element_by_tag_name('body')
            #text = elem.text
            #sitedata['text'] = text
        except Exception as e:
            traceback.print_exc(limit=2, file=sys.stdout)
            print(str(e))
            # f.write(url + "\t" + str(e))  Chelsea
            # f.close()
            return {}, None
        finally:
            try:
                # f.close()   Chelsea
                driver.quit()
            except Exception as e:
                pass
        #return sitedata


# url = "https://www.nytimes.com/"
# url = "http://yu78uiiie9.temp.swtest.ru/logcons/"
# dirname = "/var/tmp/phishing/"

#In addition to taking a screenshot, the below method call will also return content of the page and title
#some pages may timeout. In such cases, you may have to paly with increasing timeout values or other options
# r = get_screenshot(url, dirname)
#print(r)


# url = "https://google.com"
# dirname = "/var/tmp/phishing/alexa_screenshots/"
# r = get_screenshot(url, dirname)
