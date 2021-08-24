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
from tranco import Tranco



def get_top_tranco_domains(limit):
   t = Tranco(cache=True, cache_dir='.tranco')
   latest_list = t.list()
   top_list = latest_list.top(limit)
   dom_list = []
   for d in top_list:
      dom_list.append(d)
   return dom_list


