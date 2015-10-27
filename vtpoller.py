__author__ = 'hgascon'

import os
import urllib
import urllib2
import json
import time
import apikey
from datetime import date, timedelta
from shutil import copyfile
from pandas import DataFrame
import pandas as pd

"""
Query VT for samples submitted today and in previous days
with less than 3 detections and save their detections.

DATA FILE:
query date, submission date, hash, detections
"""

DATAFILE = "malware_metadata.csv"
COLUMNS = ["query_time", "scan_time", "hash", "detections"]


#TODO add android tag to query
def query(parameters):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    jsoni = response.read()
    jsonr = json.loads(jsoni)
    return jsonr


def add_results(jsonr, df):
    query_time = int(time.time())
    results = []
    for r in jsonr:
        hash = r['sha256']
        detections = r['positives']
        scan_time = int(time.mktime(time.strptime(r['scan_date'],
                                                  "%Y-%m-%d %H:%M:%S")))
        new_row = [query_time, scan_time, hash, detections]
        results.append(new_row)

    results = DataFrame(results, columns=COLUMNS)
    df.append(results)
    return df


datafile_path = os.path.abspath(DATAFILE)

# create data file if it doesn't exist
if not os.path.exists(datafile_path):
    df = DataFrame(columns=COLUMNS)
    df.to_csv(datafile_path)

# backup data file
copyfile(datafile_path, "{}.bak".format(datafile_path))

# load dataframe and find hashes with max 3 detections
df = pd.read_csv(datafile_path)
undetected_hashes = ','.join(df.hash[df.detections <= 3].values)

# add results from existing samples
parameters = {"resource": undetected_hashes,
              "apikey": apikey.APIKEY}
jsonr = query(parameters)
df = add_results(jsonr, df)

# add results from new samples
scan_date = (date.today() - timedelta(1)).strftime('%Y-%m-%d')
parameters = {"resource": "",
              "apikey": apikey.APIKEY,
              "scan_date": scan_date}
jsonr = query(parameters)
df = add_results(jsonr, df)

# update results
df.to_csv(df, index=False)
