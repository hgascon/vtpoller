__author__ = 'hgascon'

import os
import sys
import urllib
import urllib2
import json
import time
import requests
from apikey import API_KEY
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
FILE_TYPE = 'pe'
FILE_MAX_SIZE = '200kb'
COLUMNS = ["query_time", "scan_date", "hash", "detections"]


def run():
    datafile_path = os.path.abspath(DATAFILE)

    # create data file if it doesn't exist
    if not os.path.exists(datafile_path):
        print "[*] Creating data frame..."
        df = DataFrame(columns=COLUMNS)
        df.to_csv(datafile_path)

    # backup data file
    print "[*] Backing data file up..."
    copyfile(datafile_path, "{}.bak".format(datafile_path))

    # load dataframe and find hashes with max 3 detections
    df = pd.read_csv(datafile_path)
    undetected_hashes = ', '.join(df.hash[df.detections <= 3].values)

    # add results from existing samples
    parameters = {"apikey": API_KEY,
                  "resource": undetected_hashes}
    if undetected_hashes:
        print "[*] Retrieving reports for undetected samples..."
        jsonr = retrieve_reports(parameters)
        df = add_results(jsonr, df)

    # retrieve hashes from new samples under criteria
    first_seen_plus = (date.today() - timedelta(1)).strftime('%Y-%m-%d')
    first_seen_minus = date.today().strftime('%Y-%m-%d')
    query = "fs:{}+ fs:{}- tag:{} size:{}- positives:0".format(
            first_seen_plus, first_seen_minus, FILE_TYPE, FILE_MAX_SIZE)
    parameters = {"apikey": API_KEY,
                  "query": query}
    print "[*] Retrieving new samples..."
    response_new_hashes = retrieve_hashes(parameters)

    # query for reports of new hashes
    try:
        new_hashes = ', '.join(response_new_hashes['hashes'])
        parameters = {"apikey": API_KEY,
                      "resource": new_hashes}
    except:
        "No new new hashes found!"
        new_hashes = ''

    if new_hashes:
        jsonr = retrieve_reports(parameters)
        df = add_results(jsonr, df)

    # update results
    print "[*] Saving data file..."
    df.to_csv(datafile_path, index=False)


def retrieve_hashes(parameters):
    url = 'https://www.virustotal.com/intelligence/search/programmatic'
    response = requests.get(url, params=parameters)
    return response.json()


def retrieve_reports(parameters):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
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
    df = df.append(results)
    return df

if __name__ == "__main__":
    run()
