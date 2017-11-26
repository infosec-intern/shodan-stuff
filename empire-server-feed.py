'''
Query Shodan for open Empire HTTP listeners based on the following article:
https://www.tenable.com/blog/identifying-empire-http-listeners
'''
import csv
import ipaddress
import json
import logging

import shodan


logging.basicConfig(level=logging.DEBUG)


def read_config(path="config.json"):
    ''' Read API info out of config file '''
    with open(path, "r") as ifile:
        return json.load(ifile)

def search(api):
    '''
    Perform our Shodan search with the search terms set out in the article

    :api: Shodan search API
    '''
    query_terms = 'title:"404 Not Found" + "Content-Length: 233"  + "Cache-Control: no-cache, no-store, must-revalidate" -"post-check=" -"pre-check=" -"private" + "Pragma: no-cache" + "Expires: 0" + "Server:" -"X-" -"Set-Cookie:" -"Connection:" -"Etag" -"Last-Modified" -"Accept-Ranges:" -"Access-Control"'


if __name__ == "__main__":
    CONFIG = read_config()
    api = shodan.Shodan(CONFIG["key"])
