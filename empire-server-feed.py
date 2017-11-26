'''
Generate a CSV feed from Shodan data on open Empire HTTP listeners
Based on the following article: https://www.tenable.com/blog/identifying-empire-http-listeners
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
    query = 'title:"404 Not Found" + "Content-Length: 233"  + "Cache-Control: no-cache, no-store, must-revalidate" -"post-check=" -"pre-check=" -"private" + "Pragma: no-cache" + "Expires: 0" + "Server:" -"X-" -"Set-Cookie:" -"Connection:" -"Etag" -"Last-Modified" -"Accept-Ranges:" -"Access-Control"'
    results = api.search(query)
    print(results["total"])
    for result in results["matches"]:
        ip = ipaddress.ip_address(result["ip"])
        port = result["port"]
        city = result["location"]["city"]
        country = result["location"]["country_code"]
        ssl_fingerprint = result["ssl"]["cert"]["fingerprint"]["sha256"]
        ssl_issued = result["ssl"]["cert"]["issued"]
        ssl_expires = result["ssl"]["cert"]["expires"]
        raw_link = "https://www.shodan.io/host/{}".format(ip)
    print(json.dumps(results["matches"][0], indent=2))

if __name__ == "__main__":
    CONFIG = read_config()
    CSV_FILENAME = "empire-http-listeners.csv"
    CSV_FIELDS = [ "ipaddress", "port", "country", "added-on" ]
    FACETS = [ "org", "domain", "port", "asn", "country" ]
    api = shodan.Shodan(CONFIG["key"])
    search(api)
