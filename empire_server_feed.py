'''
Generate a CSV feed from Shodan data on open Empire HTTP listeners
Based on the following article: https://www.tenable.com/blog/identifying-empire-http-listeners
'''
import csv
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
    facets = {
        "org": "Top 5 Organizations",
        "domain": "Top 5 Domains",
        "port": "Top 5 Ports",
        "asn": "Top 5 ASNs",
        "country": "Top 5 Countries",
        "product": "Top 5 Servers",
        "isp": "Top 5 ISPs"
    }
    results = api.count(query, facets=list(facets.keys()))
    print("Total Results: {}".format(results["total"]))
    for facet in results["facets"]:
        print(facets[facet])
        for term in results["facets"][facet]:
            print("\t{}: {}".format(term["value"], term["count"]))
    results = api.search_cursor(query)
    feed_data = []
    for result in results:
        feed_data.append({
            "city": result["location"]["city"],
            "country": result["location"]["country_code"],
            "ip": result["ip_str"],
            "port": result["port"],
            # "ssl_fingerprint": result["ssl"]["cert"]["fingerprint"]["sha256"],
            # "ssl_issued": result["ssl"]["cert"]["issued"],
            # "ssl_expires": result["ssl"]["cert"]["expires"],
            "timestamp": result["timestamp"]
        })
        logging.debug("Added '%s' to feed", result["ip_str"])
    return feed_data

def write_results(feed):
    '''
    Write out Shodan results to a CSV file

    :feed: list of results
    '''
    with open("empire-http-listeners.csv", "w", newline='') as ofile:
        fields = sorted(list(feed[0].keys()))
        csvfile = csv.DictWriter(f=ofile, fieldnames=fields)
        csvfile.writeheader()
        for row in feed:
            csvfile.writerow(row)

if __name__ == "__main__":
    CONFIG = read_config()
    API = shodan.Shodan(CONFIG["key"])
    FEED = search(API)
    write_results(FEED)
