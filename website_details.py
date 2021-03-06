''' Basic practice with the Shodan API '''
import ipaddress
import json
import logging
import socket

import pandas
import shodan


logging.basicConfig(level=logging.DEBUG)


def read_config(path="config.json"):
    ''' Read API info out of config file '''
    with open(path, "r") as ifile:
        return json.load(ifile)

def resolve_websites():
    ''' DNS lookup on all the websites available '''
    hostnames = {
        "centurylink.com": [],
        "level3.com": [],
        "twc.com": [],
        "xfinity.com": [],
        "att.com": [],
        "chase.com": [],
        "usbank.com": [],
        "bankofamerica.com": [],
        "google.com": [],
        "apple.com": [],
        "amazon.com": []
    }
    for host in hostnames:
        answer = socket.getaddrinfo(host, 0, 0, 0, 0)
        hostnames[host] = [record[-1][0] for record in answer]
        logging.debug("%s resolves to: %s", host, ", ".join(hostnames[host]))
    return hostnames

if __name__ == "__main__":
    CONFIG = read_config()
    API = shodan.Shodan(CONFIG["key"])
    WEBSITES = resolve_websites()
    for hostname in WEBSITES:
        for ip in WEBSITES[hostname]:
            results = API.host(ip)
            print(json.dumps(results, indent=2))
        break
