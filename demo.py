''' Basic practice with the Shodan API '''
import ipaddress
import json
import logging
import socket

import pandas
import shodan


def _read_config(path="config.json"):
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
        for record in answer:
            hostnames[host].append(record[-1][0])
    return hostnames


if __name__ == "__main__":
    CONFIG = _read_config()
    api = shodan.Shodan(CONFIG["key"])
    websites = resolve_websites()
