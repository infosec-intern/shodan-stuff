''' Basic practice with the Shodan API '''
import json

import shodan


def _read_config(path="config.json"):
    ''' Read API info out of config file '''
    with open(path, "r") as ifile:
        return json.load(ifile)


if __name__ == "__main__":
    config = _read_config()
    api = shodan.Shodan(config["key"])
    print(api)

