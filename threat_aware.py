#!/usr/bin/env python3
"""
    This utility analyzes online components including IP-addresses, URLs, ports
    and hashes for vulnerabilities through indicators of compromise metric. This
    utility computes the metric by obtaining information from public sources and
    honeypots (Included in this repository is a sample dataset from a public
    honeypot that includes various events).

    The utility accepts as arguments IP-address, port, source, domain, URLs and
    hashes and lets the user know for any indications of compromise (IoC).

    Author     : Bennur, Suraj.
    Version    : 1.0
"""
import sys
import json
import time
import logging
import argparse
import subprocess

from os.path import join


logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)

SUCURI_BASE_API_URL = "https://sitecheck.sucuri.net/results"

URL_SCAN_API_BASE_URL = "https://urlscan.io/api/v1/"


class ThreatAware:
    """Class that computes potential risks of the given input
    and displays evidence in the form of indicators of compromise
    """
    def __init__(self, urls=None, api_key=""):
        self.url_list = urls
        self.api_key = api_key

    def scan_inputs(self):
        """Scan the given inputs
        """
        LOGGER.info("Starting the URL scan...")
        LOGGER.info("Checking with SecUri (https://sitecheck.sucuri.net) "
                    "through UrlScan.io (http://urlscan.io)")
        LOGGER.info("Please wait, this may take a few moments...\n")
        for url in self.url_list:
            final_url = self._construct_sucuri_url(url)
            uuid = self._post_submission_api(final_url)
            import time
            time.sleep(10)
            result = self._get_result_api(uuid)
            self._process_url_output(url, result)

    @staticmethod
    def _construct_sucuri_url(url):
        """Construct the final url to sucuri.

        :param url: Given actual url => 'http://www.google.com'
        :return: string representation of the final sucuri url
        => https://sitecheck.sucuri.net/results/www/google/com
        """
        url_list = [_.strip(":") for _ in url.split("/") if _ != ""]
        url_list.remove("http") if "http" in url_list else ""
        final_url = join(SUCURI_BASE_API_URL, *url_list)
        return final_url

    def _process_url_output(self, url, out_res):
        """Process the URL Scan output. This is the meat of the utility.

        :param url: The URL being scanned
        :param out_res: Response to extract
        """
        skip_list = [
            '', 'Knowledgebase', 'Privacy', 'Request Cleanup', 'See our policy>>', 'Sign up',
            'Sucuri Blog Learn about the latest malware hacks and DDoS attacks.',
            'Sucuri Labs The place where we publicly archive all the malware we find.',
            'Support', 'Terms', 'Website Backups', 'Website Firewall',
            'Website Monitoring', 'submit a support request']
        try:
            stats = {"uniqCountries": out_res["stats"]["uniqCountries"],
                     "totalLinks": out_res["stats"]["totalLinks"],
                     "malicious": out_res["stats"]["malicious"],
                     "adBlocked": out_res["stats"]["adBlocked"]}
            black_list_status = False
            black_list = [" ".join(_["text"].split()) for _ in out_res["data"]["links"]]
            black_list.sort()
            self._clean_up_link_list(
                skip_list=skip_list, black_list=black_list)
            for _ in black_list:
                if "Domain blacklisted by" in _:
                    black_list_status = True
                    break
            if stats["malicious"] or black_list_status:
                LOGGER.warning("Possible threat detected!!!! {}\n".format(url))
                LOGGER.info("Stats:")
                for key, val in stats.items():
                    LOGGER.warning("{}: {}".format(key, val))
                print("\n")
                LOGGER.info("Black list information:")
                for item in black_list:
                    LOGGER.warning(item)
            else:
                LOGGER.info("Yay! No threats detected here {}".format(url))
                LOGGER.info("Stats are as follows:")
                for key, val in stats.items():
                    LOGGER.info("{}: {}".format(key, val))
        except KeyError as _error:
            LOGGER.exception("%s", _error)

    def _post_submission_api(self, final_url):
        cmd = ["curl", "-X", "POST", "-H", "Content-Type: application/json",
               "-H", "API-Key: {}".format(self.api_key),
               "-d", json.dumps({"url": final_url, "visibility": "public"}),
               join(URL_SCAN_API_BASE_URL, "scan")]
        uuid_json = self._process_subprocess_cmd(cmd)
        uuid = uuid_json["uuid"]
        return uuid

    def _get_result_api(self, uuid):
        cmd = ["curl", "-X", "GET", "-H", "Content-Type: application/json",
               "-H", "API-Key: {}".format(self.api_key),
               join(URL_SCAN_API_BASE_URL, "result", str(uuid))]
        result = self._process_subprocess_cmd(cmd)
        return result

    @staticmethod
    def _process_subprocess_cmd(cmd, polling=True):
        res_json = {}
        try:
            with open("/dev/null", "w") as devnull:
                while polling:
                    res_obj = subprocess.check_output(cmd, stderr=devnull)
                    res_json = json.loads(res_obj)
                    time.sleep(3)
                    message = res_json.get("message")
                    if (not message or
                            "submission successful" in message.lower()):
                        polling = False
        except (AttributeError, TypeError, subprocess.CalledProcessError) as _error:
            LOGGER.exception("%s", _error)
        return res_json

    @staticmethod
    def _clean_up_link_list(skip_list, black_list):
        """Modify the black list array in place by removing
         the common items from the black list that are also in the skip list

        :param skip_list: list of items to be skipped
        :param black_list: list of black listed items
        :return: None
        """
        sl_i = 0
        bl_i = 0
        """
        sl = ["ab", "cd", "ef", "gg", "hh", "zz"]
        bl = ["ab", "ef", "xx", "yy", "zz"]
        """
        while sl_i < len(skip_list) and bl_i < len(black_list):
            if skip_list[sl_i] < black_list[bl_i]:
                sl_i += 1
            elif skip_list[sl_i] > black_list[bl_i]:
                bl_i += 1
            else:
                black_list.pop(bl_i)
                sl_i += 1


def parse_args(arguments):
    """Parse and set arguments.

    :param arguments: argument list => sysv[1:]
    :return: dict() object
    """
    arg_parser = argparse.ArgumentParser()
    help_text = "Enter URL/s to scan"
    arg_parser.add_argument("-u", "--urls", type=str, nargs="+", help=help_text)
    # help_text = "Enter the Virus Total API Key by registering on http://virustotal.com"
    # arg_parser.add_argument("-k", "--vt_api_key", type=str, help=help_text)

    help_text = "Enter the URLScan API Key by registering on http://urlscan.io"
    arg_parser.add_argument("-k1", "--url_scan_api_key", type=str, help=help_text)

    args = arg_parser.parse_args(arguments)
    return vars(args)


def main(arguments):
    """Main function.
    """
    args = parse_args(arguments)
    threat_aware = ThreatAware(args["urls"], args["url_scan_api_key"])
    threat_aware.scan_inputs()


if __name__ == "__main__":
    exit(main(sys.argv[1:]))
