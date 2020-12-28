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
import re
import sys
import logging
import argparse
import subprocess

# from lxml import html, etree
from os.path import join

# from bs4 import BeautifulSoup

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)

SUCURI_BASE_URL = "https://sitecheck.sucuri.net/"


class ThreatAware:
    """Class that computes potential risks of the given input
    and displays evidence in the form of indicators of compromise
    """
    def __init__(self, urls=None):
        self.url_list = urls
        self.api_key = ""

    def scan_inputs(self):
        """Scan the given inputs
        """
        LOGGER.info("Starting the URL scan...")
        with open("/dev/null", "w") as devnull:
            for url in self.url_list:
                final_url = self._construct_sucuri_url(url)
                out = subprocess.check_output(
                    ["curl", "-H", "application/html", final_url], stderr=devnull)
                self._process_url_output(out, url)

    @staticmethod
    def _construct_sucuri_url(url):
        """Construct the final url to sucuri.

        :param url: Given actual url => 'http://www.google.com'
        :return: string representation of the final sucuri url
        => https://sitecheck.sucuri.net/results/www/google/com
        """
        url_list = [_.strip(":") for _ in url.split("/") if _ != ""]
        url_list.remove("http") if "http" in url_list else ""
        final_url = join(SUCURI_BASE_URL, *url_list)
        return final_url

    @staticmethod
    def _process_url_output(out_res, url):
        # tree = html.fromstring(out_res.decode('utf-8', errors='ignore'))
        # print(tree.xpath('/html/body'))
        out_res_str = out_res.decode('utf-8')
        # FIXME Change this bruteforce method of parsing the results
        results = re.search("Site is Blacklisted", out_res_str)
        if results:
            LOGGER.warning("{}: {}".format(results.group(), url))
        else:
            LOGGER.info("No threats detected for: {}".format(url))


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
    args = arg_parser.parse_args(arguments)
    return vars(args)


def main(arguments):
    """Main function.
    """
    args = parse_args(arguments)
    threat_aware = ThreatAware(args["urls"])
    threat_aware.scan_inputs()


if __name__ == "__main__":
    exit(main(sys.argv[1:]))
