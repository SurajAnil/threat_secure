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


class ThreatSecure:
    """Class that computes indicators of compromise
    """
    pass


def parse_args(arguments):
    """Parse and set arguments.

    :param arguments: argument list => sysv[1:]
    :return: dict() object
    """
    pass


def main(arguments):
    """Main function.
    """
    pass


if __name__ == "__main__":
    exit(main(sysv[1:]))
