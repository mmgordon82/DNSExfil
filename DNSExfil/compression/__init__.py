"""
Package for handling different compressions (built for DNSExfil).
"""

from .abc import Compression
from .bzip2 import Bzip2
from .zlib import Zlib

class NoCompress(Compression):
    """
    class for no compressing the data at all.
    Sometimes, compressed data might be bigger in size than the original.
    """

    __id__ = "NoCompress"

    @staticmethod
    def compress(in_data: bytes, compresslevel: int = 9) -> bytes:
        return in_data

    @staticmethod
    def decompress(comp_data: bytes) -> bytes:
        return comp_data


def suggest_best_compression(data: bytes, compressionlevel: int = 9) -> Compression:
    """
    Returns the best compression for the sample data provided.
    The best compression is defined by the size of the compressed content.
    When the data is too small, using no compression might benefit more than any.
    :param data: the sample data to select the best compression for.
    :type data: bytes
    :param compressionlevel: for supported compressions - how hard to compress the information.
                        number between 1 - 9 where 1 means fastest but least compressed and 9
                        means best compression but slow.
    :type compressionlevel: int
    :return: The compression that best compresses the data
    :rtype: Compression
    """
    return min(Compression.__subclasses__(),
               key=lambda x: len(x.compress(in_data=data, compresslevel=compressionlevel)))

__all__ = [i.__id__ for i in Compression.__subclasses__()] + ["Compression", "suggest_best_compression"]
