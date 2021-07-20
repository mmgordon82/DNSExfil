import bz2

from .abc import Compression


class Bzip2(Compression):
    __id__ = "Bzip2"

    @staticmethod
    def compress(in_data: bytes, compresslevel: int = 9) -> bytes:
        """
        Compress data as bzip2.
        using python's internal library bz2.
        see: https://docs.python.org/3/library/bz2.html#bz2.compress
        """
        return bz2.compress(in_data, compresslevel=compresslevel)

    @staticmethod
    def decompress(comp_data: bytes) -> bytes:
        """
        Decompress data as bzip2.
        using python's internal library bz2.
        see: https://docs.python.org/3/library/bz2.html#bz2.decompress
        """
        return bz2.decompress(comp_data)
