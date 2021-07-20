import zlib

from .abc import Compression


class Zlib(Compression):
    __id__ = "Zlib"
    @staticmethod
    def compress(in_data: bytes, compresslevel: int = 9) -> bytes:
        """
        Compress data as zlib.
        using python's internal library zlib.
        see: https://docs.python.org/3/library/zlib.html#zlib.compress
        """
        return zlib.compress(in_data, level=compresslevel)

    @staticmethod
    def decompress(comp_data: bytes) -> bytes:
        """
        Decompress data as zlib.
        using python's internal library zlib.
        see: https://docs.python.org/3/library/zlib.html#zlib.decompress
        """
        return zlib.decompress(comp_data)
