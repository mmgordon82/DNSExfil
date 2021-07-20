from abc import ABC, abstractmethod


class Compression(ABC):
    """
    Base class for compression.
    all compression classes will inherit
    """
    __id__ = "Compression"

    @property
    def name(self):
        return self.__id__

    def __repr__(self):
        return f"<{self.name} Compression Object>"

    def __str__(self):
        return self.name

    @staticmethod
    @abstractmethod
    def compress(in_data: bytes, compresslevel: int = 9) -> bytes:
        """
        Compress the data.
        Should be overridden by other classes.
        :param in_data:
        :type in_data:
        :param compresslevel: Controls the compression-speed vs compression-
        density tradeoff.
        :type compresslevel: int
        :return: the compressed data
        :rtype: bytes
        """
        pass

    @staticmethod
    @abstractmethod
    def decompress(comp_data: bytes) -> bytes:
        """
        Decompress the data back to original form.
        Should be overridden by other classes.
        :param comp_data: compressed data, from the same compression method
        :type comp_data: bytes
        """
        pass
