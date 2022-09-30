"""OsAdapter module is used in unittest to Mock some os functions."""

import os


class OsAdapter:
    """OsAdapter class."""

    @staticmethod
    def listdir(path: str) -> list[str]:
        """List directories from path."""
        return os.listdir(path)

    @staticmethod
    def join(path: str, file: str) -> str:
        """Join path with a filename."""
        return os.path.join(path, file)

    @staticmethod
    def read_file(file: str, mode: str, encoding: str) -> str:
        """Read file and return string."""
        with open(file, mode, encoding=encoding) as file_stream:
            return str(file_stream.read())

    @staticmethod
    def exists(path: str) -> bool:
        """Check if file exists."""
        return os.path.exists(path)

    @staticmethod
    def mkdir(directory: str) -> None:
        """Create directory."""
        return os.mkdir(directory)

    @staticmethod
    def isfile(path: str) -> bool:
        """Check if path is a file."""
        return os.path.isfile(path)
