import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from smb_client import SMBClient  # noqa: E402


class _FakeConnection:
    max_read_size = 8
    sequence_window = {"low": 0, "high": 1024}

    def send(self, message, session_id, tree_id, credit_request=0):
        return message


class _ShortReadOpen:
    def __init__(self):
        self.connection = _FakeConnection()
        self.tree_connect = SimpleNamespace(
            session=SimpleNamespace(session_id=1), tree_connect_id=2)
        self.requests = []

    def read(self, offset, length, send=False):
        self.requests.append((offset, length))

        def receive(_request):
            data = b"abcdefghijklmnop"[offset:offset + length]
            if offset == 0 and length == 8:
                return data[:4]
            return data

        return (offset, length), receive


class PipelinedReadTests(unittest.TestCase):
    def test_short_response_is_filled_before_later_pipeline_data(self):
        client = SMBClient("host", 445, "user", "pass", "share",
                           read_size=8, read_pipeline_depth=2)
        opened = _ShortReadOpen()
        client._connection = opened.connection

        actual = client._read_pipelined(opened, 0, 16)

        self.assertEqual(b"abcdefghijklmnop", actual)
        self.assertEqual([(0, 8), (8, 8), (4, 4)], opened.requests)


if __name__ == "__main__":
    unittest.main()
