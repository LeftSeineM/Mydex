"""A confirmed crashing client probe must fail before opening any process."""
import sys
import unittest
from unittest.mock import patch

import locate_native_marker
import probe_native


class ClientProbeDisabledTests(unittest.TestCase):
    def test_counter_never_opens_process_while_disabled(self):
        with patch.object(sys,'argv',['probe_native.py','--pid','123']), \
             patch.object(probe_native,'verify_process') as verify:
            with self.assertRaisesRegex(RuntimeError,'已停用'):
                probe_native.main()
            verify.assert_not_called()

    def test_marker_scan_never_opens_process_while_disabled(self):
        with patch.object(sys,'argv',['locate_native_marker.py','--pid','123']), \
             patch.object(locate_native_marker,'verify_process') as verify:
            with self.assertRaisesRegex(RuntimeError,'已停用'):
                locate_native_marker.main()
            verify.assert_not_called()


if __name__=='__main__':unittest.main()
