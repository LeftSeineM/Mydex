import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import assistant_supervisor as supervisor


class Tests(unittest.TestCase):
    def test_injection_attempt_not_repeated_in_same_client_session(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(supervisor,'DATA',Path(temporary)):
            supervisor.claim_install_attempt(100,123.0)
            with self.assertRaises(ValueError):supervisor.claim_install_attempt(100,123.0)
            # A new OS process with the same PID is a different session.
            supervisor.claim_install_attempt(100,124.0)


if __name__=='__main__':unittest.main()
