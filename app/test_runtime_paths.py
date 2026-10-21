import os
import unittest
from unittest.mock import patch
from pathlib import Path
from runtime_paths import configured_path, ROOT

class PathsTests(unittest.TestCase):
    def test_defaults_are_repo_relative_and_client_is_unconfigured(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(Path(configured_path('runtime','temp')),ROOT/'.runtime/temp')
            self.assertEqual(configured_path('gcc'),'gcc')
            self.assertIn('unconfigured-client',configured_path('client'))

    def test_explicit_paths_override_defaults(self):
        with patch.dict(os.environ,{'MYDEX_RUNTIME_DIR':'custom-runtime','MYDEX_WECHAT_DLL':'custom-client/Weixin.dll'}):
            self.assertEqual(Path(configured_path('runtime','temp')),Path('custom-runtime/temp'))
            self.assertEqual(configured_path('client'),'custom-client/Weixin.dll')
