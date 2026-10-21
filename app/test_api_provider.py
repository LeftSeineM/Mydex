import json
import unittest
from unittest.mock import patch, MagicMock
from lab import Backend, DEFAULTS, UserError


class ApiProviderTests(unittest.TestCase):
    def config(self, **changes):
        return {**DEFAULTS, 'provider': 'api', 'model': 'Qwen3.8-Flash',
                'api_base': 'https://llmapi.paratera.com/v1',
                'api_credential': 'paratera', 'api_enable_thinking': False, **changes}

    def test_protected_key_and_fast_mode_reach_request(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({'choices': [{'message': {'content': '成功'}}]}).encode()
        with patch('api_credentials.load_key', return_value='fake-test-key') as key, patch('lab.urllib.request.build_opener') as opener:
            opener.return_value.open.return_value = response
            self.assertEqual(Backend().reply(self.config(), [{'role':'user','content':'你好'}]), '成功')
            request = opener.return_value.open.call_args.args[0]
            payload = json.loads(request.data)
            self.assertFalse(payload['enable_thinking'])
            self.assertIn('Qwen3.8-Flash', payload['messages'][0]['content'])
            self.assertEqual(request.get_header('Authorization'), 'Bearer fake-test-key')
            key.assert_called_once()

    def test_wrong_endpoint_never_decrypts_or_sends(self):
        with patch('api_credentials.load_key') as key, patch('lab.urllib.request.build_opener') as opener:
            with self.assertRaises(UserError):
                Backend().reply(self.config(api_base='https://example.com/v1'), [])
            key.assert_not_called()
            opener.assert_not_called()

    def test_credential_errors_do_not_leak(self):
        with patch('api_credentials.load_key', side_effect=ValueError('sensitive-material')):
            with self.assertRaises(UserError) as error:
                Backend().reply(self.config(), [])
            self.assertNotIn('sensitive-material', str(error.exception))

if __name__ == '__main__':
    unittest.main()
