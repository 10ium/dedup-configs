import json
import unittest
from unittest.mock import patch, mock_open
from scripts.deduplicate import (
    normalize_config,
    fingerprint_config,
    detect_protocol,
)

class TestDeduplication(unittest.TestCase):

    def setUp(self):
        self.defaults = {
            'shadowsocks': {'method': 'aes-128-gcm'},
            'trojan': {'sni': 'example.com'}
        }

    def test_normalize_config(self):
        config = {
            'server': '1.1.1.1',
            'server_port': 443,
            'password': 'pass',
            'timestamp': '12345',
            'UUID': 'aBcDeF'
        }
        expected = {
            'server': '1.1.1.1',
            'server_port': 443,
            'password': 'pass',
            'UUID': 'abcdef'
        }
        self.assertEqual(normalize_config(config, self.defaults), expected)

    def test_detect_protocol(self):
        ss_config = {'server': '1.1.1.1', 'server_port': 80, 'password': 'p', 'method': 'm'}
        trojan_config = {'server': '1.1.1.1', 'server_port': 443, 'password': 'p', 'sni': 's'}
        self.assertEqual(detect_protocol(ss_config), 'shadowsocks')
        self.assertEqual(detect_protocol(trojan_config), 'trojan')

    def test_fingerprint_config(self):
        config1 = {'server': '1.1.1.1', 'server_port': 80, 'password': 'p', 'method': 'm'}
        config2 = {'server': '1.1.1.1', 'server_port': 80, 'password': 'p', 'method': 'm', 'comment': 'c'}
        config3 = {'server': '2.2.2.2', 'server_port': 80, 'password': 'p', 'method': 'm'}

        with patch('scripts.deduplicate.detect_protocol', return_value='shadowsocks'):
            fp1 = fingerprint_config(config1)
            fp2 = fingerprint_config(config2)
            fp3 = fingerprint_config(config3)

        self.assertEqual(fp1, fp2)
        self.assertNotEqual(fp1, fp3)

if __name__ == '__main__':
    unittest.main()
