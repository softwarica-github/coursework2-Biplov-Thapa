import unittest
from unittest.mock import patch
import tkinter as tk
from app import CombinedApp

class MockSocket:
    def __init__(self):
        self.sent_data = None

    def send(self, data):
        self.sent_data = data

    def recv(self, size):
        return b"Mocked data"

class TestCombinedApp(unittest.TestCase):

    def setUp(self):
        self.root = tk.Tk()
        self.app = CombinedApp(self.root)

    def tearDown(self):
        self.root.destroy()

    def test_server_start_stop(self):
        # Test server start
        self.app.start_server()
        self.assertTrue(self.app.server_running)

        # Test server stop
        self.app.stop_server()
        self.assertFalse(self.app.server_running)

    def test_client_connection_disconnection(self):
        # Mock client socket to simulate connection
        with patch('socket.socket', return_value=MockSocket()) as mock_socket:
            # Test client connection
            self.app.connect_as_client()
            self.assertTrue(self.app.client_connected)

            # Test client disconnection
            self.app.disconnect_client()
            self.assertFalse(self.app.client_connected)

    def test_encryption_decryption(self):
        message = "Test Message"
        encrypted_message = self.app.encrypt_message(self.app.server_public_key, message)
        decrypted_message = self.app.decrypt_message(self.app.server_private_key, encrypted_message)
        self.assertEqual(message, decrypted_message)

    # You can write more tests for broadcasting, sending, and receiving messages.

if __name__ == '__main__':
    unittest.main()
