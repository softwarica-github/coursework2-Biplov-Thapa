import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import threading
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Define global variables for host and port
HOST = '127.0.0.1'
PORT = 55555

class CombinedApp:
    def __init__(self, root):
        self.root = root
        self.setup_ui()

        # Server attributes
        self.server = None
        self.server_running = False
        self.clients = []
        self.client_public_keys = {}

        # Client attributes
        self.client = None
        self.client_connected = False
        self.client_nickname = None
        self.client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.client_public_key = self.client_private_key.public_key()

        # Cryptography for the server
        self.server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.server_public_key = self.server_private_key.public_key()

        # Serialize server's public key to send to clients
        self.serialized_server_public_key = self.server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def setup_ui(self):
        self.root.title("Combined Server/Client App")
        self.root.geometry("800x600")

        # Server GUI setup
        self.server_frame = tk.LabelFrame(self.root, text="Server", padx=5, pady=5)
        self.server_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.server_log = scrolledtext.ScrolledText(self.server_frame, width=50, height=20, state="disabled")
        self.server_log.pack(padx=5, pady=5)
        self.server_start_button = tk.Button(self.server_frame, text="Start Server", command=self.toggle_server)
        self.server_start_button.pack(padx=5, pady=5)

        # Client GUI setup
        self.client_frame = tk.LabelFrame(self.root, text="Client", padx=5, pady=5)
        self.client_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        self.client_log = scrolledtext.ScrolledText(self.client_frame, width=50, height=20, state="disabled")
        self.client_log.pack(padx=5, pady=5)
        self.client_connect_button = tk.Button(self.client_frame, text="Connect as Client", command=self.toggle_client_connection)
        self.client_connect_button.pack(padx=5, pady=5)
        self.client_message_entry = tk.Entry(self.client_frame, width=48)
        self.client_message_entry.pack(padx=5, pady=5)
        self.client_send_button = tk.Button(self.client_frame, text="Send Message", command=self.send_client_message)
        self.client_send_button.pack(padx=5, pady=5)

    def toggle_server(self):
        if not self.server_running:
            self.start_server()
        else:
            self.stop_server()

    def start_server(self):
        self.server_running = True
        self.server_start_button.config(text="Stop Server")
        threading.Thread(target=self.run_server, daemon=True).start()
        self.update_server_log("Server started.")

    def stop_server(self):
        if self.server_running:
            self.server_running = False
            for client in self.clients:
                client.close()
            self.server.close()
            self.clients.clear()
            self.client_public_keys.clear()
            self.update_server_log("Server stopped.")
            self.server_start_button.config(text="Start Server")

    def run_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.server.bind((HOST, PORT))
            self.server.listen()
            self.update_server_log(f"Listening on {HOST}:{PORT}")
            while self.server_running:
                client, address = self.server.accept()
                threading.Thread(target=self.handle_client, args=(client,address), daemon=True).start()
        except Exception as e:
            self.update_server_log(f"Server error: {e}")
        finally:
            self.server.close()

    def handle_client(self, client, address):
        try:
            client.send(self.serialized_server_public_key)  # Send server's public key to client
            # First message from client should be their public key
            public_key_serialized = client.recv(4096)
            client_public_key = serialization.load_pem_public_key(public_key_serialized, backend=default_backend())
            self.clients.append(client)
            self.client_public_keys[client] = client_public_key
            self.update_server_log(f"Client {address} connected.")
            while True:
                encrypted_message = client.recv(4096)
                if not encrypted_message:
                    raise ConnectionResetError("Client disconnected.")
                message = self.decrypt_message(self.server_private_key, encrypted_message)
                self.update_server_log(f"Client {address}: {message}")
                self.broadcast_message(message, client)
        except (ConnectionResetError, OSError):
            self.update_server_log(f"Client {address} disconnected.")
        finally:
            client.close()
            self.clients.remove(client)
            del self.client_public_keys[client]

    def broadcast_message(self, message, sender_client):
        for client in self.clients:
            if client != sender_client:
                client_public_key = self.client_public_keys[client]
                encrypted_message = self.encrypt_message(client_public_key, message)
                client.send(encrypted_message)

    def toggle_client_connection(self):
        if not self.client_connected:
            self.connect_as_client()
        else:
            self.disconnect_client()

    def connect_as_client(self):
        self.client_nickname = simpledialog.askstring("Nickname", "Choose your nickname:", parent=self.root)
        if self.client_nickname:
            try:
                self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client.connect((HOST, PORT))
                # Send client's public key to server
                self.client.send(self.client_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
                # Receive server's public key
                server_public_key_serialized = self.client.recv(4096)
                self.server_public_key = serialization.load_pem_public_key(server_public_key_serialized, backend=default_backend())
                self.client_connected = True
                self.client_connect_button.config(text="Disconnect")
                threading.Thread(target=self.receive_client_messages, daemon=True).start()
                self.update_client_log("Connected to the server.")
            except Exception as e:
                messagebox.showerror("Connection Failed", str(e))
                self.client_connected = False
        else:
            messagebox.showinfo("Nickname Required", "Please enter a nickname to connect to the server.")

    def disconnect_client(self):
        if self.client_connected:
            self.client.close()
            self.client_connected = False
            self.client_connect_button.config(text="Connect as Client")
            self.update_client_log("Disconnected from the server.")

    def send_client_message(self):
        if self.client_connected and self.client_nickname:
            message = self.client_message_entry.get()
            encrypted_message = self.encrypt_message(self.server_public_key, message)
            self.client.send(encrypted_message)
            self.client_message_entry.delete(0, tk.END)

    def receive_client_messages(self):
        while self.client_connected:
            try:
                encrypted_message = self.client.recv(4096)
                if not encrypted_message:
                    raise ConnectionResetError("Disconnected from server.")
                message = self.decrypt_message(self.client_private_key, encrypted_message)
                self.root.after(0, lambda m=message: self.update_client_log(m))
            except Exception as e:
                self.client_connected = False
                self.root.after(0, lambda: self.update_client_log("Disconnected from server."))
                break

    def encrypt_message(self, public_key, message):
        return public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt_message(self, private_key, encrypted_message):
        return private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

    def update_server_log(self, message):
        self.server_log.config(state="normal")
        self.server_log.insert(tk.END, message + "\n")
        self.server_log.config(state="disabled")
        self.server_log.see(tk.END)

    def update_client_log(self, message):
        self.client_log.config(state="normal")
        self.client_log.insert(tk.END, message + "\n")
        self.client_log.config(state="disabled")
        self.client_log.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = CombinedApp(root)
    root.mainloop()
