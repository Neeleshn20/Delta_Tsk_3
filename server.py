import socket
import os
import zlib
import hashlib
import pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from getpass import getpass

# Configuration
HOST = '127.0.0.1'
PORT = 8888
BUFFER_SIZE = 4096
FILE_STORAGE_PATH = 'file_storage/'

# AES encryption settings
AES_KEY = hashlib.sha256(getpass("Enter AES encryption key: ").encode()).digest()
IV = os.urandom(16)

# User credentials
USERS = {
    'alice': hashlib.sha256('password1'.encode()).digest(),
    'bob': hashlib.sha256('password2'.encode()).digest()
}

# Server class
class Server:
    def __init__(self):
        self.server_socket = None

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((HOST, PORT))
        self.server_socket.listen(5)
        print('Server started and listening on {}:{}'.format(HOST, PORT))

        while True:
            client_socket, address = self.server_socket.accept()
            print('Accepted connection from {}:{}'.format(address[0], address[1]))
            client_handler = ClientHandler(client_socket)
            client_handler.start()

    def stop(self):
        if self.server_socket:
            self.server_socket.close()


# Client handler class
class ClientHandler:
    def __init__(self, client_socket):
        self.client_socket = client_socket

    def start(self):
        while True:
            try:
                # Authenticate user
                username = self.receive_data()
                password = self.receive_data()
                if self.authenticate_user(username, password):
                    self.send_data('Authenticated')
                    break
                else:
                    self.send_data('Authentication failed')
            except (socket.error, ValueError):
                break

        while True:
            try:
                # Receive client command
                command = self.receive_data()
                if command == 'UPLOAD':
                    self.handle_upload()
                elif command == 'DOWNLOAD':
                    self.handle_download()
                elif command == 'SEARCH':
                    self.handle_search()
                elif command == 'REMOVE':
                    self.handle_remove()
                elif command == 'EXIT':
                    break
            except (socket.error, ValueError):
                break

        self.client_socket.close()

    def handle_upload(self):
        # Receive file name
        file_name = self.receive_data()
        # Receive file content
        file_content = self.receive_data()
        # Compress the file content
        compressed_content = zlib.compress(file_content)
        # Encrypt the compressed content
        encrypted_content = self.encrypt(compressed_content)
        # Save the encrypted content to a file
        file_path = os.path.join(FILE_STORAGE_PATH, file_name + '.zip')
        with open(file_path, 'wb') as file:
            file.write(encrypted_content)
        print('File stored as {}'.format(file_path))
        self.send_data('Uploaded')

    def handle_download(self):
        # Receive file name
        file_name = self.receive_data()
        # Load the encrypted content from file
        file_path = os.path.join(FILE_STORAGE_PATH, file_name + '.zip')
        if not os.path.exists(file_path):
            self.send_data('File not found')
            return
        with open(file_path, 'rb') as file:
            encrypted_content = file.read()
        # Decrypt the content
        compressed_content = self.decrypt(encrypted_content)
        # Decompress the content
        file_content = zlib.decompress(compressed_content)
        self.send_data(file_content)
        self.send_data('Downloaded')

    def handle_search(self):
        # Receive regex pattern
        pattern = self.receive_data()
        # Search for files matching the pattern
        matched_files = []
        for file_name in os.listdir(FILE_STORAGE_PATH):
            if file_name.endswith('.zip') and pattern in file_name:
                matched_files.append(file_name[:-4])  # Remove the '.zip' extension
        self.send_data(pickle.dumps(matched_files))
        self.send_data('Search complete')

    def handle_remove(self):
        # Receive file name
        file_name = self.receive_data()
        # Remove the file
        file_path = os.path.join(FILE_STORAGE_PATH, file_name + '.zip')
        if os.path.exists(file_path):
            os.remove(file_path)
            self.send_data('File removed')
        else:
            self.send_data('File not found')

    def authenticate_user(self, username, password):
        if username in USERS:
            hashed_password = USERS[username]
            return hashed_password == hashlib.sha256(password.encode()).digest()
        return False

    def receive_data(self):
        data = self.client_socket.recv(BUFFER_SIZE)
        if not data:
            raise ValueError('Connection closed')
        return data.decode()

    def send_data(self, data):
        self.client_socket.send(data.encode())

    def encrypt(self, data):
        cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        return IV + encrypted_data

    def decrypt(self, data):
        iv = data[:16]
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(data[16:]), AES.block_size)
        return decrypted_data


# Main entry point
if __name__ == '__main__':
    server = Server()
    try:
        server.start()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()

