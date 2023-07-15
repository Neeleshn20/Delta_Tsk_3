import socket
import zlib
import pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from getpass import getpass

# Configuration
HOST = '127.0.0.1'
PORT = 8888
BUFFER_SIZE = 4096

# AES encryption settings
AES_KEY = hashlib.sha256(getpass("Enter AES encryption key: ").encode()).digest()
IV = os.urandom(16)

# Client class
class Client:
    def __init__(self):
        self.client_socket = None

    def connect(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((HOST, PORT))

    def disconnect(self):
        if self.client_socket:
            self.client_socket.close()

    def authenticate(self, username, password):
        self.send_data(username)
        self.send_data(password)
        response = self.receive_data()
        return response == 'Authenticated'

    def upload_file(self, file_path):
        file_name = os.path.basename(file_path)
        file_content = self.read_file(file_path)
        self.send_data('UPLOAD')
        self.send_data(file_name)
        self.send_data(file_content)
        response = self.receive_data()
        print(response)

    def download_file(self, file_name):
        self.send_data('DOWNLOAD')
        self.send_data(file_name)
        response = self.receive_data()
        if response == 'File not found':
            print('File not found')
        else:
            file_content = self.receive_data()
            self.write_file(file_name, file_content)
            print('File downloaded')

    def search_files(self, pattern):
        self.send_data('SEARCH')
        self.send_data(pattern)
        response = self.receive_data()
        if response == 'Search complete':
            matched_files = pickle.loads(self.receive_data())
            print('Matched files: {}'.format(matched_files))
        else:
            print('Search failed')

    def remove_file(self, file_name):
        self.send_data('REMOVE')
        self.send_data(file_name)
        response = self.receive_data()
        print(response)

    def send_data(self, data):
        self.client_socket.send(data.encode())

    def receive_data(self):
        data = self.client_socket.recv(BUFFER_SIZE)
        if not data:
            raise ValueError('Connection closed')
        return data.decode()

    def read_file(self, file_path):
        with open(file_path, 'rb') as file:
            return file.read()

    def write_file(self, file_name, file_content):
        with open(file_name, 'wb') as file:
            file.write(file_content)

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
    client = Client()
    client.connect()

    username = input('Username: ')
    password = getpass('Password: ')
    if client.authenticate(username, password):
        while True:
            command = input('Enter command (UPLOAD, DOWNLOAD, SEARCH, REMOVE, EXIT): ')
            if command == 'UPLOAD':
                file_path = input('Enter file path: ')
                client.upload_file(file_path)
            elif command == 'DOWNLOAD':
                file_name = input('Enter file name: ')
                client.download_file(file_name)
            elif command == 'SEARCH':
                pattern = input('Enter search pattern: ')
                client.search_files(pattern)
            elif command == 'REMOVE':
                file_name = input('Enter file name: ')
                client.remove_file(file_name)
            elif command == 'EXIT':
                break

    client.disconnect()

