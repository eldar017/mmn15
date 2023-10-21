import socket
import struct
import uuid
from Crypto.Cipher import AES
import os


def pad(data):
    padding_length = 16 - (len(data) % 16)
    return data + bytes([padding_length] * padding_length)


def unpad(data):
    return data[:-data[-1]]


def connect_to_server(server_ip, server_port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))
    return client_socket


def get_public_key():
    with open("public_key.pem", "rb") as pub_file:
        return pub_file.read()


def send_large_data(sock, data):
    size = 4096  # Size of each chunk. This can be adjusted as per your requirement.
    chunks = [data[i:i+size] for i in range(0, len(data), size)]
    for chunk in chunks:
        sock.sendall(chunk)
def send_file_to_server(sock, file_path, aes_key):
    version = b'\x01\x00'
    print("Sending file to server...")
    try:
        with open(file_path, "rb") as file:
            file_content = file.read()
    except FileNotFoundError:
        print("File not found.")
        return

    print("AES key:", aes_key)

    # Pad the file content
    file_content_padded = pad(file_content)
    print("File content size:", len(file_content))

    # Print the padded file content
    # print("Padded file content:", file_content_padded)

    # Create a cipher object
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=b'\0' * 16)

    # Encrypt the file content
    encrypted_content = cipher.encrypt(file_content_padded)

    # Print the encrypted content
    # print("Encrypted content:", encrypted_content)

    # Create the header
    file_name = os.path.basename(file_path)
    encrypted_size = len(encrypted_content)
    print("Encrypted size:", encrypted_size)
    message_code = 1028  # Assuming 1026 is the code for "file sending"
    header = struct.pack("<16s2sH4s", b'\0' * 16, version, message_code, struct.pack("<I", encrypted_size))
    print("Packed size:", struct.pack("<I", encrypted_size))


    # Send the header and encrypted content
    try:
        try:
            # print(header)

            sock.sendall(header)

        except socket.error:
            print("Failed to send file to server.")
            return
        try:
            send_large_data(sock, encrypted_content)
        except socket.error:
            print("Failed to send file to server.")
            return
        response_code = struct.unpack("<H", sock.recv(2))[0]
        print("Response code:", response_code)
        if response_code == 2103:  # Assuming 2103 is the code for "File Received"
            print("File sent successfully!")
        else:
            print(f"Error from server with response code: {response_code}")
    except socket.error:
        print("Failed to sendall.")
        return



def register_to_server(sock, client_name):
    version = b'\x01\x00'
    code = 1025
    payload_size = 255
    public_key = get_public_key()

    message = struct.pack("<16s2sH", b'\0' * 16, version, code) + struct.pack("<I", payload_size) + client_name.ljust(
        255, '\0').encode()
    message += public_key
    print(f"Sending message with length: {len(message)}")

    sock.sendall(message)

    response_header = sock.recv(18)
    if len(response_header) != 18:
        print("Unexpected response size from server.")
        return False, None

    response_code, client_id_received = struct.unpack("<H16s", response_header)

    if response_code == 2100:
        return True, client_id_received
    elif response_code == 2101:
        return False, None


def main():
    server_ip = '127.0.0.1'
    server_port = 1357

    client_name = input("Enter your client name (max 255 characters): \n")

    with connect_to_server(server_ip, server_port) as sock:
        success, client_id = register_to_server(sock, client_name)

        if success:
            print(f"Registered successfully with ID: {uuid.UUID(bytes=client_id)}")
            aes_key = os.urandom(16)  # For demonstration, generate a random AES key
            file_path = input("Enter the path of the file you want to send: ")
            print("sock : {}, aes key: {}, file path: {}".format(sock, aes_key, file_path.encode('utf-8')))
            send_file_to_server(sock, file_path, aes_key)

        else:
            print("Registration failed.")


if __name__ == "__main__":
    main()
