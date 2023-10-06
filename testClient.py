import socket
import struct
import uuid


def connect_to_server(server_ip, server_port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))
    return client_socket


def register_to_server(sock, client_name):
    # Create and pack message according to protocol
    client_id = b'\0' * 16  # Generate a unique ID for the client
    version = b'\x01\x00'  # Version 1.0
    code = 1025 # Registration code
    payload_size = 255  # Max name length

    # Constructing the message

    message = struct.pack("<16s2sH", client_id, version, code) + struct.pack("<I", payload_size) + client_name.ljust(
        255, '\0').encode()

    print(f"Sending message with length: {len(message)}")
    # Send registration request
    sock.send(message)

    # Receive response
    response_header = sock.recv(22)  # Header size
    print(f"Received response of length: {len(response_header)}")

    _, version, response_code, payload_size = struct.unpack("<16sH2sH4s", response_header)

    if response_code == 2100:  # Registration successful
        client_id = sock.recv(16)
        return True, client_id
    elif response_code == 2101:  # Registration failed
        return False, None


def main():
    server_ip = '127.0.0.1'
    server_port = 1357

    client_name = input("Enter your client name (max 255 characters): ")

    with connect_to_server(server_ip, server_port) as sock:
        success, client_id = register_to_server(sock, client_name)
        if success:
            print(f"Registered successfully with ID: {uuid.UUID(bytes=client_id)}")
        else:
            print("Registration failed.")


if __name__ == "__main__":
    main()
