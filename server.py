import socket
import sqlite3
import struct
import uuid
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import os
import zlib


def initialize_database():
    conn = sqlite3.connect('../db.defensive')
    cursor = conn.cursor()

    # Create the 'clients' table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS clients (
        ID BLOB PRIMARY KEY,
        Name TEXT,
        PublicKey BLOB,
        LastSeen TEXT,
        AESKey BLOB NULL
    )
    ''')

    # Create the 'files' table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS files (
        ID BLOB,
        FileName TEXT,
        FilePath TEXT,
        Verified BOOLEAN
    )
    ''')

    conn.commit()
    conn.close()


def get_port_from_file():
    try:
        with open("info.port", "r") as file:
            return int(file.read().strip())
    except FileNotFoundError:
        print("Warning: info.port not found. Using default port 1357.")
        return 1357

def save_received_public_key(client_id, public_key):
    file_name = f"{client_id.hex()}_public_key.pem"
    with open(file_name, "wb") as pub_file:
        pub_file.write(public_key)

def calculate_crc(data):
    return zlib.crc32(data) & 0xFFFFFFFF



def handle_client_login(conn, cursor, client_name, public_key):
    # Check if client_name already exists in the database
    cursor.execute('SELECT ID FROM clients WHERE Name=?', (client_name,))
    client = cursor.fetchone()

    if client:
        # Client is already registered, fetch the client's ID
        client_id = client[0]
    else:
        # New client, generate a new UUID for the client
        client_id = uuid.uuid4().bytes
        cursor.execute('''
        INSERT INTO clients (ID, Name, PublicKey) VALUES (?, ?, ?)
        ''', (client_id, client_name, public_key))

    # Send back the client's ID
    conn.sendall(struct.pack("<H16s", 2100, client_id))


def handle_client_returning_login(conn, cursor, client_name):
    # Check if client_name already exists in the database
    cursor.execute('SELECT ID, AESKey FROM clients WHERE Name=?', (client_name,))
    client = cursor.fetchone()

    if client:
        # If client is found in the database
        client_id, aes_key = client
        # (You might also want to update the 'LastSeen' column here)

        # For now, we're assuming the AES key was stored in plain-text in the database.
        # This may not be the most secure method, but for simplicity and demonstration,
        # we'll proceed this way. Later, you might want to consider storing the AES key
        # in a more secure manner.

        # Send the AES key to the client (2105)
        conn.sendall(struct.pack("<H16s", 2105, aes_key))
    else:
        # If client is not found in the database
        conn.sendall(struct.pack("<H", 2106))


def handle_public_key_request(conn, cursor, client_name, public_key):
    # Update the client's public key in the database
    cursor.execute('''
    UPDATE clients SET PublicKey=? WHERE Name=?
    ''', (public_key, client_name))

    # Generate AES key and encrypt it with the client's public key
    aes_key = os.urandom(16)
    rsa_public_key = RSA.importKey(public_key)
    cipher = PKCS1_OAEP.new(rsa_public_key)
    encrypted_aes_key = cipher.encrypt(aes_key)

    # Update the client's AES key in the database
    cursor.execute('''
    UPDATE clients SET AESKey=? WHERE Name=?
    ''', (aes_key, client_name))

    # Send the encrypted AES key to the client (2102)
    response_code = 2102
    conn.sendall(struct.pack("<H16s", response_code, encrypted_aes_key))


def handle_registration_request(conn, cursor, client_name):
    print(f"Handling registration for client {client_name}...")  # Add this print statement
    cursor.execute('SELECT * FROM clients WHERE Name=?', (client_name,))
    if cursor.fetchone():
        print(f"Client {client_name} already exists!")  # Add this print statement
        conn.sendall(struct.pack("<H", 2101))
        return
    client_id = uuid.uuid4().bytes
    public_key = conn.recv(450)
    cursor.execute('''
    INSERT INTO clients (ID, Name, PublicKey) VALUES (?, ?, ?)
    ''', (client_id, client_name, public_key))
    cursor.connection.commit()
    print(f"Registered client {client_name} with ID {client_id.hex()}")  # Add this print statement
    print("Sending response to client...")
    conn.sendall(struct.pack("<H16s", 2100, client_id))
    print("Response sent!")




def handle_send_public_key_request(conn, cursor, client_name, public_key):
    # Check if client_name already exists in the database
    cursor.execute('SELECT ID FROM clients WHERE Name=?', (client_name,))
    client = cursor.fetchone()

    if not client:
        # Client not found, send an error (2106)
        conn.sendall(struct.pack("<H", 2106))
        return

    client_id = client[0]
    # Update the client's public key in the database
    cursor.execute('UPDATE clients SET PublicKey=? WHERE ID=?', (public_key, client_id))

    # Generate a new AES key
    aes_key = os.urandom(16)

    # Encrypt the AES key with the client's public key and send it to the client
    rsa_public_key = RSA.importKey(public_key)
    cipher = PKCS1_OAEP.new(rsa_public_key)
    encrypted_aes_key = cipher.encrypt(aes_key)

    # Update the client's AES key in the database
    cursor.execute('UPDATE clients SET AESKey=? WHERE ID=?', (aes_key, client_id))

    # Send the encrypted AES key to the client (2102)
    conn.sendall(struct.pack("<H16s", 2102, encrypted_aes_key))


def handle_send_file_request(conn, cursor, client_id, file_size, file_name, encrypted_content):
    cursor.execute('SELECT AESKey FROM clients WHERE ID=?', (client_id,))
    aes_key_entry = cursor.fetchone()

    if not aes_key_entry:
        # Client not found, send a general server error (2107)
        conn.sendall(struct.pack("<H", 2107))
        return

    aes_key = aes_key_entry[0]

    # Decrypt the file content
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=b'\0' * 16)
    file_content = cipher.decrypt(encrypted_content)

    # Save the file locally
    local_file_path = f'files/{file_name}'
    with open(local_file_path, 'wb') as f:
        f.write(file_content)

    # Store the file details in the "files" table
    cursor.execute('''
    INSERT INTO files (ID, FileName, FilePath) VALUES (?, ?, ?)
    ''', (client_id, file_name, local_file_path))

    # Calculate CRC (as described, you would use an equivalent of the "cksum" command)
    # Assuming you have a function `calculate_crc` implemented:
    crc_value = calculate_crc(file_content)

    # Send back the CRC to the client (2103)
    response = struct.pack("<H16sI255sI", 2103, client_id, file_size, file_name.encode(), crc_value)
    conn.sendall(response)


def handle_crc_validation_request(conn, cursor, client_id, file_name):
    # Fetch the file details from the database
    cursor.execute('SELECT FilePath FROM files WHERE ID=? AND FileName=?', (client_id, file_name))
    file_entry = cursor.fetchone()

    if not file_entry:
        # File not found, send a general server error (2107)
        conn.sendall(struct.pack("<H", 2107))
        return

    file_path = file_entry[0]

    with open(file_path, 'rb') as f:
        file_content = f.read()

    # Calculate the CRC of the file
    crc_value = calculate_crc(file_content)

    # Send back the CRC value to the client (2103)
    response = struct.pack("<H16sI255sI", 2103, client_id, len(file_content), file_name.encode(), crc_value)
    conn.sendall(response)


def handle_invalid_crc_request(conn, client_id, file_name):
    # You can add logic here to track the number of retries for each file, if necessary.
    # For now, we just acknowledge the client's request.
    response = struct.pack("<H16s", 2104, client_id)
    print("handle_invalid_crc_request")
    conn.sendall(response)

def handle_invalid_crc_resend_request(conn, cursor, client_id, file_name):
    # This function will handle when the client indicates the CRC is invalid and
    # intends to resend the file. This might involve some logging or status update.
    print("handle_invalid_crc_resend_request")
    pass  # Placeholder

def handle_invalid_crc_resend_request(conn, cursor, client_id, file_name):
    # This function will handle when the client indicates the CRC is invalid and
    # intends to resend the file. This might involve some logging or status update.
    print("handle_invalid_crc_resend_request  ")
    pass  # Placeholder


def server_loop(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', port))
    s.listen(5)

    while True:  # Add an infinite loop to keep the server running
        conn, addr = s.accept()
        try:
            with conn:
                # Decode the incoming message according to the protocol
                try:
                    header, version, code, payload_size = struct.unpack("<16s2sH4s", conn.recv(24))
                    client_id = header
                except Exception as e:
                    print(f"Failed to unpack the received data due to: {e}")
                    return

                if code == 1025:
                    # Registration request
                    client_name = conn.recv(255).decode().rstrip('\0')

                    with sqlite3.connect('../db.defensive') as db_conn:
                        cursor = db_conn.cursor()
                        handle_registration_request(conn, cursor, client_name)
                        db_conn.commit()

        except Exception as e:
            print(f"Error while handling client  {addr}: {e}")
            try:
                conn.sendall(struct.pack("<H", 2107))
            except:
                pass  # ignore if we can't send the error
            conn.close()


if __name__ == "__main__":
    initialize_database()
    port = get_port_from_file()
    server_loop(port)
