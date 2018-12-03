"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
            Minhchau
            Andre
            Brennon
            Paris
            Dominic
"""

import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


iv = "G4XO4L\X<J;MPPLD"

host = "localhost"
port = 10001

# open & save server's public key
f = open('../secret_keys/public.pem','r')
# server_public_key = RSA.importKey(f.read()).exportKey(format='PEM')
server_public_key = RSA.importKey(f.read())
f.close()

# A helper function that you may find useful for AES encryption
def pad_message(message):
    return message + " "*((16-len(message))%16)


# Generate a random AES key
def generate_key():
    return get_random_bytes(16)

# Takes an AES session key and encrypts it using the server's
# public key and returns the value
def encrypt_handshake(session_key):
    encryptor = PKCS1_OAEP.new(server_public_key)
    return encryptor.encrypt(session_key)


# TODO: Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    pass


# TODO: Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    pass


# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        session_key = generate_key()
        print('session key: {}'.format(session_key))

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(session_key)
        print('encrypted session key: {}'.format(encrypted_key))

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # TODO: Encrypt message and send to server

        # TODO: Receive and decrypt response from server and print

    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
