import socket
from threading import Thread
import random
import os

import rsa
import main

IP="127.0.0.1"
PORT=random.randint(20000, 65535)
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.bind((IP,PORT))

option_select=False
rsa_public_key, rsa_private_key=rsa.generate_keys(512)

aes_key_self=os.urandom(8).hex()
print(aes_key_self)
self_aes=main.AES()
self_aes.create_key(aes_key_self)


def listen():
    client_socket.listen(1)
    local_conn, local_addr = client_socket.accept()
    local_option = True
    return local_conn, local_addr, local_option

def connect(ip="127.0.0.1", port=12345):
    try:
        client_socket.connect((ip,port))
        print("Connected!")
        local_option = True
    except:
        print("Cannot connect")
        local_option= False
    return local_option

def receiver(conn):
    while True:
        received_message = conn.recv(1024).decode('latin-1')
        print(received_message)
        print(f"Received message length: {len(received_message)}")

        size16blocks = len(received_message) // 16
        if len(received_message) % 16 != 0:
            size16blocks += 1

        decrypted_message = ""

        for i in range(size16blocks):
            message_block = received_message[i*16 : (i+1)*16]

            self_aes.create_state(message_block)
            self_aes.create_key(aes_key_self)
            print(f"AES Key = {self_aes.key}")
            self_aes.decipher()
            #print(self_aes)
            decrypted_block = main.hex_mat_to_ascii(self_aes.state)
            #print(f"Decrypted block {i}: {decrypted_block}")
            if i == size16blocks - 1:
                decrypted_block = remove_padding_from_string(decrypted_block)

            #print(f"Decrypted block {i}: {repr(decrypted_block)}")

            decrypted_message += decrypted_block

        if decrypted_message.strip().lower() == "exit":
            print("Client disconnected")
            break

        print("Other Side:", decrypted_message)



def sender(conn):
    while True:
        message_to_send = input()

        size16blocks = len(message_to_send) // 16
        if len(message_to_send) % 16 != 0:
            size16blocks += 1

        crypted_message = ""

        for i in range(size16blocks):
            message_block = message_to_send[i * 16: (i + 1) * 16]

            # Manually pad last block if needed
            # if len(message_block) < 16:
            #     pad_len = 16 - len(message_block)
            #     message_block += chr(pad_len) * pad_len

            #print(f"Block {i}: {repr(message_block)}")
            other_AES.create_state(message_block)
            other_AES.create_key(recv_aes_key)
            print(f"AES Key = {other_AES.key}")
            #print(f"Message block {i}: {main.hex_mat_to_ascii(other_AES.state)}")
            other_AES.cipher()
            encrypted_block = main.hex_mat_to_ascii(other_AES.state)
            print(other_AES)

            crypted_message += encrypted_block
            #print(f"Encrypted block {i}: {encrypted_block}")

        print(f"Final encrypted message length: {len(crypted_message)}")

        # Send encrypted string (encode as bytes)
        print(crypted_message)
        conn.sendall(crypted_message.encode('latin-1'))  # or utf-8 if safe


def remove_padding_from_string(padded_text):
    pad_char = padded_text[-1]
    pad_len = ord(pad_char)
    print(f"[DEBUG] Padding char: {repr(pad_char)}, ord: {pad_len}")

    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding length")

    if padded_text[-pad_len:] != pad_char * pad_len:
        raise ValueError("Invalid padding characters")

    return padded_text[:-pad_len]



print(IP," ",PORT)
conn=""
recv_rsa_public_key=""
recv_aes_key = ""
other_AES = main.AES()
while not option_select:
    option=input("CONNECT/LISTEN").upper()
    if option=="CONNECT":
        option_select=connect(IP,int(input("PORT: ")))
        conn=client_socket

        # RSA EXCHANGE KEY (OTHER)
        data=conn.recv(1024)
        recv_rsa_public_key = rsa.format_json_key_to_tuple(data)


        # RSA EXCHANGE KEY (SELF)
        conn.send(rsa.json_key(rsa_public_key).encode('utf-8'))

        # AES EXCHANGE KEY (OTHER)

        encrypted_self_rsa_aes_key=int(conn.recv(1024).decode('utf-8'))
        recv_aes_key = rsa.decrypt_string(encrypted_self_rsa_aes_key, rsa_private_key)

        # AES EXCHANGE KEY (SELF)

        encrypted_other_rsa_aes_key = rsa.encrypt_string(aes_key_self, recv_rsa_public_key)
        conn.send(str(encrypted_other_rsa_aes_key).encode('utf-8'))


    elif option=="LISTEN":

        conn, addr, option_select = listen()

        # RSA EXCHANGE KEY (SELF)
        conn.send(rsa.json_key(rsa_public_key).encode('utf-8'))

        # RSA EXCHANGE KEY (OTHER)
        data=conn.recv(1024)
        recv_rsa_public_key = rsa.format_json_key_to_tuple(data)

        # AES EXCHANGE KEY (SELF)

        encrypted_other_rsa_aes_key = rsa.encrypt_string(aes_key_self, recv_rsa_public_key)
        conn.send(str(encrypted_other_rsa_aes_key).encode('utf-8'))

        # AES EXCHANGE KEY (OTHER)

        encrypted_self_rsa_aes_key=int(conn.recv(1024).decode('utf-8'))
        recv_aes_key = rsa.decrypt_string(encrypted_self_rsa_aes_key, rsa_private_key)

        print(addr)




thread = Thread(target=receiver, args=(conn, ))
thread.start()
sender(conn)
# while True:
#     message_to_send = input("You: ")
#     client_socket.sendall(message_to_send.encode())
#
#     if message_to_send.lower() == "exit":
#         print("Disconnected from server")
#         break
#
#     received_message = client_socket.recv(1024).decode()
#     print("Server:", received_message)

client_socket.close()
