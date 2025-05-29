import socket
import sys
from threading import Thread
import random
import os

import rsa
import main
import mainUI
from PyQt5.QtWidgets import QApplication, QDialog


class CommunicatorWindow(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = mainUI.Ui_Dialog()
        self.ui.setupUi(self)

        self.other_conn=""
        self.my_conn=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.ui.chatBox.setText("")

        self.ui.connectButton.clicked.connect(self.connect)
        self.ui.listenButton.clicked.connect(self.listen)
        self.ui.sendButton.clicked.connect(self.sender)

        self.IP = "127.0.0.1"
        self.PORT = random.randint(20000, 65535)

        self.ui.myPortNumber.setText(str(self.PORT))

        self.my_conn.bind((self.IP, self.PORT))

        self.rsa_public_key, self.rsa_private_key = rsa.generate_keys(512)

        self.aes_key_self = os.urandom(8).hex()
        self.self_aes = main.AES()
        self.self_aes.create_key(self.aes_key_self)

        print(IP, " ", PORT)

        self.recv_rsa_public_key = ""
        self.recv_aes_key = ""
        self.other_AES = main.AES()

    def __del__(self):
        self.other_conn.close()

    def listen(self):
        self.my_conn.listen(1)
        local_conn, local_addr = self.my_conn.accept()
        local_option = True

        # RSA EXCHANGE KEY (SELF)
        local_conn.send(rsa.json_key(rsa_public_key).encode('utf-8'))
        print(f"Sent my RSA Key to Other!")

        # RSA EXCHANGE KEY (OTHER)
        data = local_conn.recv(1024)
        self.recv_rsa_public_key = rsa.format_json_key_to_tuple(data)
        print(f"Obtained the RSA Key from Other!")

        # AES EXCHANGE KEY (SELF)

        encrypted_other_rsa_aes_key = rsa.encrypt_string(self.aes_key_self, self.recv_rsa_public_key)
        local_conn.send(str(encrypted_other_rsa_aes_key).encode('utf-8'))
        print(f"Sent my AES Key to Other!")

        # AES EXCHANGE KEY (OTHER)

        encrypted_self_rsa_aes_key = int(local_conn.recv(1024).decode('utf-8'))
        self.recv_aes_key = rsa.decrypt_string(encrypted_self_rsa_aes_key, rsa_private_key)
        print(f"Obtained the AES Key from Other!")

        self.other_conn = local_conn

        thread = Thread(target=self.receiver, args=(self.other_conn,))
        thread.start()


    def connect(self,ip="127.0.0.1", port=12345):
        try:
            connect_port= int(self.ui.portInput.toPlainText())
            print(f"Connect Port: {connect_port}")
            self.my_conn.connect((self.IP, connect_port))
            print("Connected!")

            conn = self.my_conn

            # RSA EXCHANGE KEY (OTHER)
            data = conn.recv(1024)
            recv_rsa_public_key = rsa.format_json_key_to_tuple(data)
            print(f"Obtained the RSA Key from Other!")

            # RSA EXCHANGE KEY (SELF)
            conn.send(rsa.json_key(rsa_public_key).encode('utf-8'))
            print(f"Sent my RSA Key to Other!")
            # AES EXCHANGE KEY (OTHER)

            encrypted_self_rsa_aes_key = int(conn.recv(1024).decode('utf-8'))
            self.recv_aes_key = rsa.decrypt_string(encrypted_self_rsa_aes_key, rsa_private_key)
            print(f"Obtained the AES Key from Other!")
            # AES EXCHANGE KEY (SELF)

            encrypted_other_rsa_aes_key = rsa.encrypt_string(self.aes_key_self, recv_rsa_public_key)
            conn.send(str(encrypted_other_rsa_aes_key).encode('utf-8'))
            print(f"Sent my AES Key to Other!")

            self.other_conn = conn
            thread = Thread(target=self.receiver, args=(window.other_conn,))
            thread.start()
        except:
            print("Cannot connect")


    def receiver(self, conn):
        while True:
            received_message = window.other_conn.recv(1024).decode('latin-1')
            print(received_message)
            print(f"Received message length: {len(received_message)}")

            size16blocks = len(received_message) // 16
            if len(received_message) % 16 != 0:
                size16blocks += 1

            decrypted_message = ""

            for i in range(size16blocks):
                message_block = received_message[i * 16: (i + 1) * 16]

                self.self_aes.create_state(message_block)
                self.self_aes.create_key(self.aes_key_self)
                print(f"AES Key = {self.self_aes.key}")
                self.self_aes.decipher()
                # print(self_aes)
                decrypted_block = main.hex_mat_to_ascii(self.self_aes.state)
                # print(f"Decrypted block {i}: {decrypted_block}")
                if i == size16blocks - 1:
                    decrypted_block = self.remove_padding_from_string(decrypted_block)

                # print(f"Decrypted block {i}: {repr(decrypted_block)}")

                decrypted_message += decrypted_block

            if decrypted_message.strip().lower() == "exit":
                print("Client disconnected")
                break

            window.ui.chatBox.setText(f"{window.ui.chatBox.text()} \nOther Side: {decrypted_message}")
            print("Other Side:", decrypted_message)


    def sender(self):
        message_to_send = window.ui.textInput.toPlainText()
        window.ui.chatBox.setText(f"{window.ui.chatBox.text()}\nMe: {message_to_send}")

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

            # print(f"Block {i}: {repr(message_block)}")
            self.other_AES.create_state(message_block)
            self.other_AES.create_key(self.recv_aes_key)
            print(f"AES Key = {self.other_AES.key}")
            # print(f"Message block {i}: {main.hex_mat_to_ascii(other_AES.state)}")
            self.other_AES.cipher()
            encrypted_block = main.hex_mat_to_ascii(self.other_AES.state)
            print(self.other_AES)

            crypted_message += encrypted_block
            # print(f"Encrypted block {i}: {encrypted_block}")

        print(f"Final encrypted message length: {len(crypted_message)}")

        # Send encrypted string (encode as bytes)
        print(crypted_message)
        self.other_conn.sendall(crypted_message.encode('latin-1'))  # or utf-8 if safe
        print("A Message has been sent!")


    def remove_padding_from_string(self, padded_text):
        pad_char = padded_text[-1]
        pad_len = ord(pad_char)
        print(f"[DEBUG] Padding char: {repr(pad_char)}, ord: {pad_len}")

        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding length")

        if padded_text[-pad_len:] != pad_char * pad_len:
            raise ValueError("Invalid padding characters")

        return padded_text[:-pad_len]

IP="127.0.0.1"
PORT=random.randint(20000, 65535)
# client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# client_socket.bind((IP,PORT))



option_select=False
rsa_public_key, rsa_private_key=rsa.generate_keys(512)
app = QApplication(sys.argv)
window = CommunicatorWindow()
window.show()

# # window.my_conn=client_socket
# aes_key_self=os.urandom(8).hex()
# self_aes=main.AES()
# self_aes.create_key(aes_key_self)

# print(IP," ",PORT)
# conn=""
# recv_rsa_public_key=""
# recv_aes_key = ""
# other_AES = main.AES()


# while not option_select:
#     option=input("CONNECT/LISTEN").upper()
#     if option=="CONNECT":
#         option_select=connect(IP,int(input("PORT: ")))
#         conn=client_socket
#
#         # RSA EXCHANGE KEY (OTHER)
#         data=conn.recv(1024)
#         recv_rsa_public_key = rsa.format_json_key_to_tuple(data)
#
#
#         # RSA EXCHANGE KEY (SELF)
#         conn.send(rsa.json_key(rsa_public_key).encode('utf-8'))
#
#         # AES EXCHANGE KEY (OTHER)
#
#         encrypted_self_rsa_aes_key=int(conn.recv(1024).decode('utf-8'))
#         recv_aes_key = rsa.decrypt_string(encrypted_self_rsa_aes_key, rsa_private_key)
#
#         # AES EXCHANGE KEY (SELF)
#
#         encrypted_other_rsa_aes_key = rsa.encrypt_string(aes_key_self, recv_rsa_public_key)
#         conn.send(str(encrypted_other_rsa_aes_key).encode('utf-8'))
#
#
#     elif option=="LISTEN":
#
#         conn, addr, option_select = listen()
#
#         # RSA EXCHANGE KEY (SELF)
#         conn.send(rsa.json_key(rsa_public_key).encode('utf-8'))
#
#         # RSA EXCHANGE KEY (OTHER)
#         data=conn.recv(1024)
#         recv_rsa_public_key = rsa.format_json_key_to_tuple(data)
#
#         # AES EXCHANGE KEY (SELF)
#
#         encrypted_other_rsa_aes_key = rsa.encrypt_string(aes_key_self, recv_rsa_public_key)
#         conn.send(str(encrypted_other_rsa_aes_key).encode('utf-8'))
#
#         # AES EXCHANGE KEY (OTHER)
#
#         encrypted_self_rsa_aes_key=int(conn.recv(1024).decode('utf-8'))
#         recv_aes_key = rsa.decrypt_string(encrypted_self_rsa_aes_key, rsa_private_key)
#
#         print(addr)


sys.exit(app.exec_())
# sender(conn)
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
