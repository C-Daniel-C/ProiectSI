import socket
from threading import Thread

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("127.0.0.1", 12345))

def receiver(conn):
    while True:
        received_message = conn.recv(1024).decode()
        if received_message.lower() == "exit":
            print("Client disconnected")
            break
        print("Other Side:", received_message)

def sender(conn):
    while True:
        message_to_send = input()
        conn.sendall(message_to_send.encode())



thread = Thread(target=receiver, args=(client_socket, ))
thread.start()
sender(client_socket)
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
