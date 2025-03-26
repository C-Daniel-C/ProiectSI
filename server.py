import socket
from threading import Thread

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("127.0.0.1", 12345))
server_socket.listen(1)

conn, addr = server_socket.accept()
print("Connected to:", addr)

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
        print("\n")
        conn.sendall(message_to_send.encode())

thread = Thread(target=receiver, args=(conn, ))
thread.start()
sender(conn)

conn.close()
server_socket.close()
