import socket
from threading import Thread
import random
IP="127.0.0.1"
PORT=random.randint(20000, 65535)
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.bind((IP,PORT))

option_select=False

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
        received_message = conn.recv(1024).decode()
        try:
            if received_message.lower() == "exit":
                print("Client disconnected")
                break
            print("Other Side:", received_message)
        except:
            print("Message Error")

def sender(conn):
    while True:
        message_to_send = input()
        conn.sendall(message_to_send.encode())

print(IP," ",PORT)
conn=""
while not option_select:
    option=input("CONNECT/LISTEN")
    if option=="CONNECT":
        option_select=connect(IP,int(input("PORT: ")))
        conn=client_socket
    elif option=="LISTEN":
        conn,addr,option_select=listen()
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
