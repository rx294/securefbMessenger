#!/usr/bin/env python3
"""Script for Tkinter GUI chat client."""
from socket import AF_INET, socket, SOCK_STREAM
# from threading import Thread
import tkinter
from tkinter import *
from fbchat import log, Client
from fbchat import Client
from fbchat.models import *
import time
import threading


# Subclass fbchat.Client and override required methods
# class Listner(Client):
#     def onMessage(self, author_id, message_object, thread_id, thread_type, **kwargs):
#         self.markAsDelivered(thread_id, message_object.uid)
#         self.markAsRead(thread_id)
#         print(message_object.text)

# client = Listner('sinerhandern2@gmail.com', 'WbRcG5v8P514')
client = Client('sinerhandern2@gmail.com', 'WbRcG5v8P514')
sender = client.fetchUserInfo(client.uid)[client.uid]
receiver = client.searchForUsers('alice')[0]

names = {}
names[client.uid] = sender.name
names[receiver.uid] = receiver.name

# user = client.fetchUserInfo(messages[0].author)[messages[0].author].name

def syncMessages():
    while True:
        receive()
        time.sleep(5)

def receive():
    """Handles receiving of messages."""
    msg_list.delete(0, END)
    messages = client.fetchThreadMessages(thread_id=receiver.uid, limit=100)
    messages.reverse()
    for message in messages:
        msg = "{} : {}".format(names[message.author],message.text)
        msg_list.insert(tkinter.END, msg)

def send(event=None):  # event is passed by binders.
    """Handles sending of messages."""
    msg = my_msg.get()
    my_msg.set("")  # Clears input field.
    if msg == "{quit}":
        top.quit()
    if msg == "refresh":
        receive()
        return
    client.send(Message(text=msg), thread_id=receiver.uid, thread_type=ThreadType.USER)
    msg = "{} : {}".format(sender.name,msg)
    receive()



def on_closing(event=None):
    """This function is to be called when the window is closed."""
    my_msg.set("{quit}")
    send()

top = tkinter.Tk()
top.title("Bob")

messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()  # For the messages to be sent.
my_msg.set("Type your messages here.")
scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.
# Following will contain the messages.
msg_list = tkinter.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()

entry_field = tkinter.Entry(top, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack()
send_button = tkinter.Button(top, text="Send", command=send)
send_button.pack()

top.protocol("WM_DELETE_WINDOW", on_closing)
receive()
#----Now comes the sockets part----
# HOST = input('Enter host: ')
# PORT = input('Enter port: ')
# if not PORT:
#     PORT = 33000
# else:
#     PORT = int(PORT)

# BUFSIZ = 1024
# ADDR = (HOST, PORT)

# client_socket = socket(AF_INET, SOCK_STREAM)
# client_socket.connect(ADDR)
receive_thread = threading.Thread(target=syncMessages)
receive_thread.start()

tkinter.mainloop()  # Starts GUI execution.