#!/usr/bin/env python3

try:
    import tkinter
    from tkinter import *
    from fbchat import log, Client
    from fbchat.models import *
    import time
    import threading
    from enum import Enum
    from Cryptography import *
    from Keystore import *
except ImportError as e:
    print(e)
    sys.exit()


#================================= MESSAGE TYPES =================================#

class MsgType(Enum):
    RAW_MESSAGE = "rawMessage"
    PUBLIC_KEY = "publicKey"
    SHARED_KEY = "sharedKey"
    CIPHER_TEXT = "cipherText"
    KEY_ESTABLISHED = "keyACK"

#============================= FACEBOOK INTERFACE CLASS =========================#

class FacebookClient(Client):
    def onMessage(self, author_id, message_object, thread_id, thread_type, **kwargs):
        self.markAsDelivered(thread_id, message_object.uid)
        self.markAsRead(thread_id)
        receive(1)

def listen():
    ''' Thread to listen to listen for new messages '''
    client.listen()

#================================= MESSENGER HELPERS =================================#


def parseMessage(message):
    ''' Get Message Type '''
    tags = message.split(":::")
    if len(tags) < 3:
        return message, MsgType.RAW_MESSAGE
    if tags[0] == tags[2]:
        return tags[1], MsgType(tags[0])

def packMessage(message, type):
    ''' Pack Message with message type '''
    try:
        return type.value + ":::" + message + ":::" + type.value
    except TypeError:
        return type.value + ":::" + message.decode("utf-8") + ":::" + type.value

def grabMesseges(limit):
    """ retreive last messeges by limit count """
    try:
        return client.fetchThreadMessages(thread_id=receiver.uid, limit=limit)
    except FBchatException:
        return []

def sendMessage(message,receiverUID):
    """ send message to received """
    client.send(Message(text=message), thread_id=receiverUID, thread_type=ThreadType.USER)

def sendHandshake():
    """ send initial handshake """
    pem_pubKey = serializeKey(pubKey, 'public')
    message = packMessage(pem_pubKey, MsgType.PUBLIC_KEY)
    sendMessage(message,receiver.uid)
    initializeMessage = Message(text='|----------------------SENT INITIALIZATION REQUEST---------------------|')
    initializeMessage.author = 'message'
    printMessages([initializeMessage])

def sendSharedKey(pubKey):
    """ send shared key ecrypted by received public key """
    sharedKey = generateSharedKey()
    encryptSharedKey_ = encryptSharedKey(sharedKey,pubKey)
    message = packMessage(encryptSharedKey_, MsgType.SHARED_KEY)
    keyStoreHandle.setKeyfor(receiver.uid, sharedKey)
    sendMessage(message,receiver.uid)

def handleSharedKey(sharedKey):
    """ receive and decrypt shared key sent by receiver"""
    decryptedSharedKey = decryptSharedKey(sharedKey,privKey)
    keyStoreHandle.setKeyfor(receiver.uid, decryptedSharedKey)
    keyStoreHandle.ackKeyfor(receiver.uid)
    message = packMessage('', MsgType.KEY_ESTABLISHED)
    time.sleep(5)
    sendMessage(message,receiver.uid)

def handleKeyACK():
    """ set key acknolegded status for shared key"""
    keyStoreHandle.ackKeyfor(receiver.uid)

def receive(limit):
    """ recrive and messages and take action based on message type"""
    messages = grabMesseges(limit)
    messageList = []

    for message in messages:
        msg, tag = parseMessage(message.text)
        key, ack = keyStoreHandle.getKeyfor(receiver.uid)

        if tag is MsgType.RAW_MESSAGE:
            message.text = "UnEncrypted: " + message.text
            messageList.append(message)

        if tag is MsgType.SHARED_KEY and message.author == receiver.uid and key is None: 
            handleSharedKey(msg)

            message = Message(text="|---------------------------KEY ESTABLISHED---------------------------|")
            message.author = 'message'
            messageList.append(message)
            message = Message(text="|-------------------------RECEIVED SHARED KEY-------------------------|")
            message.author = 'message'
            messageList.append(message)

        if tag is MsgType.PUBLIC_KEY and message.author == receiver.uid and key is None: 
            receiver_pubkey = loadKey(msg.encode("utf-8") , 'public')
            sendSharedKey(receiver_pubkey)

            message = Message(text="|--------------------SHARED KEY SENT - AWAITING ACK-------------------|")
            message.author = 'message'
            messageList.append(message)
            message = Message(text="|--------------------RECEIVED INITIALIZATION REQUEST------------------|")
            message.author = 'message'
            messageList.append(message)

        if tag is MsgType.KEY_ESTABLISHED and message.author == receiver.uid and ack is not True : 
            message.text = "|---------------------------KEY ESTABLISHED---------------------------|"
            message.author = 'message'
            handleKeyACK()
            messageList.append(message)

        if tag is MsgType.CIPHER_TEXT:
            sharedKey, ack = keyStoreHandle.getKeyfor(receiver.uid)
            if sharedKey is None or ack is None or ack is False:
                message.text = "Decrypt Error: Shared Key not established"
            else:
                message.text = verify_decrypt(sharedKey, msg, int(message.timestamp))
            messageList.append(message)
    printMessages(messageList)



def printMessages(messages):
    ''' print messages on the chat screen '''
    messages.reverse()

    for message in messages:
        if message.author is 'message':
            msg = message.text
        else:
            msg = "{} : {}".format(participantNames[message.author],message.text)

        msg_list.insert(tkinter.END, msg)
        msg_list.select_clear(msg_list.size() - 2)   #Clear the current selected item     
        msg_list.select_set(END)                             #Select the new item
        msg_list.yview(END)  


def send(event=None): 
    """ Retrieve message in the text box and ecrypt it before sending it to receiver"""
    msg = my_msg.get()
    my_msg.set("")

    sharedKey, ack = keyStoreHandle.getKeyfor(receiver.uid)
    if sharedKey is None or ack is None or ack is False:
        message = packMessage("Encrypt Error: Shared Key not established", MsgType.RAW_MESSAGE)
    else:
        message = packMessage(encrypt_mac(sharedKey, msg), MsgType.CIPHER_TEXT)
    sendMessage(message,receiver.uid)

def on_closing(event=None):
    """This function is to be called when the window is closed."""
    print("#================EXITING APPLICATION...=================#")
    tkHandle.destroy()
    client.stopListening()
    client.logout()


# #================================= MAIN =================================#


def main(): 
    ''' global data points to be used by the methods above'''
    global msg_list
    global my_msg
    global tkHandle
    global client
    global receiver
    global sender
    global participantNames
    global keyStoreHandle
    global privKey
    global pubKey

    # Login to Facebook Messenger with user provided username/password
    while True:
        username = input("Facebook Username:")
        password = input("Facebook password:")
        try:
            client = FacebookClient(username, password)
            if client.isLoggedIn():
                break
        except FBchatUserError:
            print("Invalid username/password provided")

    # select messenger contact to be the receiver
    while True:
        recipientName = input("\n\nFull name of Messenger Contact:")
        receiver = client.searchForUsers(recipientName)
        if receiver:
            # retrieve receiver client's user object
            receiver = receiver[0]

            confirm = input("\nConfirm Messenger Contact: " + receiver.name + " Y/N")
            if confirm.lower() in ["y","yes"]:
                break

        print("Friend not found please try again.")

    # retrieve sender client's user object
    sender = client.fetchUserInfo(client.uid)[client.uid]

    # Collect participant names, this is an efficiency measure 
    participantNames = {}
    participantNames[client.uid] = sender.name
    participantNames[receiver.uid] = receiver.name

    # retrieve user RSA key if already defined in DB
    # if not a new pair is generated and stored in the DB
    keyStoreHandle = KeyStore(sender.uid)
    if keyStoreHandle.getKeyPair() is None:
        privKey = generatePrivateKey()
        keyStoreHandle.savePrivateKey(privKey)
        privKey, pubKey = keyStoreHandle.getKeyPair()
    else:
        privKey, pubKey = keyStoreHandle.getKeyPair()


    #============================= SETUP GUI ============================#

    tkHandle = tkinter.Tk()
    tkHandle.title(sender.name + "->" + receiver.name)
    messages_frame = tkinter.Frame(tkHandle)
    my_msg = tkinter.StringVar()
    my_msg.set("Type your messages here.")
    scrollbar = tkinter.Scrollbar(messages_frame)
    msg_list = tkinter.Listbox(messages_frame, height=20, width=100)
    scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
    msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
    msg_list.configure(yscrollcommand = scrollbar.set)
    scrollbar.configure(command = msg_list.yview)
    msg_list.pack()
    messages_frame.pack()
    entry_field = tkinter.Entry(tkHandle, textvariable=my_msg)
    entry_field.bind("<Return>", send)
    entry_field.pack()
    tkHandle.protocol("WM_DELETE_WINDOW", on_closing)


    #============================= START MESSENGER ============================#

    # retrieve last messages 
    receive(1000)

    # start Listening thread
    listenThread = threading.Thread(target=listen)
    listenThread.start()

    # if receiver session was never initialized, initialize session
    if keyStoreHandle.getInitializedFor(receiver.uid) is False:
        sendHandshake()
        keyStoreHandle.setInitializedFor(receiver.uid)

    # Starts GUI execution.
    tkinter.mainloop()

if __name__ == '__main__':
    main()