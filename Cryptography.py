try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, hmac, padding, serialization
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    import os, sys, time, struct
except ImportError as e:
    print(e)
    sys.exit()

# Generated Key length in bytes
KEY_SIZE = 32

# Key Split offset to grab encryption key and mac key
SPLIT = 16

# time for message arrival to check for replay attacks
TTL = 10

backend = default_backend()


def encrypt_mac(key,plainText):
    ''' encrypt plaintext with specified key and calculate mac'''
    try:
        plainText = plainText.encode('utf-8')

        # generate 16 bit random IV 
        iv = os.urandom(16)

        # grab message time
        msg_time = struct.pack(">Q", int(time.time()))

        #split generated key to encryption key and mac key
        key, mac_key  = bytes((key[0:SPLIT])), bytes((key[SPLIT:]))

        # define encryptor params
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()

        # define hmac params
        h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())

        # define padder
        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        # add padding to message
        plainText = padder.update(plainText) + padder.finalize()

        # encrypt plaintext
        cipherText = encryptor.update(plainText) + encryptor.finalize()

        # pack ciphertext with messagetime and IV for hmac
        package = msg_time + iv + cipherText

        #generate hmac
        h.update(package)
        package_mac = h.copy().finalize()

        # pack cipherText to be sent with messagetime, IV and hmac
        cipherText = bytearray(msg_time+iv+package_mac+cipherText).hex()
    except:
        return False
    return cipherText


def verify_decrypt(key, cipherText, fbMsgTimestamp):
    '''verify cipherText with hmac and check for replay attack and then decrypt the message'''
    
    # if message is a unencrypted message return the message
    try:
        bytes(bytearray.fromhex(cipherText))
    except ValueError:
        return cipherText

    # parse out keys data points
    key, macKey = bytes((key[0:SPLIT])), bytes((key[SPLIT:]))
    msg_time    = bytes(bytearray.fromhex(cipherText[0:16]))
    iv          = bytes(bytearray.fromhex(cipherText[16:48]))
    packageMac  = bytes(bytearray.fromhex(cipherText[48:112]))
    cipherText  = bytes(bytearray.fromhex(cipherText[112:]))

    # define decryptor params
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    
    # define hmac params
    h         = hmac.HMAC(macKey, hashes.SHA256(), backend=default_backend())

    # define unpadder
    unpadder  = padding.PKCS7(algorithms.AES.block_size).unpadder()

    # decrypt plaintext
    try:
        plaintext = decryptor.update(cipherText)
        plaintext = unpadder.update(plaintext) + unpadder.finalize()
    except:
        return "Decrypt Error"

    # check for message integrity
    # is unverified message found return plaintext with 'Integrity Attack Detected' warning
    try:
        h.update(msg_time + iv + cipherText)
        h.copy().verify(packageMac)
    except InvalidSignature:
        return "Unauthenticated Message(Integrity Attack Detected): %s" %plaintext.decode('utf-8')

    # check for replay attack
    # is unverified message found return plaintext with 'Replay Attack Detected' warning
    try:
        msg_time, = struct.unpack(">Q", msg_time)
    except struct.error:
        return "Unauthenticated Message(Replay Attack Detected): %s" %plaintext.decode('utf-8')

    if msg_time + TTL < int(fbMsgTimestamp/1000):
        return "Unauthenticated Message(Replay Attack Detected): %s" %plaintext.decode('utf-8')

    return plaintext.decode('utf-8')


from cryptography.hazmat.primitives.asymmetric import padding as a_padding, rsa

def generatePrivateKey():
    '''generate RSA Key'''
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=3072,
    backend=default_backend()
    )
    return private_key

def generateSharedKey():
    ''' generate shared key '''
    return os.urandom(KEY_SIZE)

def encryptSharedKey(sharedKey,public_key):
    ''' encrypt shared key with specified publickey'''
    ciphertext = public_key.encrypt(
        sharedKey,
        a_padding.OAEP(
            mgf=a_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext.hex()

def decryptSharedKey(sharedKey,private_key):
    ''' decrypt shared key with specified privatekey'''
    plaintext = private_key.decrypt(
        bytes(bytearray.fromhex(sharedKey)),
        a_padding.OAEP(
            mgf=a_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def serializeKey(key, type):
    ''' serialize RSA key to PEM format for storage as text'''
    if type is 'private':
        return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
        )
    else:
        return key.public_bytes(
           encoding=serialization.Encoding.PEM,
           format=serialization.PublicFormat.SubjectPublicKeyInfo
        )


def loadKey(key,type):
    ''' load RSA key from PEM format'''
    if type is 'private':
        return serialization.load_pem_private_key(
            key,
            password=None,
            backend=default_backend()
        )
    else:
        return serialization.load_pem_public_key(
            key, 
            backend=default_backend()
        )

