try:
    import sqlite3
    from Cryptography import *
except ImportError as e:
    print(e)
    sys.exit()

class KeyStore:
    def __init__(self, senderUID):
        self.db = sqlite3.connect('secureFB_'+senderUID+'_DB', check_same_thread=False)
        self.cursor = self.db.cursor()
        
        # table for shared key storage
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS keyStore(id INTEGER PRIMARY KEY, UID TEXT,
                               INITIALIZED INT, SHARED_KEY TEXT, ESTABLISHED INT)
        ''')
        self.db.commit()

        # table for RSA key storage
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS rsa(id INTEGER PRIMARY KEY,
                               PRIVATEKEY TEXT)
        ''')
        self.db.commit()

    def getKeyfor(self,uid):
        ''' get shared key for specified receiver '''
        self.cursor.execute('''SELECT SHARED_KEY, ESTABLISHED FROM keystore WHERE UID=?''', (uid,))
        row = self.cursor.fetchone()
        if row is not None:
            return row[0], bool(row[1])
        else:
            return None, None

    def setKeyfor(self,uid,key):
        ''' set shared key for specified receiver '''
        self.cursor.execute('''SELECT SHARED_KEY, ESTABLISHED FROM keystore WHERE UID=?''', (uid,))
        row = self.cursor.fetchone()
        if row is None:
            self.cursor.execute('''INSERT INTO keystore(UID, INITIALIZED, SHARED_KEY, ESTABLISHED) VALUES(?,?,?,?)''', (uid, 1, key, 0))
        else:
            self.cursor.execute(''' UPDATE keystore
                                    SET SHARED_KEY = ? 
                                    WHERE UID = ?''', (key, uid))
        self.db.commit()

    def setInitializedFor(self,uid):
        ''' initialize record for specified receiver '''
        self.cursor.execute('''INSERT INTO keystore(UID, INITIALIZED)
                  VALUES(?,?)''', (uid, 1))
        self.db.commit()

    def getInitializedFor(self,uid):
        ''' check if specified receiver has been initialized'''
        self.cursor.execute('''SELECT INITIALIZED FROM keystore WHERE UID=?''', (uid,))
        row = self.cursor.fetchone()
        if row is not None:
            return bool(row[0])
        else:
            return False

    def ackKeyfor(self,uid):
        '''set acknowledged tag for specified receiver'''
        self.cursor.execute(''' UPDATE keystore
                                SET ESTABLISHED = ? 
                                WHERE UID = ?''', (1, uid))
        self.db.commit()

    def savePrivateKey(self, privKey):
        '''save generated private RSA key'''
        privKeyPem = serializeKey(privKey, 'private')

        self.cursor.execute('''INSERT INTO rsa(PRIVATEKEY)
                  VALUES(?)''', (privKeyPem,))
        self.db.commit()

    def getKeyPair(self):
        '''return retrieve and return private/public RSA key'''
        self.cursor.execute("SELECT PRIVATEKEY FROM rsa")
        privKey = self.cursor.fetchone()
        
        if privKey is None :
            return None

        private_key = loadKey(privKey[0], 'private')
        return private_key, private_key.public_key()