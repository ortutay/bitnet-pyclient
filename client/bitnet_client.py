#!/usr/bin/python

import base64
import binascii
import datetime
import ecdsa
import hashlib
import json
import logging
import os
import requests
import threading
import time

# Use PyCrypto for RSA, AES; may want to evaluate other libraries as well.
from Crypto import Random
from Crypto.Random import random as cryptorandom
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

_JSON_RPC_HEADERS = {"Content-Type": "application/json"}
# _DEFAULT_ADDR = "54.187.157.104:8555"
_DEFAULT_ADDR = "localhost:8555"

logging.basicConfig(format='%(levelname)s %(name)s %(asctime)-15s %(filename)s:%(lineno)d %(message)s')
_logger = logging.getLogger("bitnet")
# TODO(ortutay): set lower logger level for prod
_logger.setLevel(logging.INFO)

def SetLogLevel(level):
    _logger.setLevel(level)

# Stub Plugin, for when we are loading from Electrum wallet. No-op otherwise.
try:
    from electrum import BasePlugin
    class Plugin(BasePlugin):
        def fullname(self): return ''
        def description(self): return ''
        def is_available(self): return False
        def enable(self): return False
except:
    pass

class BitnetException(Exception):
    pass

class BitnetRPCException(BitnetException):
    pass

class BitnetClient:
    def __init__(self, data_dir=None, addr=_DEFAULT_ADDR):
        if not data_dir:
            data_dir = ".bitnet"
        data_path = "%s/%s" % (os.path.expanduser("~"), data_dir)

        try:
            os.makedirs(data_path)
        except OSError:
            pass

        id_key_path =  "%s/id.pem" % data_path
        msg_key_path =  "%s/msg.pem" % data_path
        self._client_data_path =  "%s/client_data.json" % data_path

        # ID key
        try:
            id_key_data = open(id_key_path, "r").read()
            self.id_key = ecdsa.SigningKey.from_pem(id_key_data)
        except IOError:
            bits = cryptorandom.getrandbits(256)
            k = binascii.unhexlify(hex(bits)[2:].rstrip("L"))
            secret = ecdsa.util.string_to_number(k)
            self.id_key = ecdsa.SigningKey.from_secret_exponent(
                secret, curve=ecdsa.curves.SECP256k1)
            open(id_key_path, "w").write(self.id_key.to_pem())

        # Messaging key
        try:
            msg_key_data = open(msg_key_path, "r").read()
            self.msg_key = RSA.importKey(msg_key_data)
        except IOError:
            # TODO(ortutay): use 4096 bits instead?
            self.msg_key = RSA.generate(2048, Random.new().read)
            msg_enc = self.msg_key.exportKey('PEM')
            open(msg_key_path, "w").write(msg_enc)


        self._listeners = {}
        self._next_listener_id = 1
        self._seen_messages = set([])
        try:
            self._data = json.loads(open(self._client_data_path, "r").read())
        except:
            self._data = {}
        self.url = "http://%s/bitnetRPC" % addr
        ClaimTokens(self.url, "", self.PubKeyStr(), "", "claimfree")

        # Store messaging key on server, if not already there.
        # TODO(ortutay): If expiration behavior is implemented in the future,
        # this code will need to be updated.
        msgs = self.Get({
            "from-pubkey": self.PubKeyStr(),
            "type": "bitnet.RSAPubKey",
        })
        if not msgs:
            self.Send(None, {
                "from-pubkey": self.PubKeyStr(),
                "type": "bitnet.RSAPubKey",
                "body": self.MsgPubKeyStr(),
            })

    def _StoreData(self):
        open(self._client_data_path, "w").write(json.dumps(self._data))

    def PubKeyStr(self):
        compressed = True
        point = self.id_key.privkey.public_key.point
        h = point_to_ser(point, compressed).encode('hex')
        return h

    def MsgPubKeyStr(self):
        return binascii.hexlify(self.msg_key.publickey().exportKey("DER"))

    def Tokens(self, amount):
        resp = Challenge(self.url)
        challenge = resp["result"]["Challenge"]
        signable = sha256(challenge + str(amount))
        sig = Sign(signable, self.id_key)
        tokens = {
            "Challenge": challenge,
            "Amount": amount,
            "PubKey": self.PubKeyStr(),
            "Sig": sig,
            }
        return tokens

    def SendPlain(self, to_pub_key, plaintext):
        # TODO(ortutay): implement
        pass

    def _GetAesPrivForSend(self, to_pub_key):
        if "pub_to_aes_priv" not in self._data:
            self._data["pub_to_aes_priv"] = {}
        if "rsa_pub_keys" not in self._data:
            self._data["rsa_pub_keys"] = {}

        print "DATA:", self._data

        # TODO(ortutay): Use one-off keys for each message.
        if to_pub_key in self._data["pub_to_aes_priv"]:
            return self._data["pub_to_aes_priv"][to_pub_key]
        
        if to_pub_key not in self._data["rsa_pub_keys"]:
            msgs = self.Get({
                "from-pubkey": to_pub_key,
                "type": "bitnet.RSAPubKey",
            })
            if not msgs:
                raise BitnetException("Couldn't get RSA pub key for %s" % to_pub_key)
            d = {}
            for msg in msgs:
                d[msg["Plaintext"]["Body"]] = 1
            if len(d) != 1:
                raise BitnetException("Expected 1 RSA pub key, got %d" % len(d))
            rsa_pub_key = msgs[0]["Plaintext"]["Body"]
        self._data["rsa_pub_keys"][to_pub_key] = rsa_pub_key

        # TODO(ortutay): Review this key generation code.
        # TODO(ortutay): Look at and choose appropriate options.
        bits = cryptorandom.getrandbits(256)
        aes_priv_hex = (hex(bits)[2:].rstrip("L")).rjust(32, "0")
        print "aes_priv_hex", aes_priv_hex
        k = binascii.unhexlify(aes_priv_hex)
        aes_key = AES.new(k)

        rsa_pub_key = RSA.importKey(binascii.unhexlify(rsa_pub_key))
        rsa_pub = PKCS1_OAEP.new(rsa_pub_key)

        ciphertext = rsa_pub.encrypt(aes_priv_hex)
        body = base64.b64encode(ciphertext)
        msg = {
            "to-pubkey": to_pub_key,
            "datetime": _Datetime(),
            "type": "bitnet.AESPrivKey",
            "encrypted-body": body,
        }
        print "send msg:", msg
        self.Send(None, msg)
        self._data["pub_to_aes_priv"][to_pub_key] = aes_priv_hex
        self._StoreData()
        return aes_priv_hex

    def SendEncrypted(self, to_pub_key, message):
        aes_priv_hex = self._GetAesPrivForSend(to_pub_key)
        to_priv_key_hash = _AESPrivKeyHash(aes_priv_hex)
        aes_priv = binascii.unhexlify(aes_priv_hex)
        aes_cipher = AESCipher(aes_priv)
        encrypted = base64.b64encode(aes_cipher.encrypt(message))
        print "aes priv hex:", aes_priv_hex
        re_plaintext = aes_cipher.decrypt(base64.b64decode(encrypted))
        print "re plaintxt:", re_plaintext
        # TODO(ortutay): handle message headers
        self.Send(None, {
            "type": "bitnet.AESEncrypted",
            "datetime": _Datetime(),
            "to": str(to_priv_key_hash),
            "encrypted-body": encrypted,
        })
    
    def Send(self, to_pub_key, message):
        # TODO(ortutay): Cached-pull of recepients privkey, and then encrypt.
        # TODO(ortutay): Default to encryption, and allow plaintext send only
        # with explicit override.
        if not ("body" in message or "encrypted-body" in message):
            message = {
                "type": "bitnet.Plain",
                "datetime": _Datetime(),
                "to-pubkey": str(to_pub_key),
                "from-pubkey": self.PubKeyStr(),
                "body": str(message),
            }
        # if "encrypted_body" in message:
        #     raise Exception("Message encryption not yet implemented")

        headers = dict()
        body, encrypted_body = "", ""
        for key in message:
            if key == "body":
                body = message[key]
                continue
            elif key == "encrypted-body":
                encrypted_body = message[key]
                continue
            vals = []
            if isinstance(message[key], basestring):
                vals = [message[key]]
            else:
                print key
                print message[key]
                for val in message[key]:
                    val += message[key]
            headers[key] = vals
        message = {
            "Plaintext": {
                "Headers": headers,
                "Body": body,
            },
            "Encrypted": encrypted_body,
        }
            
        tokens = self.Tokens(-1)
        # TODO(ortutay): In Python, might be better to "raise" here.
        return StoreMessage(self.url, tokens, message)

    def Get(self, query=None):
        # Do not mutate passed query
        if query:
            query = dict(query)

        if not query:
            query = {"to-pubkey": self.PubKeyStr()}

        # Get plaintext
        tokens = self.Tokens(-1)
        resp = GetMessages(self.url, tokens, {"Headers": query})
        print "get plaintext got", resp
        plaintext_msgs = []
        try:
            plaintext_msgs = resp["result"]["Messages"]
        except:
            pass

        # Get encrypted
        encrypted_msgs = self._GetEncrypted(query)
        print "get encrypted got", encrypted_msgs

        return plaintext_msgs + encrypted_msgs

    def _GetEncrypted(self, query=None):
        # Do not mutate passed query
        if query:
            query = dict(query)

        if not query:
            query = {}

        # TODO(ortutay): Think of better approach here
        if "to-pubkey" in query:
            del query["to-pubkey"]

        print "get encrypted", query

        base_query = dict(query)

        tokens = self.Tokens(-1)

        # TODO(ortutay): This code is very inefficient, especially as we rack
        # up a large number of AES private keys. We should add the ability to
        # "or" together queries, and also to use a bloom filter to in queries.
        aes_privs_query = dict(base_query)
        aes_privs_query["to-pubkey"] = self.PubKeyStr()
        aes_privs_query["type"] = "bitnet.AESPrivKey"
        print "aes privs query", aes_privs_query
        resp = GetMessages(self.url, tokens, {"Headers": aes_privs_query})
        try:
            aes_privs_msgs = resp["result"]["Messages"]
        except:
            aes_privs_msgs = []

        print "enc resp", resp
        print "aes privs msgs", aes_privs_msgs

        rsa_cipher = PKCS1_OAEP.new(self.msg_key)
        if aes_privs_msgs:
            for msg in aes_privs_msgs:
                try:
                    aes_priv_encrypted = msg["Encrypted"]
                except KeyError:
                    continue
                try:
                    aes_priv_hex = rsa_cipher.decrypt(
                        base64.b64decode(aes_priv_encrypted))
                except Exception as e:
                    _logger.error("Couldn't decrypt AES private key %s: %s" %
                                  (aes_priv_encrypted, str(e)))

                if "aes_privs" not in self._data:
                    self._data["aes_privs"] = []
                if aes_priv_hex not in self._data["aes_privs"]:
                    self._data["aes_privs"].append(aes_priv_hex)
            self._StoreData()

        if "aes_privs" not in self._data:
            return []

        ret_msgs = []
        for aes_priv_hex in self._data["aes_privs"]:
            aes_priv = binascii.unhexlify(aes_priv_hex)
            aes_cipher = AESCipher(aes_priv)
            print "aes_priv_hex:", aes_priv_hex
            query = dict(base_query)
            query["type"] = "bitnet.AESEncrypted"
            query["to"] = _AESPrivKeyHash(aes_priv_hex)
            print "aes encrypted query", query
            resp = GetMessages(self.url, tokens, {"Headers": query})
            msgs = resp["result"]["Messages"]
            for msg in msgs:
                ciphertext = msg["Encrypted"]
                plaintext = aes_cipher.decrypt(base64.b64decode(ciphertext))
                print "got plaintext:", plaintext, " from ", ciphertext, "using", aes_priv_hex
                msg["Encrypted"] = {"Body": plaintext}
                ret_msgs.append(msg)
            # print resp

        print "returning", ret_msgs
        return ret_msgs

    # Receive new messages.
    # Overrides "datetime >" field in query.
    def Listen(self, handler, query=None):
        # Do not mutate passed query
        if query:
            query = dict(query)

        print "Listen query:", query
        if not query:
            query = {"to-pubkey": self.PubKeyStr()}
        print "Listen query2:", query
        # Server currently does not charge for "GetMessages" RPC
        tokens = self.Tokens(-1)

        # TODO(ortutay): Once we are using Web sockets instead of polling, this
        # part shouldn't be necessary.
        print "3 query", query
        current_msgs = self.Get(query)
        print "4 query", query
        datetime_gt = None
        if current_msgs:
            datetime_gt = _MostRecentDatetime(current_msgs)

        def periodic_poll(client, url, handler, tokens, query, datetime_gt):
            print "peridoc_poll query", query
            while True:
                try:
                    if datetime_gt:
                        query["datetime >"] = datetime_gt.isoformat("T") + "Z"
                    print "calling GetMessages", query
                    resp = GetMessages(url, tokens, {"Headers": query})
                    print "GetMessages resp", resp
                    encrypted_msgs = self._GetEncrypted(query)

                    # Following is skipped if GetMessages or _GetEncrypted
                    # raises exception
                    msgs = resp["result"]["Messages"] + encrypted_msgs
                    if msgs:
                        datetime_gt = _MostRecentDatetime(msgs)
                except BitnetRPCException as e:
                    _logger.error("Error on GetMessages(%s, %s): %s" % (
                        tokens, query, str(e)))
                    continue
                for msg in msgs:
                    try: 
                        h = msg["Plaintext"]["Headers"]["message-hash"][0]
                        if h in client._seen_messages:
                            continue
                        client._seen_messages.add(h)
                    except Exception:
                        pass
                    handler(msg)
                time.sleep(5)
        id = "get-messages-poll-%d" % self._next_listener_id
        self._next_listener_id += 1
        print "passing query", query
        thr = threading.Thread(
            group=None, target=periodic_poll, name=id,
            args=(self, self.url, handler, tokens, query, datetime_gt))
        thr.daemon = True
        thr.start()
        return id

    def StopListening(self, id):
        # TODO(ortutay): implement
        pass

# Mutates the list
def _MostRecentDatetime(msgs):
    if not msgs:
        return None
    msgs.sort(key=_MessageDatetimeKey, reverse=True)
    try:
        dt_str = msgs[0]["Plaintext"]["Headers"]["datetime"][0]
        return _ParseRFC3339(dt_str)
    except Exception:
        return None

def _MessageDatetimeKey(msg):
    try:
        dt_str = msg["Plaintext"]["Headers"]["datetime"][0]
    except Exception:
        return 0
    dt = _ParseRFC3339(dt_str)
    return int(dt.strftime("%s"))

def _ParseRFC3339(dt_str):
    dt_str = dt_str.rstrip("Z")
    dt = datetime.datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S.%f")
    return dt

def Challenge(url):
    req = {
        "method": "Bitnet.Challenge",
        "params": [{}],
        "id": 0,
        }
    return _DoRPC(url, req)

def ClaimTokens(url, challenge, pub_key, bitcoin_address, sig):
    req = {
        "method": "Bitnet.ClaimTokens",
        "params": [{
            "Challenge": challenge,
            "PubKey": pub_key,
            "BitcoinAddress": bitcoin_address,
            "Sig": sig,
        }],
        "id": 0,
    }
    return _DoRPC(url, req)

def StoreMessage(url, tokens, message):
    req = {
        "method": "Bitnet.StoreMessage",
        "params": [{
            "Tokens": tokens,
            "Message": message,
        }],
        "id": 0,
    }
    return _DoRPC(url, req)

def GetMessages(url, tokens, query):
    req = {
        "method": "Bitnet.GetMessages",
        "params": [{
            # "Tokens": tokens,
            "Query": query,
        }],
        "id": 0,
    }
    return _DoRPC(url, req)

def _DoRPC(url, req):
    _logger.info("Sending request to %s: %s", url, str(req))
    resp = requests.post(url, data=json.dumps(req), headers=_JSON_RPC_HEADERS)
    _logger.info("Got response: %s, %s", resp, resp.json())
    resp_json = resp.json()
    if resp_json["error"]:
        raise BitnetRPCException(resp_json["error"])
    return resp_json

def Sign(msg, sk):
    sig = sk.sign_digest(msg, sigencode=ecdsa.util.sigencode_der)
    return base64.b64encode(sig)

# This is pulled mostly from electrum.bitcoin, with a few modifications. Store
# it here as this client is meant to be used in different bitcoin wallets.
# Initial code for "class EC_KEY" copyright (C) 2011 thomasv@gitorious,
# GNU General Public License, version >= 3
# class EC_KEY(object):
#     def __init__(self, k):
#         secret = ecdsa.util.string_to_number(k)
#         self.pubkey = ecdsa.ecdsa.Public_key(ecdsa.ecdsa.generator_secp256k1, ecdsa.ecdsa.generator_secp256k1 * secret )
#         self.privkey = ecdsa.ecdsa.Private_key(self.pubkey, secret)
#         self.secret = secret

#     def get_public_key(self, compressed=True):
#         return point_to_ser(self.pubkey.point, compressed).encode('hex')

#     def get_private_key_pem(self, compressed=True):
#         sk = ecdsa.SigningKey.from_secret_exponent(
#             self.secret, curve=ecdsa.curves.SECP256k1)
#         return sk.to_pem()

def point_to_ser(P, comp=True):
    if comp:
        return ( ('%02x'%(2+(P.y()&1)))+('%064x'%P.x()) ).decode('hex')
    return ( '04'+('%064x'%P.x())+('%064x'%P.y()) ).decode('hex')


def sha256(x):
    return hashlib.sha256(x).digest()

def _Datetime():
    return datetime.datetime.utcnow().isoformat("T") + "Z"

def _AESPrivKeyHash(aes_priv):
    return hashlib.sha256(aes_priv).hexdigest()

# TODO(ortutay): Review the code below.
class AESCipher:
    def __init__(self, key):
        self.bs = 32
        if len(key) != 32:
            raise Exception("Unexpected key length %d bytes" % len(key))
        self.key = key

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return (iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]
