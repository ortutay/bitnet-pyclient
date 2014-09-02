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
_DEFAULT_ADDR = "54.187.157.104:8555"
# _DEFAULT_ADDR = "localhost:8555"

logging.basicConfig(format='%(levelname)s %(name)s %(asctime)-15s %(filename)s:%(lineno)d %(message)s')
_logger = logging.getLogger("bitnet")
# TODO(ortutay): set lower logger level for prod
_logger.setLevel(logging.INFO)


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

class BitnetRPCException(Exception):
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
        client_key_path =  "%s/client_data.json" % data_path

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
            self.msg_key = RSA.generate(1024, Random.new().read)
            msg_enc = self.msg_key.exportKey('PEM')
            open(msg_key_path, "w").write(msg_enc)


        self._listeners = {}
        self._next_listener_id = 1
        self._seen_messages = set([])
        try:
            self._data = json.loads(open(client_data_path, "r").read())
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

    def _GetAesPriv(self, to_pub_key):
        if "aes_priv_keys" not in self._data:
            self._data["aes_priv_keys"] = {}
        if "rsa_pub_keys" not in self._data:
            self._data["rsa_pub_keys"] = {}
            
        if to_pub_key in self._data["aes_priv_keys"]:
            return self._data["aes_priv_keys"][to_pub_key]
        
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
        aes_priv = (hex(bits)[2:].rstrip("L")).rjust(32, "0")
        print "aes_priv", aes_priv
        k = binascii.unhexlify(aes_priv)
        aes_key = AES.new(k)

        rsa_pub_key = RSA.importKey(binascii.unhexlify(rsa_pub_key))
        rsa_pub = PKCS1_OAEP.new(rsa_pub_key)

        ciphertext = rsa_pub.encrypt(aes_priv)
        body = base64.b64encode(ciphertext)
        self.Send(None, {
            "to-pubkey": to_pub_key,
            "type": "bitnet.AESPrivKey",
            "encrypted-body": body,
        })
        return aes_priv

    def SendEncrypted(self, to_pub_key, message):
        aes_priv = self._GetAesPriv(to_pub_key)
        to_priv_key_hash = hashlib.sha256(aes_priv).hexdigest()
        aes_cipher = AESCipher(aes_priv)
        encrypted = base64.b64encode(aes_cipher.encrypt(message))
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
        if not query:
            query = {"to-pubkey": self.PubKeyStr()}
        tokens = self.Tokens(-1)
        resp = GetMessages(self.url, tokens, {"Headers": query})
        try:
            return resp["result"]["Messages"]
        except:
            return []

    # Receive new messages.
    # Overrides "datetime >" field in query.
    def Listen(self, handler, query=None):
        if not query:
            query = {"to-pubkey": self.PubKeyStr()}
        # Server currently does not charge for "GetMessages" RPC
        tokens = self.Tokens(-1)
        def periodic_poll(client, url, handler, tokens, query):
            datetime_gt = datetime.datetime.utcnow()
            while True:
                try:
                    query["datetime >"] = datetime_gt.isoformat("T") + "Z"
                    resp = GetMessages(url, tokens, {"Headers": query})

                    # Following line is skipped if GetMessages raises exception.
                    datetime_gt = datetime.datetime.utcnow()
                except BitnetRPCException as e:
                    _logger.error("Error on GetMessages(%s, %s): %s" % (
                        tokens, query, str(e)))
                    continue
                for msg in resp["result"]["Messages"]:
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
        thr = threading.Thread(
            group=None, target=periodic_poll, name=id,
            args=(self, self.url, handler, tokens, query))
        thr.daemon = True
        thr.start()
        return id

    def StopListening(self, id):
        # TODO(ortutay): implement
        pass

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

# TODO(ortutay): Review the code below.
class AESCipher:
    def __init__(self, key):
        self.bs = 32
        if len(key) >= 32:
            self.key = key[:32]
        else:
            self.key = self._pad(key)

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

if __name__ == "__main__":
    client = BitnetClient2()
