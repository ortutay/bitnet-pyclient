import bitnet_client
import logging
from bitnet_client import BitnetClient

bitnet_client.SetLogLevel(logging.INFO)

a = BitnetClient(data_dir=".bitnet-encryptedtest")
# enc = a._GetEncrypted()
msgs = a.Get()
print "Encrypted messages for %s:" % a.PubKeyStr()
for msg in msgs:
    try:
        msg["Encrypted"]["Body"]
    except:
        continue
    print msg
