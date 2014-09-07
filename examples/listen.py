import bitnet_client
import logging
from bitnet_client import BitnetClient

bitnet_client.SetLogLevel(logging.WARNING)

def handle_new_messages(msg):
    print "Got new message:", msg

a = BitnetClient(".bitnet-test-ab")

print "Listening for messages at %s" % a.PubKeyStr()
a.Listen(handle_new_messages)

while True:
    pass

