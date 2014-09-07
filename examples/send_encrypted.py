#!/usr/bin/python
import sys
import bitnet_client
import logging

from bitnet_client import BitnetClient

bitnet_client.SetLogLevel(logging.WARNING)

a = BitnetClient(".bitnet4")
a.SendEncrypted(sys.argv[1], sys.argv[2])
