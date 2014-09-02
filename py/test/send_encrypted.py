#!/usr/bin/python
import sys
from bitnet_client import BitnetClient

a = BitnetClient(".bitnet3")
a.SendEncrypted(sys.argv[1], sys.argv[2])
