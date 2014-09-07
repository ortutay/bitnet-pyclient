#!/usr/bin/python
import sys
from bitnet_client import BitnetClient

a = BitnetClient(".bitnet2")
a.Send(sys.argv[1], sys.argv[2])

