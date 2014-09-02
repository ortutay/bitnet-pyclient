import binascii
import ecdsa
from electrum import BasePlugin
from electrum.i18n import _
from electrum.account import *

from bitnet_client import BitnetClient

import PyQt4
from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

class Plugin(BasePlugin):
    def fullname(self): return 'Bitnet'

    def description(self): return 'Communication network for Bitcoin wallets'

    def __init__(self, gui, name):
        self.gui = gui
        self.client = BitnetClient()
        BasePlugin.__init__(self, gui, name)
        self._is_available = self._init()

    def _init(self):
        return True

    def is_available(self):
        return self._is_available

    def enable(self):
        return BasePlugin.enable(self)

    def init(self):
        self.gui.main_window.tabs.addTab(self.create_bitnet_tab(), _('Bitnet'))
    
    def create_bitnet_tab(self):
        w = QWidget()
        self.bitnet_grid = grid = QGridLayout(w)
        grid.setSpacing(8)

        row = 0
        grid.addWidget(QLabel("Pub key:"), row, 0)

        self.pub_key_line = QLineEdit(self.client.PubKeyStr())
        self.pub_key_line.setReadOnly(True)
        grid.addWidget(self.pub_key_line, row, 1)

        row += 1
        grid.addWidget(QLabel("Console:"), row, 0)
        self.dialog = dialog = QPlainTextEdit("", w)
        grid.addWidget(dialog, row, 1)

        row += 1
        grid.addWidget(QLabel("Send to pub key:"), row, 0)
        self.send_to_line = QLineEdit("")
        grid.addWidget(self.send_to_line, row, 1)

        row += 1
        grid.addWidget(QLabel("Send message:"), row, 0)
        self.send_msg_line = QLineEdit("")
        grid.addWidget(self.send_msg_line, row, 1)

        row += 1
        b = QPushButton("Send", w)
        b.setMaximumWidth(100)
        b.clicked.connect(lambda: self.do_send())
        grid.addWidget(b, row, 1)

        self.client.Listen(self.handle_new_message,
                           {"to-pubkey": self.client.PubKeyStr()})

        return w

    def do_update_priv_seed(self, t):
        self.client.SetIdPriv(t)
        self.pub_key_line.setText(self.client.PubKeyStr())

    def do_send(self):
        to_pub_key = self.send_to_line.displayText()
        message = self.send_msg_line.displayText()
        print "send:", message, "to:", to_pub_key
        try:
            self.client.Send(to_pub_key, message)
        except BitnetRPCException as e:
            self.dialog.appendPlainText("Error: %s" % str(e))
            return

        self.dialog.appendPlainText(
            "Sent to %s: %s" % (to_pub_key[:8], message))

    def handle_new_message(self, message):
        # TODO(ortutay): Handle encrypted section.
        try:
            to_show = message["Plaintext"]["Body"]
        except:
            to_show = "Unhandled message format"
        try:
            sender = (message["Plaintext"]["Headers"]["from-pubkey"][0])[:8]
        except:
            sender = "unknown-sender"
        self.dialog.appendPlainText("Got from %s: %s" % (sender, to_show))
        self.dialog.repaint(self.dialog.rect())
