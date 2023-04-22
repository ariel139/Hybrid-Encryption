import sys
from Hybrid_Encryption import Encryption_Method
from PyQt6.QtWidgets import *
from PyQt6.QtCore import QStringListModel
from clientHybrid import main, Logger
WIDTH, HEIGHT =600,600

log_dict = Logger.log_dict
DEBUG = False
l_app = QApplication([])
window = QWidget()
window.setWindowTitle("QFormLayout")
window.setFixedSize(WIDTH,HEIGHT)
layout = QFormLayout()

ip_input = QLineEdit()
print(ip_input.text())
ip_input.setFixedWidth(200)
port_input = QLineEdit()
port_input.setFixedWidth(200)
layout.addRow("IP:", ip_input)
layout.addRow("port:", port_input)
layout.addRow(QLabel('chose key exchange algoritem: '))
dph_radio = QRadioButton("D.P.H")
rsa_radio = QRadioButton("RSA")
layout.addRow(dph_radio)
layout.addRow(rsa_radio)

data_input = QPlainTextEdit()
data_input.setFixedHeight(200)
layout.addRow(QLabel('enter data:'))
layout.addRow(data_input)
lstview_after_decryption = QListView()
lstview_encryption = QListView()
layout.addRow(lstview_after_decryption, lstview_encryption)

lstview_erros = QListView()
def get_form():
    ip = ip_input.text()
    port = int(port_input.text())
    method = Encryption_Method.DPH if dph_radio.isChecked() else Encryption_Method.RSA
    data = data_input.toPlainText().encode()
    main(ip,port,method,data)
    model = QStringListModel()
    model.setStringList(log_dict['1'])
    lstview_after_decryption.setModel(model)

    model = QStringListModel()
    model.setStringList(log_dict['2'])
    lstview_encryption.setModel(model)

    model = QStringListModel()
    model.setStringList(log_dict['5'])
    lstview_erros.setModel(model)

if not DEBUG:
    ctn_btn = QPushButton('Connect and send')

    layout.addRow(ctn_btn)
    ctn_btn.clicked.connect(get_form)

    layout.addRow(lstview_erros)

    window.setLayout(layout)

    window.show()
    sys.exit(l_app.exec())
if DEBUG:

    main('127.0.0.1',8200,Encryption_Method.RSA,b'losdde')

