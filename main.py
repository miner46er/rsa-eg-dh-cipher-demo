from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog
from mainwindow import Ui_MainWindow
import sys
from iterator import *
from modes import ECB
from rsa import RSA
from elgamal import Elgamal
from dh import DiffieHellman

class ApplicationWindow(QMainWindow):
    def __init__(self):
        super(ApplicationWindow, self).__init__()

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # RSA
        # Encrypt
        self.ui.pushButton_browse_input_file.clicked.connect(self.rsa_encrypt_browse_input)
        self.ui.pushButton_browse_public_key.clicked.connect(self.rsa_encrypt_browse_public)
        self.ui.pushButton_encrypt.clicked.connect(self.rsa_encrypt_to_text)
        self.ui.pushButton_encrypt_and_save.clicked.connect(self.rsa_encrypt_to_file)
        # Decrypt
        self.ui.pushButton_browse_input_file_2.clicked.connect(self.rsa_decrypt_browse_input)
        self.ui.pushButton_browse_private_key.clicked.connect(self.rsa_decrypt_browse_private)
        self.ui.pushButton_decrypt.clicked.connect(self.rsa_decrypt_to_text)
        self.ui.pushButton_decrypt_save.clicked.connect(self.rsa_decrypt_to_file)
        # Generate Key
        self.ui.pushButton_generate_key.clicked.connect(self.rsa_generate_key)
        self.ui.pushButton_save_private_key.clicked.connect(self.rsa_generate_save_private)
        self.ui.pushButton_save_public_key.clicked.connect(self.rsa_generate_save_public)

        # ElGamal
        # Encrypt
        self.ui.pushButton_browse_input_file_3.clicked.connect(self.eg_encrypt_browse_input)
        self.ui.pushButton_browse_public_key_2.clicked.connect(self.eg_encrypt_browse_public)
        self.ui.pushButton_encrypt_2.clicked.connect(self.eg_encrypt_to_text)
        self.ui.pushButton_encrypt_and_save_2.clicked.connect(self.eg_encrypt_to_file)
        # Decrypt
        self.ui.pushButton_browse_input_file_4.clicked.connect(self.eg_decrypt_browse_input)
        self.ui.pushButton_browse_private_key_2.clicked.connect(self.eg_decrypt_browse_private)
        self.ui.pushButton_decrypt_2.clicked.connect(self.eg_decrypt_to_text)
        self.ui.pushButton_decrypt_save_2.clicked.connect(self.eg_decrypt_to_file)
        # Generate Key
        self.ui.pushButton_generate_key_2.clicked.connect(self.eg_generate_key)
        self.ui.pushButton_save_private_key_2.clicked.connect(self.eg_generate_save_private)
        self.ui.pushButton_save_public_key_2.clicked.connect(self.eg_generate_save_public)

        # Diffie-Hellman
        self.ui.pushButton.clicked.connect(self.dh_generate_n)
        self.ui.pushButton_2.clicked.connect(self.dh_generate_n)
        self.ui.pushButton_3.clicked.connect(self.dh_generate_n)
        self.ui.pushButton_4.clicked.connect(self.dh_generate_n)
        self.ui.pushButton_9.clicked.connect(self.dh_generate_n)

    def rsa_encrypt_browse_input(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Open file', 
            self.ui.plainTextEdit_input_file.toPlainText(), "All Files (*)")
        self.ui.plainTextEdit_input_file.setPlainText(filename)

    def rsa_encrypt_browse_public(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Open file', 
            self.ui.plainTextEdit_public_key.toPlainText(), "Public key (*.pub)")
        self.ui.plainTextEdit_public_key.setPlainText(filename)

    def rsa_encrypt_to_text(self):
        key_path = self.ui.plainTextEdit_public_key.toPlainText()
        if key_path == '':
            return

        with open(key_path, "rb") as file:
            key = file.read()
            cipher = RSA(public_key = key)

            mode = ECB(cipher)

            input_file_path = self.ui.plainTextEdit_input_file.toPlainText()
            if input_file_path == '':
                message = self.ui.plainTextEdit_plaintext.toPlainText().encode("latin-1")
                message_iterator = bytes_block_iterator(message, mode.block_size_plaintext)
            else:
                message_iterator = file_block_iterator(input_file_path, mode.block_size_plaintext)

            self.ui.plainTextEdit_ciphertext.setPlainText('')
            for data in mode.encrypt(message_iterator):
                self.ui.plainTextEdit_ciphertext.appendPlainText(data.decode("latin-1"))

    def rsa_encrypt_to_file(self):
        output_filename, _ = QFileDialog.getSaveFileName(self, 'Save File')
        if output_filename == '':
            return

        key_path = self.ui.plainTextEdit_public_key.toPlainText()
        if key_path == '':
            return

        with open(key_path, "rb") as file:
            key = file.read()
            cipher = RSA(public_key = key)

            mode = ECB(cipher)

            input_file_path = self.ui.plainTextEdit_input_file.toPlainText()
            if input_file_path == '':
                message = self.ui.plainTextEdit_plaintext.toPlainText().encode("latin-1")
                message_iterator = bytes_block_iterator(message, mode.block_size_plaintext)
            else:
                message_iterator = file_block_iterator(input_file_path, mode.block_size_plaintext)

            with open(output_filename, "wb") as output_file:
                for data in mode.encrypt(message_iterator):
                    output_file.write(data)

    def rsa_decrypt_browse_input(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Open file', 
            self.ui.plainTextEdit_input_file_2.toPlainText(), "All Files (*)")
        self.ui.plainTextEdit_input_file_2.setPlainText(filename)

    def rsa_decrypt_browse_private(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Open file', 
            self.ui.plainTextEdit_private_key.toPlainText(), "Private key (*.pri)")
        self.ui.plainTextEdit_private_key.setPlainText(filename)

    def rsa_decrypt_to_text(self):
        key_path = self.ui.plainTextEdit_private_key.toPlainText()
        if key_path == '':
            return

        with open(key_path, "rb") as file:
            key = file.read()
            cipher = RSA(private_key = key)

            mode = ECB(cipher)

            input_file_path = self.ui.plainTextEdit_input_file_2.toPlainText()
            if input_file_path == '':
                message = self.ui.plainTextEdit_ciphertext_2.toPlainText().encode("latin-1")
                message_iterator = bytes_block_iterator(message, mode.block_size_ciphertext)
            else:
                message_iterator = file_block_iterator(input_file_path, mode.block_size_ciphertext)

            self.ui.plainTextEdit_plaintext_2.setPlainText('')
            for data in mode.decrypt(message_iterator):
                self.ui.plainTextEdit_plaintext_2.appendPlainText(data.decode("latin-1"))

    def rsa_decrypt_to_file(self):
        output_filename, _ = QFileDialog.getSaveFileName(self, 'Save File')
        if output_filename == '':
            return

        key_path = self.ui.plainTextEdit_private_key.toPlainText()
        if key_path == '':
            return

        with open(key_path, "rb") as file:
            key = file.read()
            cipher = RSA(public_key = key)

            mode = ECB(cipher)

            input_file_path = self.ui.plainTextEdit_input_file_2.toPlainText()
            if input_file_path == '':
                message = self.ui.plainTextEdit_ciphertext_2.toPlainText().encode("latin-1")
                message_iterator = bytes_block_iterator(message, mode.block_size_ciphertext)
            else:
                message_iterator = file_block_iterator(input_file_path, mode.block_size_ciphertext)

            with open(output_filename, "wb") as output_file:
                for data in mode.decrypt(message_iterator):
                    output_file.write(data)

    def rsa_generate_key(self):
        cipher = RSA()
        cipher.generate_key()
        self.ui.plainTextEdit_private_key_2.setPlainText(cipher.get_private_key_base64().decode("latin-1"))
        self.ui.plainTextEdit_public_key_2.setPlainText(cipher.get_public_key_base64().decode("latin-1"))

    def rsa_generate_save_private(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Save File', '', "Private key (*.pri)")

        if filename == '':
            return

        with open(filename, "w") as file:
            file.write(self.ui.plainTextEdit_private_key_2.toPlainText())

    def rsa_generate_save_public(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Save File', '', "Public key (*.pub)")

        if filename == '':
            return

        with open(filename, "w") as file:
            file.write(self.ui.plainTextEdit_public_key_2.toPlainText())

    def eg_encrypt_browse_input(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Open file', 
            self.ui.plainTextEdit_input_file_3.toPlainText(), "All Files (*)")
        self.ui.plainTextEdit_input_file_3.setPlainText(filename)

    def eg_encrypt_browse_public(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Open file', 
            self.ui.plainTextEdit_public_key_3.toPlainText(), "Public key (*.pub)")
        self.ui.plainTextEdit_public_key_3.setPlainText(filename)

    def eg_encrypt_to_text(self):
        key_path = self.ui.plainTextEdit_public_key_3.toPlainText()
        if key_path == '':
            return

        with open(key_path, "rb") as file:
            key = file.read()
            cipher = Elgamal(public_key = key)

            mode = ECB(cipher)

            input_file_path = self.ui.plainTextEdit_input_file_3.toPlainText()
            if input_file_path == '':
                message = self.ui.plainTextEdit_plaintext_3.toPlainText().encode("latin-1")
                message_iterator = bytes_block_iterator(message, mode.block_size_plaintext)
            else:
                message_iterator = file_block_iterator(input_file_path, mode.block_size_plaintext)

            self.ui.plainTextEdit_ciphertext_3.setPlainText('')
            for data in mode.encrypt(message_iterator):
                self.ui.plainTextEdit_ciphertext_3.appendPlainText(data.decode("latin-1"))

    def eg_encrypt_to_file(self):
        output_filename, _ = QFileDialog.getSaveFileName(self, 'Save File')
        if output_filename == '':
            return

        key_path = self.ui.plainTextEdit_public_key_3.toPlainText()
        if key_path == '':
            return

        with open(key_path, "rb") as file:
            key = file.read()
            cipher = Elgamal(public_key = key)

            mode = ECB(cipher)

            input_file_path = self.ui.plainTextEdit_input_file_3.toPlainText()
            if input_file_path == '':
                message = self.ui.plainTextEdit_plaintext_3.toPlainText().encode("latin-1")
                message_iterator = bytes_block_iterator(message, mode.block_size_plaintext)
            else:
                message_iterator = file_block_iterator(input_file_path, mode.block_size_plaintext)

            with open(output_filename, "wb") as output_file:
                for data in mode.encrypt(message_iterator):
                    output_file.write(data)

    def eg_decrypt_browse_input(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Open file', 
            self.ui.plainTextEdit_input_file_4.toPlainText(), "All Files (*)")
        self.ui.plainTextEdit_input_file_4.setPlainText(filename)

    def eg_decrypt_browse_private(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Open file', 
            self.ui.plainTextEdit_private_key_3.toPlainText(), "Private key (*.pri)")
        self.ui.plainTextEdit_private_key_3.setPlainText(filename)

    def eg_decrypt_to_text(self):
        key_path = self.ui.plainTextEdit_private_key_3.toPlainText()
        if key_path == '':
            return

        with open(key_path, "rb") as file:
            key = file.read()
            cipher = Elgamal(private_key = key)

            mode = ECB(cipher)

            input_file_path = self.ui.plainTextEdit_input_file_4.toPlainText()
            if input_file_path == '':
                message = self.ui.plainTextEdit_ciphertext_4.toPlainText().encode("latin-1")
                message_iterator = bytes_block_iterator(message, mode.block_size_ciphertext)
            else:
                message_iterator = file_block_iterator(input_file_path, mode.block_size_ciphertext)

            self.ui.plainTextEdit_plaintext_4.setPlainText('')
            for data in mode.decrypt(message_iterator):
                self.ui.plainTextEdit_plaintext_4.appendPlainText(data.decode("latin-1"))

    def eg_decrypt_to_file(self):
        output_filename, _ = QFileDialog.getSaveFileName(self, 'Save File')
        if output_filename == '':
            return

        key_path = self.ui.plainTextEdit_private_key_3.toPlainText()
        if key_path == '':
            return

        with open(key_path, "rb") as file:
            key = file.read()
            cipher = Elgamal(public_key = key)

            mode = ECB(cipher)

            input_file_path = self.ui.plainTextEdit_input_file_4.toPlainText()
            if input_file_path == '':
                message = self.ui.plainTextEdit_ciphertext_4.toPlainText().encode("latin-1")
                message_iterator = bytes_block_iterator(message, mode.block_size_ciphertext)
            else:
                message_iterator = file_block_iterator(input_file_path, mode.block_size_ciphertext)

            with open(output_filename, "wb") as output_file:
                for data in mode.decrypt(message_iterator):
                    output_file.write(data)

    def eg_generate_key(self):
        cipher = Elgamal()
        cipher.generate_key()
        self.ui.plainTextEdit_private_key_4.setPlainText(cipher.get_private_key_base64().decode("latin-1"))
        self.ui.plainTextEdit_public_key_4.setPlainText(cipher.get_public_key_base64().decode("latin-1"))

    def eg_generate_save_private(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Save File', '', "Private key (*.pri)")

        if filename == '':
            return

        with open(filename, "w") as file:
            file.write(self.ui.plainTextEdit_private_key_4.toPlainText())

    def eg_generate_save_public(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Save File', '', "Public key (*.pub)")

        if filename == '':
            return

        with open(filename, "w") as file:
            file.write(self.ui.plainTextEdit_public_key_4.toPlainText())

    def dh_generate_n(self):
        self.ui.plainTextEdit_input_file_5.setPlainText(DiffieHellman.get_n())

    def dh_generate_g(self):
        n = int(self.ui.plainTextEdit_input_file_5.toPlainText())
        self.ui.plainTextEdit_input_file_6.setPlainText(DiffieHellman.get_g(n))

    def dh_generate_x(self):
        n = int(self.ui.plainTextEdit_input_file_5.toPlainText())
        self.ui.plainTextEdit_input_file_7.setPlainText(DiffieHellman.get_x(n))

    def dh_generate_y(self):
        n = int(self.ui.plainTextEdit_input_file_5.toPlainText())
        g = int(self.ui.plainTextEdit_input_file_6.toPlainText())
        x = int(self.ui.plainTextEdit_input_file_7.toPlainText())
        self.ui.plainTextEdit_input_file_8.setPlainText(DiffieHellman.get_Y(n, g, x))

    def dh_generate_k(self):
        n = int(self.ui.plainTextEdit_input_file_5.toPlainText())
        g = int(self.ui.plainTextEdit_input_file_6.toPlainText())
        x = int(self.ui.plainTextEdit_input_file_7.toPlainText())
        y = int(self.ui.plainTextEdit_input_file_8.toPlainText())
        self.ui.plainTextEdit_input_file_9.setPlainText(DiffieHellman.get_symetric_key(n, g, x, y))

def main():
    app = QApplication(sys.argv)
    application = ApplicationWindow()
    application.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()