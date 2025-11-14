"""
Application PyQt6 pour générer, chiffrer et déchiffrer des messages RSA optimisée.
Auteur : Rafael ISTE © 2025
"""

import sys
import random
import json
from typing import List, Tuple, Dict

from PyQt6.QtWidgets import (  # pylint: disable=E0611 # type: ignore
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox, QMessageBox,
    QTabWidget, QTextEdit
)
from PyQt6.QtGui import QFont  # pylint: disable=E0611 # type: ignore


def is_prime(n: int, k: int = 5) -> bool:
    """Test de primalité de Miller-Rabin.

    Args:
        n (int): Nombre à tester.
        k (int): Nombre de répétitions du test pour fiabilité.

    Returns:
        bool: True si n est probablement premier, False sinon.
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # écriture n-1 = 2^r * d
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int, k: int = 5) -> int:
    """Génère un nombre premier aléatoire de 'bits' bits.

    Args:
        bits (int): Taille en bits.
        k (int): Fiabilité Miller-Rabin.

    Returns:
        int: Nombre premier.
    """
    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1)) | 1
        if is_prime(p, k):
            return p


def gcd(a: int, b: int) -> int:
    """Calcule le plus grand commun diviseur (PGCD) de deux nombres.

    Args:
        a (int): Premier nombre.
        b (int): Second nombre.

    Returns:
        int: PGCD de a et b.
    """
    while b:
        a, b = b, a % b
    return a


def generate_keys(bits: int = 512) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """Génère une paire de clés RSA (publique et privée).

    Args:
        bits (int): Taille en bits des nombres premiers.

    Returns:
        Tuple[Tuple[int,int], Tuple[int,int]]: Clé publique et clé privée.
    """
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    d = pow(e, -1, phi)
    return (e, n), (d, n)


def rsa_encrypt(text: str, key: Tuple[int, int]) -> List[int]:
    """Chiffre un texte avec la clé publique RSA.

    Args:
        text (str): Texte clair.
        key (Tuple[int,int]): Clé publique (e, n).

    Returns:
        List[int]: Liste de nombres chiffrés.
    """
    e, n = key
    return [pow(ord(c), e, n) for c in text]


def rsa_decrypt(nums: List[int], key: Tuple[int, int]) -> str:
    """Déchiffre une liste de nombres avec la clé privée RSA.

    Args:
        nums (List[int]): Nombres chiffrés.
        key (Tuple[int,int]): Clé privée (d, n).

    Returns:
        str: Texte déchiffré.
    """
    d, n = key
    return ''.join(chr(pow(num, d, n)) for num in nums)


class RsaQt(QWidget):
    """Interface graphique PyQt6 pour le chiffrement/déchiffrement RSA."""

    def __init__(self) -> None:
        """Initialise l'interface et tous les widgets."""
        super().__init__()
        self.setWindowTitle("RSA Crypteur")
        self.setFixedSize(880, 575)
        self.setFont(QFont("Segoe UI", 10))

        self.text_widgets: Dict[str, QLineEdit] = {}
        self.button_widgets: Dict[str, QPushButton] = {}

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Crée la structure générale de l'interface avec les onglets."""
        root_layout = QVBoxLayout()
        root_layout.setContentsMargins(10, 10, 10, 10)
        self.setLayout(root_layout)

        tabs = QTabWidget()
        root_layout.addWidget(tabs)

        self._init_rsa_tab(tabs)
        self._init_explications_tab(tabs)

    def _init_rsa_tab(self, tabs: QTabWidget) -> None:
        """Onglet principal RSA avec génération, chiffrement et déchiffrement."""
        tab_rsa = QWidget()
        tabs.addTab(tab_rsa, "RSA")
        rsa_layout = QVBoxLayout()
        rsa_layout.setSpacing(15)
        rsa_layout.setContentsMargins(15, 15, 15, 15)
        tab_rsa.setLayout(rsa_layout)

        self._init_keys_section(rsa_layout)
        self._init_encrypt_section(rsa_layout)
        self._init_decrypt_section(rsa_layout)

    def _init_keys_section(self, parent_layout: QVBoxLayout) -> None:
        """Section pour générer et afficher les clés RSA."""
        box_keys = QGroupBox("Génération & affichage des clés RSA")
        box_keys.setFixedHeight(200)
        layout_keys = QVBoxLayout()
        layout_keys.setSpacing(10)
        layout_keys.setContentsMargins(12, 10, 12, 12)
        box_keys.setLayout(layout_keys)

        h_bits = QHBoxLayout()
        h_bits.setSpacing(12)
        h_bits.addWidget(QLabel("Taille des nombres premiers (bits) :"))

        self.text_widgets["bits_var"] = QLineEdit("512")
        self.text_widgets["bits_var"].setFixedWidth(80)
        h_bits.addWidget(self.text_widgets["bits_var"])

        self.button_widgets["btn_gen"] = QPushButton("Générer les clés")
        self.button_widgets["btn_gen"].setFixedWidth(160)
        self.button_widgets["btn_gen"].clicked.connect(self.generate_keys_ui)
        h_bits.addWidget(self.button_widgets["btn_gen"])
        h_bits.addStretch()
        layout_keys.addLayout(h_bits)

        form_keys = QFormLayout()
        form_keys.setHorizontalSpacing(20)
        form_keys.setVerticalSpacing(6)
        form_keys.setContentsMargins(0, 0, 0, 0)

        for name in ("pub_n", "pub_e", "priv_n", "priv_d"):
            self.text_widgets[name] = QLineEdit()
            self.text_widgets[name].setFixedWidth(300)

        form_keys.addRow("Clé publique n :", self.text_widgets["pub_n"])
        form_keys.addRow("Clé publique e :", self.text_widgets["pub_e"])
        form_keys.addRow("Clé privée n :", self.text_widgets["priv_n"])
        form_keys.addRow("Clé privée d :", self.text_widgets["priv_d"])
        layout_keys.addLayout(form_keys)

        parent_layout.addWidget(box_keys)

    def _init_encrypt_section(self, parent_layout: QVBoxLayout) -> None:
        """Section pour le chiffrement."""
        box_encrypt = QGroupBox("Cryptage")
        box_encrypt.setFixedHeight(130)
        layout_encrypt = QVBoxLayout()
        layout_encrypt.setSpacing(10)
        layout_encrypt.setContentsMargins(12, 10, 12, 12)
        box_encrypt.setLayout(layout_encrypt)

        form_encrypt = QFormLayout()
        form_encrypt.setHorizontalSpacing(20)
        form_encrypt.setVerticalSpacing(6)
        form_encrypt.setContentsMargins(0, 0, 0, 0)

        self.text_widgets["entree_text"] = QLineEdit()
        self.text_widgets["crypter_text"] = QLineEdit()
        self.text_widgets["crypter_text"].setReadOnly(True)

        self.button_widgets["btn_crypter"] = QPushButton("Crypter")
        self.button_widgets["btn_crypter"].setFixedWidth(130)
        self.button_widgets["btn_crypter"].clicked.connect(self.encrypt_text_ui)

        form_encrypt.addRow("Texte à crypter :", self.text_widgets["entree_text"])
        form_encrypt.addRow("Texte crypté :", self.text_widgets["crypter_text"])
        h_btn = QHBoxLayout()
        h_btn.addStretch()
        h_btn.addWidget(self.button_widgets["btn_crypter"])
        h_btn.addStretch()
        form_encrypt.addRow(h_btn)
        layout_encrypt.addLayout(form_encrypt)

        parent_layout.addWidget(box_encrypt)

    def _init_decrypt_section(self, parent_layout: QVBoxLayout) -> None:
        """Section pour le déchiffrement."""
        box_decrypt = QGroupBox("Décryptage")
        box_decrypt.setFixedHeight(130)
        layout_decrypt = QVBoxLayout()
        layout_decrypt.setSpacing(10)
        layout_decrypt.setContentsMargins(12, 10, 12, 12)
        box_decrypt.setLayout(layout_decrypt)

        form_decrypt = QFormLayout()
        form_decrypt.setHorizontalSpacing(20)
        form_decrypt.setVerticalSpacing(6)
        form_decrypt.setContentsMargins(0, 0, 0, 0)

        self.text_widgets["entre_text"] = QLineEdit()
        self.text_widgets["decrypter_text"] = QLineEdit()
        self.text_widgets["decrypter_text"].setReadOnly(True)

        self.button_widgets["btn_decrypter"] = QPushButton("Décrypter")
        self.button_widgets["btn_decrypter"].setFixedWidth(130)
        self.button_widgets["btn_decrypter"].clicked.connect(self.decrypt_text_ui)

        form_decrypt.addRow("Liste à décrypter :", self.text_widgets["entre_text"])
        form_decrypt.addRow("Texte décrypté :", self.text_widgets["decrypter_text"])
        h_btn = QHBoxLayout()
        h_btn.addStretch()
        h_btn.addWidget(self.button_widgets["btn_decrypter"])
        h_btn.addStretch()
        form_decrypt.addRow(h_btn)
        layout_decrypt.addLayout(form_decrypt)

        parent_layout.addWidget(box_decrypt)

    def _init_explications_tab(self, tabs: QTabWidget) -> None:
        """Onglet affichant des explications sur RSA."""
        tab_exp = QWidget()
        tabs.addTab(tab_exp, "Explications RSA")
        exp_layout = QVBoxLayout()
        exp_layout.setContentsMargins(15, 15, 15, 15)
        tab_exp.setLayout(exp_layout)

        texte = QTextEdit()
        texte.setReadOnly(True)
        texte.setFont(QFont("Segoe UI", 10))
        texte.setPlainText(
            "Le RSA est un système de cryptographie asymétrique.\n\n"
            "1️⃣ Génération des clés :\n"
            "   - Choisir deux nombres premiers p et q.\n"
            "   - Calculer n = p * q et φ(n) = (p-1)*(q-1).\n"
            "   - Choisir e tel que 1 < e < φ(n) et gcd(e, φ(n)) = 1.\n"
            "   - Calculer d tel que (d*e) % φ(n) = 1.\n\n"
            "La clé publique est (e, n) et la clé privée est (d, n).\n\n"
            "2️⃣ Chiffrement :\n"
            "   Pour chaque caractère c du texte clair :\n"
            "       chiffre = (ord(c) ** e) % n\n\n"
            "3️⃣ Déchiffrement :\n"
            "   Pour chaque nombre chiffré :\n"
            "       clair = chr((chiffre ** d) % n)\n\n"
            "⚠️ Plus les nombres premiers p et q sont grands, plus la sécurité est élevée.\n"
            "💡 Exemple simple : p=17, q=11, e=7 → n=187, φ=160 → d=23."
        )
        exp_layout.addWidget(texte)

    def generate_keys_ui(self) -> None:
        """Génère les clés RSA depuis l'interface utilisateur."""
        try:
            bits = int(self.text_widgets["bits_var"].text())
        except ValueError:
            QMessageBox.critical(self, "Erreur", "Taille invalide.")
            return

        pub, priv = generate_keys(bits)
        self.text_widgets["pub_n"].setText(str(pub[1]))
        self.text_widgets["pub_e"].setText(str(pub[0]))
        self.text_widgets["priv_n"].setText(str(priv[1]))
        self.text_widgets["priv_d"].setText(str(priv[0]))
        QMessageBox.information(self, "OK", "Clés RSA générées avec succès !")

    def encrypt_text_ui(self) -> None:
        """Chiffre le texte saisi par l'utilisateur."""
        try:
            e = int(self.text_widgets["pub_e"].text())
            n = int(self.text_widgets["pub_n"].text())
            cipher_nums = rsa_encrypt(self.text_widgets["entree_text"].text(), (e, n))
            self.text_widgets["crypter_text"].setText(str(cipher_nums))
        except (ValueError, TypeError):
            self.text_widgets["crypter_text"].setText("Erreur avec la clé ou le texte")

    def decrypt_text_ui(self) -> None:
        """Déchiffre la liste saisie par l'utilisateur."""
        try:
            d = int(self.text_widgets["priv_d"].text())
            n = int(self.text_widgets["priv_n"].text())
            nums: List[int] = json.loads(self.text_widgets["entre_text"].text())
            self.text_widgets["decrypter_text"].setText(rsa_decrypt(nums, (d, n)))
        except (ValueError, TypeError, json.JSONDecodeError):
            self.text_widgets["decrypter_text"].setText("Erreur avec la clé ou les nombres")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RsaQt()
    window.show()
    sys.exit(app.exec())

