# Architecture du projet RSA Crypteur PyQt6

## Structure du projet

```
rsa_crypteur/
│
├─ main.py # Code principal de l'application
├─ requirements.txt # Dépendances Python
├─ README.md
├─ INSTALL.md
├─ ARCHITECTURE.md
├─ CHANGELOG.md
├─ CONTRIBUTING.md
├─ LICENSE.md
├─ ROADMAP.md
└─ assets/ # (optionnel) images, icônes, etc.
```

## Modules principaux

- `main.py`
  - Contient toutes les fonctionnalités :
    - Génération de nombres premiers avec Miller-Rabin (`is_prime`, `generate_prime`)
    - Calcul des clés RSA (`generate_keys`)
    - Chiffrement/Déchiffrement RSA (`rsa_encrypt`, `rsa_decrypt`)
    - Interface PyQt6 (`RsaQt`) avec onglets :
      - RSA : Génération des clés, chiffrement et déchiffrement
      - Explications RSA : Texte explicatif sur le fonctionnement de RSA

## Flux de l'application

1. L'utilisateur choisit la taille des nombres premiers et génère les clés.
2. Les clés sont affichées dans des champs lisibles.
3. L'utilisateur peut chiffrer un message texte → le résultat est affiché sous forme de liste de nombres.
4. L'utilisateur peut déchiffrer une liste de nombres → le résultat est affiché sous forme de texte clair.

## Technologies utilisées

- Python 3.11+
- PyQt6 pour l'interface graphique
- Standard library (`random`, `json`, `typing`)

## Concepts clés

- **Cryptographie asymétrique RSA**
- **Primalité probabiliste (Miller-Rabin)**
- **Modular exponentiation**
- **Interface graphique avec QWidgets, QLineEdit, QPushButton, QTabWidget**
