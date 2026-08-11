#!/usr/bin/env python3
"""
Keygen minimal pour le crackme 'Sallos's Key License'.

Génère un fichier 'key.license' de 19 octets :
- 4 premiers octets satisfont les conditions de validate_license_bytes()
- les 15 suivants sont remplis avec 0x00 (sans importance)
"""

from pathlib import Path

def build_key():
    # Octets choisis pour respecter les contraintes :
    # b0 % 2 == 0, b1 % 3 == 0, b2 % 5 == 0, b3 % 8 == 0
    first_bytes = [0x2A, 0x3C, 0x28, 0x40]

    # Compléter jusqu'à 19 octets
    padding = [0x00] * (0x13 - len(first_bytes))

    data = bytes(first_bytes + padding)
    out_path = Path("key.license")
    out_path.write_bytes(data)

    print(f"[+] key.license généré ({len(data)} octets)")
    print(f"    Premiers octets : {data[:4].hex(' ')}")

if __name__ == "__main__":
    build_key()