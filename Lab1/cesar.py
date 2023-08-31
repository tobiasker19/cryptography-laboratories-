#!/usr/bin/env python3

import sys

def cifrar_cesar(texto, corrimiento):
    resultado = ''
    for caracter in texto:
        if caracter.isalpha():
            if caracter.islower():
                nuevo_caracter = chr((ord(caracter) - ord('a' ) + corrimiento) % 26 + ord('a'))
            else:
                nuevo_caracter = chr((ord(caracter) - ord('A' ) + corrimiento) % 26 + ord('A'))
            resultado += nuevo_caracter
        else:
            resultado += caracter
    return resultado

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py <cadena_de_texto> <numero_corrimiento>")
        sys.exit(1)

    cadena = sys.argv[1]
    corrimiento = int(sys.argv[2])

    texto_cifrado = cifrar_cesar(cadena, corrimiento)
    print("Texto cifrado:", texto_cifrado)
