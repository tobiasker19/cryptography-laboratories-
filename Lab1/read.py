import sys
from scapy.all import rdpcap
from termcolor import colored

# Función para descifrar el mensaje utilizando el algoritmo de César
def caesar_decrypt(message, shift):
    decrypted_message = ""
    for char in message:
        if char.isalpha():
            char_code = ord(char)
            char_code -= shift
            if char.isupper():
                if char_code < ord('A'):
                    char_code += 26
                elif char_code > ord('Z'):
                    char_code -= 26
            else:
                if char_code < ord('a'):
                    char_code += 26
                elif char_code > ord('z'):
                    char_code -= 26
            decrypted_message += chr(char_code)
        else:
            decrypted_message += char
    return decrypted_message 

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 pcapng_caesar_decrypt.py <pcapng file>")
        sys.exit(1)
        
    pcapng_file = sys.argv[1]

    message = ""
    packets = rdpcap(pcapng_file)
    for packet in packets:
        if packet.haslayer('ICMP'):
            icmp_layer = packet.getlayer('ICMP')
            if icmp_layer.type == 8:  # ICMP request
                first_byte = icmp_layer.load[0]
                message += chr(first_byte)

    highest_score = 0
    most_probable_message = ""
    most_probable_shift = 0

    for shift in range(26):
        decrypted_message = caesar_decrypt(message, shift)
        score = decrypted_message.count(' ') + decrypted_message.count('e') + decrypted_message.count('E')
        
        if score > highest_score:
            highest_score = score
            most_probable_message = decrypted_message
            most_probable_shift = shift

    for shift in range(26):
        decrypted_message = caesar_decrypt(message, shift)
        if shift == most_probable_shift:
            print(colored(f"Shift {shift}: {decrypted_message}", 'green'))
        else:
            print(f"Shift {shift}: {decrypted_message}")

