import argparse
from Crypto.Hash import MD5
from Crypto.Cipher import AES
import pyscrypt
from base64 import b64encode
from os import urandom
from string import Template
import os

#======================================================================================================
# XOR
#======================================================================================================
# data as a bytearray
# key as a string
def xor(data, key):
    l = len(key)
    keyAsInt = list(map(ord, key))
    return bytes(bytearray(
        (data[i] ^ keyAsInt[i % l] for i in range(0, len(data)))
    ))


# data as a bytearray 
def formatCPP(data, key, cipherType):
    print("[*] XOR key [{}]".format(key))
    shellcode = "\\x"
    shellcode += "\\x".join(format(b, '02x') for b in data)
    print("[*] XOR Encoded Shellcode : ")
    print(shellcode)


#======================================================================================================
# MAIN FUNCTION
#======================================================================================================
if __name__ == '__main__':
    #------------------------------------------------------------------------
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("shellcodeFile", help="File name containing the raw shellcode to be encoded/encrypted")
    parser.add_argument("key", help="Key used to transform (XOR) the shellcode")
    args = parser.parse_args()

    #------------------------------------------------------------------------
    # Open shellcode file and read all bytes from it
    try:
        with open(args.shellcodeFile, "rb") as shellcodeFileHandle:
            shellcodeBytes = bytearray(shellcodeFileHandle.read())
            print("")
            print("[*] Shellcode file [{}] successfully loaded.".format(args.shellcodeFile))

            # Print Original (non-xor-encoded) shellcode in hex format
            hex_representation = "\\x" + "\\x".join(format(byte, '02x') for byte in shellcodeBytes)
            print("[*] Original Shellcode : ")
            print(hex_representation)

    except IOError:
        print("[!] Could not open or read file [{}]".format(args.shellcodeFile))
        quit()

    #------------------------------------------------------------------------
    # Perform XOR transformation
    masterKey = args.key
    transformedShellcode = xor(shellcodeBytes, masterKey)
    cipherType = 'xor'

    print("\n==================================== RESULT ====================================\n")
    print("[*] Encrypted shellcode size: [{}] bytes".format(len(transformedShellcode)))
    formatCPP(transformedShellcode, masterKey, cipherType)
    print("")
