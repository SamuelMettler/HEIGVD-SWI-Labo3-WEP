#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Samuel Mettler & Olivier Koffi"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4
import zlib

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'
iv = b'\xca\xfe\xfe'

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

#arp.data = 'FF:FF:FF:FF:FF:FF'

data = "c est un message compose de 36 chars"
# on calcule l'icv avec crc32
icv = zlib.crc32(bytes(data, 'utf-8'))

# rc4 seed est composé de IV+clé
seed = iv+key
# on génère la classe
cipher = RC4(seed, False)

# on génère l'icv en byte
icvByte = struct.pack('<l', icv)
# on génère le data en byte pour ensuite concatener
dataByte = bytes(data, 'utf-8')
dataCombine = dataByte + icvByte

# on met la valeur de l'icv dans l'arp
arp.icv = struct.unpack('!L', dataCombine[-4:])[0]
# on chiffre le message et le place dans l'arp et on renseigne l'iv
cipherText = cipher.crypt(dataCombine)
arp.wepdata = cipherText
arp.iv = iv

# Check
print ("Message en clair : "+data)
print ("Message chiffré : "+cipherText.hex())
print ("Message déchiffré : "+cipher.crypt(cipherText)[:-4].decode('utf-8'))

# Créer le nouveau pcap chiffré
wrpcap('crypted_pkt.cap', arp)

