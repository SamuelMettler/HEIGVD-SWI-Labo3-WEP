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
key= b'\xaa\xaa\xaa\xaa\xab'
iv = b'\xca\xfe\xfe'

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

arp.data = 'FF:FF:FF:FF:FF:FF'
print (arp[Dot11].addr1)

#data = "c est un message compose de 36 chars"
data = arp.data
icv = zlib.crc32(bytes(data, 'utf-8'))

# rc4 seed est composé de IV+clé
seed = iv+key
# on génère la classe
cipher = RC4(seed)
icvByte = struct.pack('!L', icv)
dataByte = bytes(data, 'utf-8')
dataCombine = dataByte + icvByte

cipherText = cipher.crypt(dataCombine)

arp.data = cipherText

# Check
print ("Message en clair : "+data)
print ("Message chiffré : "+cipherText.hex())
cipher = RC4(seed)
print ("Message déchiffré : "+cipher.crypt(cipherText)[:-4].decode('utf-8'))

# Créer le nouveau pcap chiffré
wrpcap('crypted_pkt.pcap', arp, append=True)

