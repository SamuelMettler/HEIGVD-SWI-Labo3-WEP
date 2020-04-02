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

data = "c est un message compose de 36 chars"
icv = zlib.crc32(bytes(data, 'utf-8'))

# rc4 seed est composé de IV+clé
seed = iv+key
# on génère la classe
cipher = RC4(seed)
icvByte = struct.pack('!L', icv)
dataByte = bytes(data, 'utf-8')
dataCombine = dataByte + icvByte

cipherText = cipher.crypt(dataCombine)

# Check
print ("Message en clair : "+data)
print ("Message chiffré : "+cipherText.hex())
cipher = RC4(seed)
print ("Message déchiffré : "+cipher.crypt(cipherText)[:-4].decode('utf-8'))
