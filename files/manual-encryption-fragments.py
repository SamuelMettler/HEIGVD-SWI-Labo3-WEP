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

#Création des trames ARP valide non chiffrée
arp1 = arp2 = arp3 = rdpcap('arp.cap')[0]  
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

# on met la valeur de l'icv dans les trames
arp1.icv = arp2.icv = arp3.icv = struct.unpack('!L', dataCombine[-4:])[0]

# on chiffre le message et le place dans les trames et on renseigne les ivs
arp1.wepdata = cipher.crypt(dataCombine)
arp2.wepdata = cipher.crypt(dataCombine)
arp3.wepdata = cipher.crypt(dataCombine)
arp1.iv = arp2.iv = arp3.iv = iv

# On active le bit "more fragments" pour toutes les trames sauf la dernière et on incrémente le compteur de fragments pour chaque nouveau fragment.
arp1.FCfield |= 0x4
arp2.SC = 0
wrpcap('crypted_pkt_frag.pcap', arp1, append=True)
arp2.FCfield |= 0x4
arp2.SC += 1 
wrpcap('crypted_pkt_frag.pcap', arp2, append=True)
arp3.FCfield &= 0xB
arp3.SC += 1
wrpcap('crypted_pkt_frag.pcap', arp3, append=True)


