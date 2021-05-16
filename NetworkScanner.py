#!/usr/bin/python

import scapy.all as scapy
from scapy.layers.l2 import ARP
import argparse
import re
import sys

def GetArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", dest="Ip", help="Target Ip / Ip range")
    arguments = parser.parse_args()
    if not arguments.Ip:
        parser.error("[-] Please specify a target ip or ip range, use --help for more info")
    else:
        return arguments

def validateIP(ip):
    ipv4 = '''^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)+[/]([0-9]|1[0-9]|2[0-4]))$'''
    matched = re.match(ipv4,ip)
    if matched is None:
        print("[-] Please specify a valid ip address")
        sys.exit(1)


def Scan(ip):
    arpRequest = ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arpBroadcastPacket = broadcast/arpRequest
    responseList = scapy.srp(arpBroadcastPacket, timeout=1, verbose=False)[0]
    clientList = []
    for element in responseList:
        clientDict = {"Ip" : element[1].psrc, "Mac" : element[1].hwsrc}
        clientList.append(clientDict)
    return clientList

def PrintResult(resultList):
    print("IP\t\t\t|MAC Address\n------------------------------------------")
    for client in resultList:
        print(client["Ip"] + "\t\t" + client["Mac"])

arguments = GetArguments()
validateIP(arguments.Ip)
scanResult = Scan(arguments.Ip)
PrintResult(scanResult)