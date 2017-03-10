#!/usr/bin/env python
'''
 _________ __                    _________
 /   _____//  |_  ____ ______    /   _____/ ____ _____    ____
 \_____  \\   __\/ __ \\____ \   \_____  \_/ ___\\__  \  /    \
 /        \|  | \  ___/|  |_> >  /        \  \___ / __ \|   |  \
/_______  /|__|  \___  >   __/  /_______  /\___  >____  /___|  /
        \/           \/|__|             \/     \/     \/     \/

                       ________
                       \_____  \   ____   ____
                        /   |   \ /    \_/ __ \
                        /    |    \   |  \  ___/    Version 1.0
                        \_______  /___|  /\___  >	    WNS
                                \/     \/     \/
Network Discovery scanner utilising NMAP, unicornscan
'''
import argparse
import ipaddress

# conditional import for older versions of python not compatible with subprocess
try:
    import subprocess as sub
    compatmode = 0 # newer version of python, no need for compatibility mode
except ImportError:
    import os # older version of python, need to use os instead
    compatmode = 1


bigline = "================================================================================================="
smlline = "-------------------------------------------------------------------------------------------------"

print bigline
print "STEP SCAN ONE - NETWORK DISCOVERY SCANNER"
print bigline
print

def execCmd(cmdDict):
    for item in cmdDict:
        cmd = cmdDict[item]["cmd"]
        if compatmode == 0: # newer version of python, use preferred subprocess
            out, error = sub.Popen([cmd], stdout=sub.PIPE, stderr=sub.PIPE, shell=True).communicate()
            results = out.split('\n')
        else: # older version of python, use os.popen
            echo_stdout = os.popen(cmd, 'r')
            results = echo_stdout.read().split('\n')
        cmdDict[item]["results"]=results
    return cmdDict

def printResults(cmdDict):
    for item in cmdDict:
        msg = cmdDict[item]["msg"]
        results = cmdDict[item]["results"]
        if msg is not None:
            print "[+] " + msg
        for result in results:
            if result.strip() != "":
                print "    " + result.strip()
        if msg is not None:
            print
    return

def determineIPs(ips):
    print "[*] DETERMINING NETWORK RANGE..."
    ipString = None
    if len(ips) == 1:
        ipString = ips[0]  
    print "[+] " + "\n[+] ".join(ips)
    return ipString


def main(args):
    ipString = determineIPs(args.ipnetwork)
    
    print "\n[*] PERFORMING NETWORK DISCOVERY..."
    results=[]
    discoScan = { "HOSTS":{"cmd":"nmap -sn -v %s -oG - | grep 'Status: Up' | cut -d ' ' -f 2 "%(ipString),"msg":"Discovered Hosts","results":results}}
    discoScan = execCmd(discoScan)
    printResults(discoScan)

    print "\n[*] DNS NETWORK DISCOVERY..."
    dnsnetScan = { "DNS":{"cmd":"nmap -sS -p 53 %s --script=dns-service-discovery -oG - | grep '53/open' | cut -d ' ' -f 2"%(ipString),"msg":"DNS Servers","results":results}}
    dnsnetScan = execCmd(dnsnetScan)
    printResults(dnsnetScan)

    print "\n[*] DNS REVERSE LOOKUP..."
    for dnsserver in dnsnetScan["DNS"]["results"]:
        try:
            isValidIP=True
            ipaddress.ip_address(unicode(dnsserver))                    
        except:
            isValidIP=False
        if isValidIP:
            dnsrevScan = { }
            print "\n[+] Reverse lookup for %s"%dnsserver 
            for ip in discoScan["HOSTS"]["results"]:
                dnsrevScan["%s-%s"%(dnsserver,ip)] = {"cmd":"dig +noall +answer @%s -x %s | sed 's/.in-addr.arpa.//' |awk '{ print $(1), $NF;}'"%(dnsserver,ip),"msg":None,"results":results}    
            dnsrevScan = execCmd(dnsrevScan)
            printResults(dnsrevScan)


if __name__ == "__main__":
    #Parse arguments
    parser = argparse.ArgumentParser(prog='step1.py', description='Step Scan One - Discovery Scanner')
    parser.add_argument('ipnetwork', metavar='networkip', type=str, nargs=1, help='an IP Network / CIDR value (eg 10.1.1.0/24)')
    args = parser.parse_args()
    main(args)


