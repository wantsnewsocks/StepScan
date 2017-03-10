#!/usr/bin/env python
'''
 _________ __                    _________
 /   _____//  |_  ____ ______    /   _____/ ____ _____    ____
 \_____  \\   __\/ __ \\____ \   \_____  \_/ ___\\__  \  /    \
 /        \|  | \  ___/|  |_> >  /        \  \___ / __ \|   |  \
/_______  /|__|  \___  >   __/  /_______  /\___  >____  /___|  /
        \/           \/|__|             \/     \/     \/     \/
                       ___________              
                       \__    ___/_  _  ______  
                         |    |  \ \/ \/ /  _ \     Version 1.0
                         |    |   \     (  <_> )        WNS
                         |____|    \/\_/ \____/ 
                         
Host scanner utilising unicornscan, NMAP
'''
import argparse
import ipaddress
import re

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
print "STEP SCAN TWO - HOST SCANNER"
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

def defaultScanHost(ip,speed = 300):
    results=[]
    cmds={"TCP":{"cmd":"unicornscan -mT -R2 -r {speed} {ip} 2>/dev/null".format(**vars()),"msg":"%s TCP Scan"%ip,"results":results},
    "UDP":{"cmd":"unicornscan -mU -R2 -r {speed} {ip} 2>/dev/null".format(**vars()),"msg":"%s UDP Scan"%ip,"results":results}}        
    try:
        execCmd(cmds)
    except Exception as e:
        return ip,cmds,str(e)
    else:
        return ip,cmds,None

def main(args):
    print "[*] DETERMINING HOSTS..."
    ipList = args.ips
    print "[+] " + "\n[+] ".join(ipList)

    print "\n[*] PERFORMING DEFAULT SCAN..." 
    scanResults = []       
    for ip,defaultScan,error in map(defaultScanHost, ipList):
        if error is None: #no error
            scanResults.append((ip, defaultScan))
            printResults(defaultScan)

    print "\n[*] PERFORMING NMAP TCP SCAN..."   
    results = []
    portPattern = re.compile('([0-9]{1,5})]')    
    for ip, scanResult in scanResults:        
        #for tcpports in scanResult["TCP"]["results"]:
        tcpports = ",".join(scanResult["TCP"]["results"])
        portString = ",".join(portPattern.findall(tcpports))
        cmd = cmds={"NMAP":{"cmd":"nmap -sS -sV -sC -Pn -p %s %s 2>/dev/null"%(portString, ip),"msg":"%s NMAP Scan"%ip,"results":results}}
        execCmd(cmd)
        printResults(cmd)

    
if __name__ == "__main__":
    #Parse arguments
    parser = argparse.ArgumentParser(prog='step2.py', description='Step Scan Two - Host Scanner')
    parser.add_argument('ips', metavar='ips', type=str, nargs="*", help='a IP(s) to scan (eg. 10.1.1.1 10.1.1.2 ...')
    args = parser.parse_args()
    main(args)
