#!/usr/bin/python3
import nmap
import socket
import sys
import os
import pyfiglet
import nmap3
import platform
from time import sleep as timeout

scanner = nmap.PortScanner()

def restart_program():
    python = sys.executable
    os.execl(python, python, *sys.argv)

banner1 = pyfiglet.figlet_format("............ NMAP ...........")
print(banner1)


print("                         Welcome To NMAP Automation Tool                    ")
print("<....................................................................................................................>")


while True:

    mode = input("""\nEnter the type of scan!!!
                  1 ) URL TO IP
                  2 ) ALL NETWORK Scan
                  3 ) NORMAL Scan
                  4 ) AGGRESSIVE Scan \nEnter your option : """)

    print("\nYou have selected option: ", mode)


    if mode == '1':
        os.system('clear')
        banner2 = pyfiglet.figlet_format("..Domain..LookUP.")
        print(banner2)
        url = input("Enter the URL ( *_Example: google.com ) : ")
        print("IP :", socket.gethostbyname(url))




    elif mode == '2':

        os.system('clear')
        a = platform.system()
        if a == 'Windows':
            print(os.system('ipconfig'))
        elif a == 'Linux':
            print(os.system('ifconfig'))
        elif a == 'Darwin':
            print(os.system('ifconfig'))

        ip = input("Enter the IP Range *_Example( 1.1.1.0/24 ) : ")
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip, arguments='-n -sP -PE -PA21 ,23,80,3389')
        ip_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
        for host, status in ip_list:
            print(host,':',status)

    elif mode == '3':
        os.system('clear')
        a = platform.system()
        if a == 'Windows':
            print(os.system('ipconfig'))
        elif a == 'Linux':
            print(os.system('ifconfig'))
        elif a == 'Darwin':
            print(os.system('ifconfig'))

        ip = input("Enter the IP address : ")
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip, '1-1024', arguments='-v -sS')
        for host in scanner.all_hosts():
            print('Host : %s (%s)' % (ip, scanner[ip].hostname()))
            print('State : %s' % scanner[host].state())
            for proto in scanner[ip].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)

                lport = scanner[ip][proto].keys()
                lport = sorted(lport)
                for port in lport:
                    print('port : %s\t%s\t%s' % (port, scanner[ip][proto][port]['state'], scanner[ip][proto][port]['name']))

    elif mode == '4':

        os.system('clear')
        a = platform.system()
        if a == 'Windows':
            print(os.system('ipconfig'))
        elif a == 'Linux':
            print(os.system('ifconfig'))
        elif a == 'Darwin':
            print(os.system('ifconfig'))

        ip_add = input("Enter the ip address : ")
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_add, '1-1024', arguments='-A')
        nmap = nmap3.NmapScanTechniques()
        results = nmap.nmap_tcp_scan(ip_add, args="-A")
        print('Host : %s (%s)' % (ip_add, scanner[ip_add].hostname()))
        print('State : %s\n' % scanner[ip_add].state())
        i=0
        while i<len(results[ip_add]):

            ser = results[ip_add][i]['service']
            print('port: %s\t%s\t%s\t%s |\t%s' % (results[ip_add][i]['portid'],results[ip_add][i]['state'],ser['name'],ser['product'],ser['version']))
            i = i+1
        os_det = results['os']
        os_cl = os_det[0]['osclass']
        print('\nOperating System: ',os_det[0]['name'],'\tAccuracy: ',os_det[0]['accuracy'])
        print('Vendor: ',os_cl['vendor'])
        print('OS gen: ',os_cl['osgen'],'\tAccuracy: ',os_cl['accuracy'])
        print('CPE: ',os_det[0]['cpe'])
    elif mode >= '5':
        print("Enter a valid option")
    elif mode == '0':
        print("Enter a valid option")
    else:
        timeout(3)
        restart_program()