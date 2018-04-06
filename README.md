# DerpNSpoof
![alt text](https://i.gyazo.com/2a689664b40478c031c718809b7e2b79.png)

Simple DNS Spoofing tool made in Python 3 with Scapy. You have to save the fake DNS records in a file and load it in when running the tool

## Usage

* Download it from git or use **_'git clone https://github.com/Trackbool/DerpNSpoof'_**
* You need the Scapy Python module, you can install it with pip: **_'pip3 install scapy'_**
* Scapy uses tcpdump
* To execute the tool, you will need root permissions

Help menu:

    [!] Options to use:
    	  <ip>  - Spoof the DNS query packets of a certain IP address
    	  <all> - Spoof the DNS query packets of all hosts
    [!] Examples:
    	  # python3 DerpNSpoof.py 192.168.1.20 myfile.txt
    	  # python3 DerpNSpoof.py all myfile.txt


The file format to save the records is very simple. You have to store the domain name, and separated by a space, the fake IP in the same line

| Domain to Spoof  | IP address    |
| -----------------|---------------|
| example.com      | 1.1.1.1       |
| example2.com     | 3.3.3.3       |
| example3.com     | 3.3.3.3       |


#### Note: 
If you are not allowed to capture another hosts packets, you have to carry out a Man in the Middle attack (P.E: ARP Spoofing,DHCP Spoofing) making use of another tools like arpspoof
https://github.com/byt3bl33d3r/arpspoof

Adrián Fernández Arnal (@adrianfa5)
Twitter: https://twitter.com/adrianfa5
