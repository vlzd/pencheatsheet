<p align="center">
  Pentest-Cheat-Sheets<br>
</p>

##[RECONNAISSANCE PASSIVE / OSINT:]

      dnsdumpster https://dnsdumpster.com/
      
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




RECONNAISSANCE ACTICE / ENUMERATION

-sudo netdiscover -r 192.168. -i eth0
(eliminer les mac vmware workstation)

-ping de l'adresse trouvée pour vérifier si ping up 
  vérifier le TTL pour trouver si linux ou windows:
    Unix / Linux – 0-64
    Windows – 64-128
    Cisco/Solaris/AIX – 128-265

nmap -sV -O 192.168xx -vvv
  banner grabbing + reconnaissance d'OS si besoin

nmap --script=http-robot.txt 192.168xx -vvv
    location des scripts NSE (nmap script engine) locate *.nse

-nikto -host http://192.168..
  recherche de repertoires
  reconnaisance de vulnerabilites
  rechercher dans l'OSVDB

-dirb http:// 
  juste pour indexer les repertoires

-Zaproxy
  webapp scanner
  
-burp
INJECTIONS WEB

  XSS : https://github.com/mandatoryprogrammer/xsshunter-express

REVERSE SHELL:

https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php





