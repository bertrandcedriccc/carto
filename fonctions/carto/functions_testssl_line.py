#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Utilisation fuzzing
import fnmatch
import operator
import os
import sys

import simplejson
import shutil
from fonctions.audit.carto import functions_carto
from fonctions.config import functions_conf
from fonctions.config import functions_fichiers
from fonctions.config import functions_rapport
from fonctions.config import functions_system


#bdd des vulns de testssl et harmonisation des criticites
#id, categ,criticite
vuln_testssl = [ 
##################### CIPHERS / ALGOS #####################
    ["certs_list_ordering_problem","algos",1], 
    ["cipherlist_3des_idea","algos",1], #Triple DES Ciphers (Medium)  
    ["cipherlist_average","algos",1], #Triple DES Ciphers (Medium)  
    ["cipherlist_strong","algos",1], 
    ["cipher_order","algos",1], 
    ["cipher_negotiated","algos",1], 
    ["cipher*","algos",1], 
    ["dh_groups","algos",1], #MODP group with safe prime modulus
    ["order_cipher","algos",1], #MODP group with safe prime modulus
    ["order","algos",1], #MODP group with safe prime modulus
    ["sslv2","protocole",2],
    ["sslv3","protocole",2],
    ["std_","algos",1], #MODP group with safe prime modulus
    ["std_null","algos",1], #NULL ciphers
    ["std_anull","algos",1], #Anonymous NULL Ciphers (no authentication)
    ["std_128bit","algos",1], #Weak 128 Bit ciphers (SEED, IDEA, RC[2,4]) 
    ["std_3des","algos",1], #Weak 128 Bit ciphers (SEED, IDEA, RC[2,4]) 
    ["tls1","protocole",2],
    ["tls1_1","protocole",2],

##################### HARDENING #####################
    ["content-security-policy","hardening",1], 
    ["cookie_count","hardening",1], 
    ["hsts","hardening",1], #HTTP Strict Transport Security
    ["hpkp","hardening",1], #No support for HTTP Public Key Pinning
    ["hpkp_spkimatch","hardening",1], #No support for HTTP Public Key Pinning
    ["ocsp_stapling","hardening",1], #OCSP stapling 
    ["ocsp_","hardening",1], #OCSP stapling 
    ["ocsp*","hardening",1],
    ["pfs","hardening",1], #(Perfect) Forward Secrecy : PFS is offered
    ["pfs_ciphers","hardening",1], #Forward Secrecy Ciphers: ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-SHA384 ECDHE-RSA-CHACHA20-POLY1305 
    ["pfs_ecdhe_curves","hardening",1], #Forward Secrecy Ciphers: ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-SHA384 ECDHE-RSA-CHACHA20-POLY1305 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-SHA256
    ["security_headers","hardening",1], #security headers
    ["sec_headers","hardening",1], #security headers
    ["app_banner","hardening",1], #detection de la banniere
    ["server_header","hardening",1], #Server banner in header
    ["rp_header","hardening",1], #detection reverse proxy
    ["x-frame-options","hardening",1], #X-Frame-Options
    ["x-frame-options_multiple","hardening",1], #X-Frame-Options
    ["x-xss-protection","hardening",1], #X-XSS-Protection
    ["x-xss-protection_multiple","hardening",1], #X-XSS-Protection
    ["x-content-type-options","hardening",1], #X-Content-Type-Options:  nosniff"
    ["x-content-type-options_multiple","hardening",1], #X-Content-Type-Options:  nosniff"

##################### CERTIFICAT #####################
    ["cert_trust","certificat",2], #certificate does not match supplied URI (same w/o SNI)
    ["cert_","certificat",2], #certificate does not match supplied URI (same w/o SNI)
    ["certificate*","certificat",1], #recherche generique certificat
    ["certcount","certificat",2], 
    ["certificate_transparency","certificat",1], #Certificate Transparency
    ["cn","certificat",2],
    ["chain_of_trust","certificat",2], 
    ["crl","certificat",2], #All certificate trust checks passed
    ["ev","certificat",1], #Extended Validation (EV) (experimental)
    ["expiration","certificat",2], #Certificate Expiration : expires < 30 days (
    ["issuer","certificat",2], #"Issuer:
    ["trust","certificat",2], #k via SAN and CN  
    ["san","certificat",2],
    ["caa_record*","certificat",1], #DNS Certification Authority Authorization (CAA) Resource Record / RFC6844 : not offered
    ["dns_caarecord","certificat",1], #with CAA record can specify which Certificate Authorities are allowed to issue certificates for your domain names.

##################### VULNS #####################
    ["beast","vuln",1], 
    ["beast_cbc_tls1","vuln",1], 
    ["cbc_tls1","vuln",1], #BEAST: CBC ciphers for TLS1: ECDHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA AES128-SHA AES256-SHA
    ["cbc_ssl3","vuln",1], #BEAST: CBC ciphers 
    ["breach","vuln",1], 
    ["ccs","vuln",2],
    ["crime","vuln",1], 
    ["drown","vuln",1], 
    ["fallback_scsv","vuln",1], #TLS_FALLBACK_SCSV (RFC 7507): Downgrade attack prevention NOT supported
    ["freak","vuln",1], 
    ["heartbleed","vuln",3],
    ["insecure_redirect","vuln",1], 
    ["logjam","vuln",1],
    ["logjam_common primes","vuln",1],
    ["logjam-common_primes","vuln",1],
    ["lucky13","vuln",1],
    ["poodle_ssl","vuln",1], 
    ["protocol_negotiated","vuln",1], #Secure Client-Initiated Renegotiation 
    ["rc4","vuln",1],
    ["robot","vuln",1],
    ["secure_nego","vuln",1],  
    ["secure_renego","vuln",1], #Secure Renegotiation
    ["sec_client_renego","vuln",1], #Secure Client-Initiated Renegotiation 
    ["secure_client_renego","vuln",1], #Secure Client-Initiated Renegotiation 
    ["sweet32","vuln",1],
    ["ticketbleed","vuln",2], 
    ["tls_session_ticket","vuln",1] #Secure Client-Initiated Renegotiation 
    
    ]

def lancer_testssl(domaine):
    """
    Args:
        domaine:
    """
    functions_rapport.create_reports(domaine)
    fichier_domaine = f"audits/{domaine}/domaines_{domaine}.txt"
    fichier_carto = f"audits/{domaine}/carto_{domaine}.xml"
    fichier_vuln = f"audits/{domaine}/vulns/ssl_vuln_{domaine}.xml"
     #f"audits/{domaine}/vulns/vuln_ssl_{domaine}.xml"
    dir_nmap = f"audits/{domaine}/nmap/"
    cfg_pentest = functions_conf.get_cfg_pentest()
    cmd_testssl = cfg_pentest.get("TESTSSL_CMD", 'testssl_cmd').replace('"', "")

    if not os.path.exists(fichier_domaine):
        print("l'enumeration des sous-domaines sur " + domaine + " n'a pas ete faite, il faut la faire avant")
        sys.exit()
    if not os.path.exists(fichier_carto):
        print("La cartographie du domaine " + domaine + " na pas ete faite, necessaire pour detecter les services ssl")
        sys.exit()
    dir_testssl = f"audits/{domaine}/testssl/"
    if not os.path.exists(dir_testssl):
        os.mkdir(dir_testssl)

    fichier_scan = f"audits/{domaine}/liste_domaines_testssl_{domaine}_not_scanned_.txt"
    sous_dom = recup_domains_not_scanned(fichier_domaine, dir_testssl, dir_nmap, domaine)

    all_sous_dom = ""
    if len(sous_dom) > 0:
        for x in range(0, len(sous_dom)):
            print("scan " + str(x + 1) + " / " + str(len(sous_dom)) + "\n")
            print("scan testssl du domaine " + sous_dom[x])
            cmd = cmd_testssl.replace("<ip>", sous_dom[x])
            cmd = cmd.replace("<file>", dir_testssl + sous_dom[x] + "_testssl.xml")
            print(cmd)
            functions_system.lancer_cmd_with_timeout(cmd, 1200)
            print("scan testssl du domaine " + sous_dom[x] + " terminee \n")
    # os.system(cmd)
    print("tous les domaines ont ete scannes avec testssl")
    print("generation de la cartographie ssl")
    gen_synthese_vuln_xml(domaine, dir_testssl, fichier_vuln)


def recup_domains_not_scanned(fichier_domaine, dir_testssl, dir_nmap, domaine):
    """
    Args:
        fichier_domaine:
        dir_testssl:
        dir_nmap:
        domaine:
    """
    domain_not_scanned = []
    nb_domains_scanned = 0
    https = recup_services_ssl(dir_nmap)
    # functions_scans.recup_id_scan(domain,"testssh",str(domain)+":"+str(port))) == "0":
    for x in range(0, len(https)):
        sousdomaine = https[x]
        # print (sousdomaine)
        nom_rapport_testssl = dir_testssl + sousdomaine + "_testssl.xml"
        if not os.path.exists(nom_rapport_testssl):
            domain_not_scanned.append(sousdomaine)
    # else:
    #    print ("Le domaine " + sousdomaine + " a deja ete scanne avec testssl")
    return domain_not_scanned


def recup_services_ssl(dir_nmap):
    """
    Args:
        dir_nmap:
    """
    ssl = []
    pattern = "*" + ".xml"
    for path, dirs, files in os.walk(os.path.abspath(dir_nmap)):
        for filename in fnmatch.filter(files, pattern):
            nmap_file = os.path.join(path, filename)
            https, target = functions_carto.check_if_https(nmap_file)
            if https == 1:
                ssl.append(filename.replace("_nmap.xml", ""))
        # else:
        #    print ("pas de ssl sur " +target)
    # except:
    #	print ("erreur lors du parsing du fichier")
    #	https = 0
    return ssl


def gen_synthese_vuln_xml(domaine, dir_testssl, fichier_vuln):
    """
    Args:
        domaine:
        dir_testssl:
        fichier_vuln:
    """
    if os.path.exists(dir_testssl):
        if not os.path.exists(fichier_vuln):
            # print(("generation des vulns ssl pour "+domaine))
            xml_infos = "<ssl>" + "\n" + " <domain>" + domaine + "</domain>" + "\n"

            pattern = "*_testssl.xml"
            for path, dirs, files in os.walk(os.path.abspath(dir_testssl)):
                for filename in fnmatch.filter(files, pattern):
                    file_report = os.path.join(path, filename)
                    print("analyse du fichier " + file_report)
                    host = filename.replace("_testssl.xml", "")
                    check_file_json(file_report)
                    infos = extract_infos_from_testssl(file_report, host)
                    if infos != "":
                        xml_infos = xml_infos + infos

            xml_infos += "</ssl>"
            functions_fichiers.ecrire_fichier(fichier_vuln, xml_infos)
            print(("la carto ssl a ete generee dans le fichier " + fichier_vuln))



def extract_infos_from_testssl(file_report, host):
    """
    Args:
        file_report:
        host:
    """
    ssl = 0
    vulns = []
    xml_infos = " <sdomain>" + "\n"
    xml_infos += "  <host>" + host + "</host>" + "\n"

    filejson = open(file_report, "r")
    json = filejson.read()
    filejson.close()
    v = json.replace("[\n", '{\"domain_testssh\": [')
    json = v.replace("]", "]}")
    try:
        response_dict = simplejson.loads(json)
        results = response_dict.get('domain_testssh')  # make dictionary for the scan results
        for item in results:
            req = ""
            id_p = item.get("id").lower()
            severity = item.get("severity")
            output = item.get("finding").lower()
            ip = item.get("ip")
            cve = item.get("cve")
            if cve is None:
                cve = "Pas de CVE associee"
            if cve.find("<") != -1 or cve.find(">") != -1:
                cve += "<![CDATA[" + str(cve) + "]]"
            port = item.get("port")
            if severity == "CRITICAL" or severity == "HIGH" or severity == "MEDIUM" or severity == "LOW":
                criticite,categ = recup_criti_from_base(id_p,severity)
                if output.find(">") != -1 or output.find("<") != -1 or output.find("=") != -1:
                    output = "<![CDATA[" + output + "]]>"

                if output.find("not supported by local openssl") == -1:
                    vulns.append([ip, criticite, id_p, output, cve,categ])

                else:
                    ssl = 1
    except:
        pass
        #print("Unexpected error:", sys.exc_info()[0])
        #print("erreur lors de l'analyse report testssl")
        #check_file_json(file_report)

    # vulns = functions_parsing.remove_duplicates(vulns)
    xml_infos += "  <vulns_ssl>" + "\n"
    if len(vulns) == 0:
        xml_infos += "   <vuln_ssl>Pas de vulnerabilites detectees / Erreur lors de l'analyse du fichier</vuln_ssl>\n"
    else:
        vulns_sorted = sorted(vulns, key=operator.itemgetter(1), reverse=True)  # tri par criticité
        for i in range(0, len(vulns_sorted)):
            # ip,criticite,nom_vuln,sortie,cve = vulns_sorted[i].split("|||")
            xml_infos += "   <vuln_ssl>" + "\n"
            xml_infos += "    <ip_vuln>" + vulns_sorted[i][0] + "</ip_vuln>" + "\n"
            xml_infos += "    <criticite_vuln>" + str(vulns_sorted[i][1]) + "</criticite_vuln>" + "\n"
            xml_infos += "    <nom_vuln>" + vulns_sorted[i][2] + "</nom_vuln>" + "\n"
            xml_infos += "    <resultat_vuln>" + vulns_sorted[i][3] + "</resultat_vuln>" + "\n"
            xml_infos += "    <cve_vuln>" + vulns_sorted[i][4] + "</cve_vuln>" + "\n"
            xml_infos += "    <categ_vuln>" + vulns_sorted[i][5] + "</categ_vuln>" + "\n"
            xml_infos += "   </vuln_ssl>" + "\n"

    xml_infos += "  </vulns_ssl>" + "\n"
    xml_infos += " </sdomain>" + "\n"

    if ssl == 1:
        print(
            "attention certains tests n'ont pas ete realises avec testssl a cause d'un souci avec la version d'openssl")
    return xml_infos


def check_file_json(file_to_test):

    """
    Args:
        file_to_test:
    """
    filejson = open(file_to_test, "r")
    json = filejson.read()
    filejson.close()
    v = json.replace("[\n", '{\"domain_testssh\": [')
    json = v.replace("]", "]}")
    try:
        response_dict = simplejson.loads(json)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        print("erreur lors de l'analyse report testssl")
        with open(file_to_test, "r") as f:
            file_str = str(f.read())
            f.close()
        last_chr = file_str[-1]
        #print(last_chr)
        if last_chr == "]":
            print("le dernier caractere est bien une ]")
        else:
            print("le dernier caractere nest pas ], correction")
            new_file_str = file_str+"\n]"
            #print (file_str)
            #print ("tentative de reecriture du fichier")
            shutil.copy(file_to_test, file_to_test+".bak")
            functions_fichiers.ecrire_fichier(file_to_test, new_file_str)



def recup_criti_from_base(id_p,severity):
    """
    Args:
     id_p       : id du plugin testssl
     severity   : criticite atribuee par testssl
    """

    for i in range(0, len(vuln_testssl)):
        if id_p == vuln_testssl[i][0] or id_p.startswith(vuln_testssl[i][0]):
                return vuln_testssl[i][2],vuln_testssl[i][1] #renvoi de la criticite et de la categ (harmonisation)
         #recherche generique pour certains mots clés car variation de testssl pour les ids - exemple : "Server Certificate #1 ocsp_stapling"
            #pas de possibilites de toujours faire une recherche generique car certains ids sont très courts
        if vuln_testssl[i][0].count("*") == 1 :
            mot_cle = vuln_testssl[i][0].replace("*","")
            if mot_cle in id_p : 
                return vuln_testssl[i][2],vuln_testssl[i][1] 

    print ("not found  "+ id_p)
    criticite =  convert_criti(severity)#si pas trouvee, on garde la criticite de base et on la convertit en nombre entier
    return criticite,"?" 



def convert_criti(criti):
    """
    Args:
        criti:
    """
    criticite = 0
    if criti == "CRITICAL":
        criticite = 4
    if criti == "HIGH":
        criticite = 3
    if criti == "MEDIUM":
        criticite = 2
    if criti == "LOW":
        criticite = 1
    return criticite
