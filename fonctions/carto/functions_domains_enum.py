#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import os

from fonctions.audit.carto import functions_domains_enum_wildcard
from fonctions.config import functions_conf
from fonctions.config import functions_fichiers
from fonctions.config import functions_parsing
from fonctions.config import functions_rapport
from fonctions.config import functions_system


def audit_domains(domaine, fichier_domaine):
    functions_rapport.create_reports(domaine)
    if not os.path.exists(fichier_domaine):
        list_dom = []
        dns_recon_vuln(domaine) # test si vulnerabilites sur le dns
        check = dns_recon_check(domaine)
        if check != "wildcard":
            list_dnsrecon = dns_recon(domaine, "dnsrecon_enum")
            list_sublister = recup_domain_sublister(domaine)
            list_acamar = recup_domain_acamar(domaine)
            if list_sublister is None: list_sublister = []
            if list_acamar is None: list_acamar = []
            if list_dnsrecon is None: list_dnsrecon = []
            print("acamar " + str(list_acamar))
            print("sublister " + str(list_sublister))
            print("dnsrecon " + str(list_dnsrecon))

            list_dom = list_sublister + list_acamar + list_dnsrecon
            list_dom.sort()
        else:
            list_dom = functions_domains_enum_wildcard.manage_wildcard(domaine)

        print("\n Liste des sous-domaines associés à " + domaine + " \n")
        list_dom = functions_parsing.remove_duplicates(list_dom)
        list_dom = remove_domains_not_valid(list_dom)
        domaines = ""
        for z in range(0, len(list_dom)):
            domaines = domaines + list_dom[z].lower() + "\n"
        print(domaines)
        print("\n \n Fin des sous-domaines \n")
        if os.path.exists(fichier_domaine): os.remove(fichier_domaine)
        functions_fichiers.ecrire_fichier(fichier_domaine, domaines)
        print("fichier des domaines ecrit dans :" + fichier_domaine)
        os.system("cat " + fichier_domaine)


def dns_recon(domain, outil):
    check = "ok"
    list_dom = []
    cfg_pentest = functions_conf.get_cfg_osint()
    cmd = cfg_pentest.get("DNSRECON_ENUM", 'dnsrecon_enum')
    check = dns_recon_check(domain)  # check dnssec, check wildcard

    dir_rapport = "audits/" + domain + "/enum/"
    nom_rapport = os.path.abspath(os.getcwd()) + "/" + dir_rapport + "dnsrecon_" + domain + ".json"
    wordlist_dns = os.path.abspath(os.getcwd()) + "/outils/wordlists/subdomains-top1mil-20000.txt"

    cmd = cmd.replace("<domain>", domain)
    cmd = cmd.replace("<file_report>", nom_rapport)
    cmd = cmd.replace("<wordlist>", wordlist_dns)
    cmd = cmd.replace('\"', "")
    cmd = functions_parsing.remove_colors_output(cmd)

    timeout = 600  # 10 minutes
    print(cmd)
    if outil == "dnsrecon_enum":
        os.system(cmd)
    else:
        functions_system.lancer_cmd_with_timeout(cmd, timeout)
    if os.path.exists(nom_rapport):
        print("scan " + outil + " fini")
        print("analyse du rapport " + outil + " fini : " + nom_rapport)
        list_dom = analyse_report_dnsrecon_zone(nom_rapport, domain, "dnsrecon_dom")
    else:
        print("Le fichier scan " + outil + " : " + str(nom_rapport) + " n\'existe pas")
    return list_dom


def dns_recon_vuln(domain):
    fichier_dns_vuln = "audits/" + domain + "/vulns/dns_vuln_" + domain + ".xml"
    if not os.path.exists(fichier_dns_vuln):
        print ("Recherche des vulnerabilites DNS")
        vulns = []
        dir_rapport = "audits/" + domain + "/enum/"
        nom_rapport = os.path.abspath(os.getcwd()) + "/" + dir_rapport + "dnsrecon_vuln_" + domain + ".json"
        cfg_pentest = functions_conf.get_cfg_osint()
        cmd = cfg_pentest.get("DNSRECON_ZONE", 'dnsrecon_zone')
        cmd = cmd.replace("<domain>", domain)
        cmd = cmd.replace("<file_report>", nom_rapport)
        cmd = cmd.replace('\"', "")
        print(cmd)
        resultat = functions_system.lancer_cmd(cmd)
        print(resultat)
        vulns = analyse_report_dnsrecon_zone(nom_rapport, domain, "dnsrecon_transfert")
        if resultat.find("DNSSEC is not configured") != -1:
            print("\n VULN : Pas de DNSSEC active\n") 
            vulns.append(domain+"|||"+"dns-nodnssec"+"|||"+cmd+"|||"+""+"|||"+"1") #criticite faible
            #domain,nom_vuln,cmd,resultat,criticite

        gen_vuln_dns(domain,vulns)
    else:
        print ("test des vulnerabilites dns deja fait")

def dns_recon_check(domain):
    vulns = []
    cfg_pentest = functions_conf.get_cfg_osint()
    cmd = cfg_pentest.get("DNSRECON_CHECK", 'dnsrecon_check')
    cmd = cmd.replace("<domain>", domain)
    cmd = cmd.replace('\"', "")
    print(cmd)
    resultat = functions_system.lancer_cmd(cmd)
    print(resultat)
    if resultat.find("Wildcard resolution is enabled on this domain") != -1:
        print("wildcard active ! ")
        return "wildcard"
    else:
        return "ok"

def analyse_report_dnsrecon_zone(report_file, domain, cmd):
    vulns = []
    if os.path.exists(report_file):
        filejson = open(report_file, "r")
        jsonn = filejson.read()
        filejson.close()
        results = []
        list_domains = []
        photon_data = json.loads(jsonn)
        for item in photon_data:
            ns_server = item.get("ns_server")
            name_server = item.get("name")
            type_server = item.get("type")
            address_server = item.get("address")
            zt = item.get("zone_transfer")
            if zt == "success":
                print("\n VULN : zone transfer success pour le serveur " + str(ns_server)+ "\n") 
                vulns.append(domain+"|||"+"dns-transfert_zone"+"|||"+cmd+"|||"+str(ns_server)+"|||"+"2")
                #domain,nom_vuln,cmd,resultat,criticite
            if name_server != None and domain in name_server and type_server != "NS" :
                list_domains.append(name_server)
    else:
        print ("le fichier "+report_file + " nexiste pas")

    if cmd == "dnsrecon_dom" : #dsnrecon pour recup les serveurs
        return list_domains
    if cmd == "dnsrecon_transfert": #dnsrecon pour s'il y a un transfert de zone
        return vulns


def recup_domain_sublister(domain):
    outil = "sublister"
    cfg_pentest = functions_conf.get_cfg_osint()
    print("scan " + outil + " sur " + str(domain))
    dir_rapport = "audits/" + domain + "/enum/"
    nom_rapport = dir_rapport + "sublister_" + domain + ".txt"
    print(nom_rapport)
    cmd = cfg_pentest.get("SUBLIST3R_CMD", 'sublist3r_cmd')
    cmd = cmd.replace("<domain>", domain)
    cmd = cmd.replace("<file_report>", nom_rapport)
    cmd = cmd.replace('\"', "")
    if os.path.exists(nom_rapport): os.remove(nom_rapport)

    os.system(cmd)
    list_sublister = []

    print("scan " + outil + " fini")
    print("analyse du rapport " + outil + " fini : " + nom_rapport)
    if os.path.exists(nom_rapport):
        list_sublister = analyse_report_sublister(nom_rapport, domain, outil)
    return list_sublister


def recup_domain_acamar(domain):
    outil = "acamar"
    cfg_pentest = functions_conf.get_cfg_osint()
    print("scan " + outil + " sur " + str(domain))
    acamar_dir = cfg_pentest.get("ACAMAR_DIR", 'acamar_dir').replace('\"', "")
    if not os.path.exists(acamar_dir): os.mkdir(acamar_dir)
    nom_rapport = cfg_pentest.get("ACAMAR_DIR", 'acamar_dir') + domain + ".txt"
    nom_rapport = nom_rapport.replace('\"', "")
    cmd = cfg_pentest.get("ACAMAR", 'acamar')
    cmd = cmd.replace("<domain>", domain)
    cmd = cmd.replace('\"', "")
    if os.path.exists(nom_rapport): os.remove(nom_rapport)
    print(cmd)
    list_acamar = []
    os.system(cmd)
    print("scan " + outil + " fini")
    if os.path.exists(nom_rapport):
        list_acamar = analyse_report_acamar(nom_rapport, domain, outil)
    return list_acamar


def analyse_report_sublister(report_file, domaine, outil):
    list_domains = []
    with open(report_file, 'r') as f:
        print(f)
        for line in f:
            sdomain = line.rstrip('\n\r')
            sdomain1 = ""
            sdomain2 = ""
            sdomain3 = ""
            sdomain4 = ""
            sdomain5 = ""

            # entetes
            if sdomain.find("<BR>") != -1:
                if sdomain.count("<BR>") == 1:
                    sdomain, sdomain2 = sdomain.split("<BR>")
                elif sdomain.count("<BR>") == 2:
                    sdomain, sdomain2, sdomain3 = sdomain.split("<BR>")
                elif sdomain.count("<BR>") == 3:
                    sdomain, sdomain2, sdomain3, sdomain4 = sdomain.split("<BR>")
                elif sdomain.count("<BR>") == 4:
                    sdomain, sdomain2, sdomain3, sdomain4, sdomain5 = sdomain.split("<BR>")
            if sdomain.find("<BR>") == -1:
                list_domains.append(sdomain)
            if sdomain != "": list_domains.append(sdomain)
            if sdomain2 != "": list_domains.append(sdomain2)
            if sdomain3 != "": list_domains.append(sdomain3)
            if sdomain4 != "": list_domains.append(sdomain4)
            if sdomain5 != "": list_domains.append(sdomain5)
    return list_domains


def analyse_report_acamar(report_file, domaine, outil):
    list_domains = []
    with open(report_file, 'r') as f:

        for line in f:
            sdomain = line.rstrip('\n\r')

            # entetes
            print(sdomain)
            if sdomain.find(domaine) != -1:
                if sdomain.find("Acamar.py") == -1:
                    list_domains.append(sdomain)
    print(str(list_domains))
    return list_domains


def ajout_ip_domain_first_method(domaine, list_dom):
    ips = []
    for z in range(0, len(list_dom)):
        try:
            answers = dns.resolver.query(list_dom[z])
            for rdata in answers:
                ips.append(rdata.to_text())
                print(list_dom[z] + " " + rdata.to_text())
        except:
            print("erreur lors de la recuperation d'ip sur " + list_dom[z])
    print(str(ips))
    return ips


def ajout_ip_domain_second_method(domaine, list_dom):
    ips = []
    for z in range(0, len(list_dom)):
        try:
            data = socket.gethostbyname_ex(d)
            ipx = repr(data[2])
            print(ipx)
            input()
            ips.append(ipx)
        except Exception:
            # fail gracefully!
            print("error")
    return ips


def remove_domains_not_valid(list_domains):
    domain_exception = ["google", "ovh.net", "ultradns.", "gandi.net", "anycast.me", "ui-dns.", "cloudflare.com",
                        "googlemail.com", "icodia.com", "oleane.net", "vadesecure.com", "altospam.com", "evxonline.net",
                        "syrhano.net", "mx-cloud.hosting", "online.net", "amenworld.com", "localhost", "lasotel.net",
                        "security-mail.net", "outlook.com", "webedia-group.net", "avancenet.net", "nameshield.net",
                        "outlook.com", "edgekey.net", "enterpriseregistration", "office.com", "cloudflare.net",
                        "cloudflare.com", "root-servers.net"]
    domains_good = []
    for y in range(0, len(list_domains)):
        domain_checked = list_domains[y]
        good = 1
        for i in range(0, len(domain_exception)):
            if domain_exception[i] in domain_checked:
                good = 0
                print("domaine non valide " + domain_checked)
        if good == 1:
            domains_good.append(domain_checked)

    return domains_good


def gen_vuln_dns(domain,vulns_dns):
    functions_rapport.create_reports(domain)
    fichier_dns_vuln = "audits/" + domain + "/vulns/dns_vuln_" + domain + ".xml"
    xml_infos = "<vuln_dns>" + "\n" + " <domain>" + domain + "</domain>" + "\n"
    if len(vulns_dns) > 0:
        old_hostname = ""
        for z in range(0, len(vulns_dns)):
            domain,vuln,cmd,result,criticite = vulns_dns[z].split("|||") #domain,nom_vuln,cmd,resultat,criticite
            xml_infos += " <trace_dns>" + "\n"    
            xml_infos += "  <domain_dns>" + domain + "</domain_dns>\n"    
            xml_infos += "  <vuln_dns>" + vuln + "</vuln_dns>\n"    
            xml_infos += "  <cmd_dns>" + cmd + "</cmd_dns>\n"    
            xml_infos += "  <result_dns>" + result + "</result_dns>\n"    
            xml_infos += "  <criticite_dns>" + criticite + "</criticite_dns>\n"    
            xml_infos += " </trace_dns>" + "\n"
    else:
        xml_infos += " <trace_dns>Pas de vulnerabilites dns detectees</trace_dns>" + "\n"
    xml_infos += "</vuln_dns>"
    print ("fichiers des vulns dns ecrit dans " + fichier_dns_vuln)
    functions_fichiers.ecrire_fichier(fichier_dns_vuln, xml_infos)