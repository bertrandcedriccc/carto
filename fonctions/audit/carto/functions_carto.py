#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fonctions relatives à la cartographie du domaine et de ses machines."""
import fnmatch
import os
import xml
from fonctions.audit.carto import functions_nmap
from fonctions.config import functions_fichiers
from xml.dom import minidom
from xml.dom.minidom import parse

def generate_carto(domaine, dir_rapport):
    """Generate cartography.

    Args:
        domaine:
        dir_rapport:
    """
    fichier_carto = "audits/" + domaine + "/carto_" + domaine + ".xml"
    functions_nmap.check_if_scan_nmap(domaine)
    if not os.path.exists(fichier_carto):
        print(("generation de la cartographie pour " + domaine))
        xml_infos = "<carto>" + "\n" + " <domain>" + domaine + "</domain>" + "\n"

        pattern = "*nmap*" + ".xml"
        for path, dirs, files in os.walk(os.path.abspath(dir_rapport)):
            for filename in fnmatch.filter(files, pattern):
                file_report = os.path.join(path, filename)
                infos = extract_infos_from_nmap(file_report, filename)

                if infos != "":
                    xml_infos = xml_infos + infos

        xml_infos += "</carto>"
        functions_fichiers.ecrire_fichier(fichier_carto, xml_infos)
        print("la carto a ete generee dans le fichier %s" % fichier_carto)


def extract_infos_from_nmap(file_nmap, filename):
    """Extract info from nmap scan results.

    Args:
        file_nmap:
        filename:
    """
    try:
        doc = xml.dom.minidom.parse(file_nmap)
        liste_ports = functions_nmap.extract_ports(file_nmap, "")
    except:
        return ""
    xml_infos = ""

    nom_site = filename.replace("_nmap.xml", "")
    xml_infos += " <site>\n"
    if '0 IP addresses (0 hosts up) scanned' in open(file_nmap).read():
        xml_infos += "  <nom_site>" + nom_site + " : domaine non resolu </nom_site>\n"
    else:
        xml_infos += "  <nom_site>" + nom_site + " </nom_site>\n"
    for host in doc.getElementsByTagName("host"):
        xml_infos += "  <sdomain>" + "\n"
        try:
            address = host.getElementsByTagName("address")[0]
            ip = address.getAttribute("addr")
            protocol = address.getAttribute("addrtype")

        except:
            print("error")
            continue

        try:
            mac_address = host.getElementsByTagName("address")[1]
            mac = mac_address.getAttribute("addr")
            mac_vendor = mac_address.getAttribute("vendor")
        except:
            mac = ""
            mac_vendor = ""

        try:
            hname = host.getElementsByTagName("hostname")[0]
            hostname = hname.getAttribute("name")
        except:
            hostname = ""

        xml_infos += "   <hostname>" + hostname + "</hostname>" + "\n"
        xml_infos += "   <ip>" + ip + "</ip>" + "\n"
        if '0 IP addresses (0 hosts up) scanned' in open(file_nmap).read():
            xml_infos += "   <etat>domaine non resolu</etat>" + "\n"
        if hostname == "" and ip == "":
            hostname = "unknown"
            ip = "unknown"
        try:
            status = host.getElementsByTagName("status")[0]
            state = status.getAttribute("state")
        except:
            state = ""

        try:
            os_el = host.getElementsByTagName("os")[0]
            os_match = os_el.getElementsByTagName("osmatch")[0]
            os_name = os_match.getAttribute("name")
            os_accuracy = os_match.getAttribute("accuracy")
            os_class = os_el.getElementsByTagName("osclass")[0]
            os_family = os_class.getAttribute("osfamily")
            os_gen = os_class.getAttribute("osgen")
        except:
            os_name = ""
            os_accuracy = ""
            os_family = ""
            os_gen = ""
        if os_name == "":
            os_name = "undetected"
        xml_infos += "   <os>" + os_name + "</os>" + "\n"
        ports = 0
        try:
            timestamp = host.getAttribute("endtime")
        except:
            timestamp = ""

        try:
            hostscript = host.getElementsByTagName("hostscript")[0]
            script = hostscript.getElementsByTagName("script")[0]
            id = script.getAttribute("id")

            if id == "whois":
                whois_str = script.getAttribute("output")
            else:
                whois_str = ""

        except:
            whois_str = ""

        try:
            ports = host.getElementsByTagName("ports")[0]
            ports = ports.getElementsByTagName("port")
            xml_infos += "   <services>" + "\n"
        except:
            continue
            ports = 0
            xml_infos += "  <services>Pas de services detectes </services>" + "\n"
        for port in ports:
            pn = port.getAttribute("portid")
            protocol = port.getAttribute("protocol")
            state_el = port.getElementsByTagName("state")[0]
            state = state_el.getAttribute("state")

            try:
                service = port.getElementsByTagName("service")[0]
                port_name = service.getAttribute("name")
                product_descr = service.getAttribute("product")
                product_ver = service.getAttribute("version")
                product_extra = service.getAttribute("extrainfo")
            except:
                service = ""
                port_name = ""
                product_descr = ""
                product_ver = ""
                product_extra = ""

            service_str = "%s %s %s" % (product_descr, product_ver, product_extra)
            banniere_nmap = service_str
            categorie, criticity = check_proto(port_name, banniere_nmap)
            if state == "open":
                ports = 1
                xml_infos += "    <service>" + "\n"
                xml_infos += "     <port>" + pn + "</port>" + "\n"
                xml_infos += "     <proto>" + port_name + "</proto>" + "\n"
                xml_infos += "     <banniere>" + banniere_nmap + "</banniere>" + "\n"
                xml_infos += "     <categorie>" + categorie + "</categorie>" + "\n"
                xml_infos += "     <criticite>" + str(criticity) + "</criticite>" + "\n"
                xml_infos += "    </service>" + "\n"

            filtre_output = ['  Supported Methods: ', '(http://drupal.org)', '\n', '\r', '(https://drupal.org)',
                             '(https://www.drupal.org)', '(CentOS)']
            for x in range(0, len(filtre_output) - 1):
                banniere_nmap = banniere_nmap.replace(str(filtre_output[x]), '')
            banniere_nmap = banniere_nmap.replace("'", "")
            banniere_nmap = banniere_nmap.replace("\"", "")
            banniere_nmap = banniere_nmap.replace("/", " ")

            info_str = ""
            for i in range(0, 5):
                try:
                    script = port.getElementsByTagName("script")[i]
                    script_id = str(script.getAttribute("id").rstrip('\n\r'))
                    script_output = script.getAttribute("output")
                except:
                    script_id = ""
                    script_output = ""

            if script_id != "" and script_output != "":
                info_str += "%s: %s\n" % (script_id, script_output)

            data = script_id.split('-')
            protocol = data[0]
            script_output = script_output.replace("'", "")
            script_output = script_output.replace("\"", "")
            script_output = script_output.replace("/", " ")

        xml_infos += "   </services>" + "\n"
        xml_infos += "  </sdomain>" + "\n"
    xml_infos += " </site>" + "\n\n"

    return xml_infos


def check_if_https(nmap_file):
    """detect if port 443 is open to check TLS config.

    Args:
        nmap_file:
    """
    hosts_ssl = []
    try:
        doc = xml.dom.minidom.parse(nmap_file)
    except:
        return 0, ""
    hostname = ""
    if os.path.exists(nmap_file):
        for host in doc.getElementsByTagName("host"):
            try:
                address = host.getElementsByTagName("address")[0]
                ip = address.getAttribute("addr")
                # print(("ip : " + str(ip)))
                protocol = address.getAttribute("addrtype")

            except:
                # print("error")
                continue

            try:
                hname = host.getElementsByTagName("hostname")[0]
                hostname = hname.getAttribute("name")
            except:
                hostname = ""
            if hostname == "":
                hostname = ip

            try:
                ports = host.getElementsByTagName("ports")[0]
                ports = ports.getElementsByTagName("port")
            except:
                return 0, ip

            for port in ports:
                pn = port.getAttribute("portid")
                protocol = port.getAttribute("protocol")
                state_el = port.getElementsByTagName("state")[0]
                state = state_el.getAttribute("state")
                if state == "open" and pn == "443":
                    return 1, hostname

    return 0, ""


def check_proto(protocole_check, banniere_check):
    """Check protocol and banner.

    TODO: handle categories and severity with a dictionary (may be defined in config)
    proto_category = {
      ...
      proto: {'category':category, 'severity': severity},
      ...
    }

    Args:
        protocole_check:
        banniere_check:
    """
    categ_admin = [3, "ssh", "vnc", "telnet", "damewaremr", "webmin", "miniserv"]
    categ_sgbd = [3, "mysql", "mongodb", "mongod", "postgresql", "ms-sql-s", "oracle"]
    categ_mail = [1, "smtp", "pop", "pop3", "imap", "smtps", "imaps", "pop3pw"]
    categ_server = [1, "domain", "ftp", "ldap", "infowave"]
    categ_windows = [3, "netbios-ssn", "netbios-ns", "netbios-dgm", "microsoft-ds", "msrpc", "msdtc", "netbios", "smb"]
    categ_web = [1, "http", "ssl", "https-alt", "iis", "apache", "nginx"]
    categ_share = [2, "nfs", "rcpbind", "rsync"]
    categ_communication = [1, "talk", "ntalk", "sip", "voip"]
    categ_analyse = [3, "redis", " wap-wsp", "elasticsearch", "svn", "git","java-rmi", "java"]
    categ_applications = [2, "jboss", "tomcat", "jenkins","glassfish"]
    categ_malwares = [4, "xtremerat"]
    categ_vpn = [2, "citrix", "vpn", "pulse secure", "netscaler"]
    categ_ics = [4, "modbus", "codesys", "iec-61850", "s7", "siemens", "plc5", "dnp3", "bacnet", "dicom", "ethernetip",
                 "general-electric-srtp", "pcworx", "redlion-crimson3", "omron-tcp", "melsec-q-tcp",
                 "automated-tank-gauge", "proconos"]
    categ_medical = [2, "dicom", "acr-nema"]
    categ_rdp = [4, "ms-wbt-server", "rdp"]
    categ_tivoli = [2, "tsrmagt"]
    categ_monitor = [2, "nagios-nsca"]

    categories = ["categ_admin", "categ_sgbd", "categ_mail", "categ_server", "categ_windows", "categ_web", "categ_share"
                  "categ_communication", "categ_analyse", "categ_applications", "categ_malwares", "categ_vpn",
                  "categ_ics", "categ_medical", "categ_rdp", "categ_tivoli", "categ_monitor"]

    for i in range(0, len(categories)):
        categorie_check = eval(categories[i])
        criticity = (categorie_check[0])
        for y in range(1, len(categorie_check)):
            protocole = categorie_check[y]
            if protocole_check.find(protocole) != -1 or banniere_check.find(protocole) != -1:
                return str(categories[i]), criticity
    return "unknown", "0"

    #snmp