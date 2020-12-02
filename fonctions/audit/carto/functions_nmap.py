#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# import functions_dump
import os
import random
import signal
import sys
import xml
import xml.dom.minidom
from datetime import datetime
from re import *
from threading import BoundedSemaphore, Thread
from time import sleep

import pexpect

from fonctions.config import functions_conf
from fonctions.config import functions_fichiers
from fonctions.config import functions_parsing
from fonctions.config import functions_rapport

cdeb = "["
cfin = "[0m"

random.seed()
randomid = random.randint(42, 65000)

# /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# Config Socket
# /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

host = "localhost"
buffer = "128"

token = 8

input_file = datetime.now().strftime("/tmp/liste_%Y%d%m_%Hh%Mm%S")

global toolid
toolid = input_file

output_dir = ""
jeton = BoundedSemaphore(token)
mk_liste = True
xml_gen = False
verbose = True
verbose2 = False
verbose3 = False
wig = False

id_client = ['libre' for i in range(token)]
nb_ip = 0


# /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# Classe Audit
# /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class Audit(Thread):

    def __init__(self, _id, _ip, tokenid, output_dir, cmd_nmap, domaineaudit):
        """
        Args:
          _id:
          _ip:
          jeton:
          output_dir:
          cmd_nmap:
          domaineaudit:
        """
        Thread.__init__(self)
        self.id = _id
        self.ip = _ip
        self.jeton = tokenid
        self.output_dir = output_dir
        self.cmd_nmap = cmd_nmap
        self.domaineaudit = domaineaudit

    def run(self):
        global nb_ip
        global randomid

        self.mkdir()
        self.date()

        if verbose:
            print(cdeb + "32m > " + self.ip + " processing... " + cfin)

        s_ntcp = self.nmap()

        nb_ip = nb_ip - 1
        time = datetime.now().strftime("[%H:%M:%S] ")
        if verbose:
            print(cdeb + "32m > " + self.ip + " finished ! " + cfin)
        print(cdeb + "34m > " + str(time) + str(nb_ip) + " host remaining.. " + cfin)
        id_client[self.id] = "libre"
        self.jeton.release()

    def mkdir(self):
        if not os.path.isdir(self.output_dir):
            os.mkdir(self.output_dir)

    def date(self):
        os.popen("date > " + self.output_dir + "/date.txt", "r")

    def nmap(self):
        cmd_nmap = self.cmd_nmap.replace("<ip>", self.ip)
        cmd_nmap = cmd_nmap + " #" + self.domaineaudit + "_nmapcarto" + str(randomid)
        cmd_nmap = cmd_nmap.replace("<file_report>", self.output_dir + self.ip + "_nmap.xml")
        print(cmd_nmap)
        if os.path.exists(self.output_dir + "/" + self.ip + "_nmap.xml"):
            os.remove(self.output_dir + self.ip + "_nmap.xml")
        if verbose:
            print(
                cdeb + "31m  > " + self.ip + cfin + " \t" + cmd_nmap.split("#" + self.domaineaudit + "_nmapcarto")[
                    0])

        child = pexpect.spawn(cmd_nmap)
        child.expect('Starting')
        child.sendline('\n')

        pourcentage = ""
        etat = ""
        info = ""

        while 1:
            sleep(5)
            try:
                child.expect(r'\w+\r\n')
                child.sendline('\n')
                childbefore = child.before.decode("utf-8").lower()
                p = compile(r'\d{1,3}\.\d{1,2}%')
                perc = p.findall(childbefore)

                p = compile('^([A-Za-z]+)')
                st = p.findall(childbefore)

                for sample in perc:
                    pourcentage = sample
                for sample in st:
                    etat = sample

                if (len(etat) > 0) and (len(pourcentage) > 0):
                    info = etat + " " + pourcentage
                else:
                    info = etat

                msg = str(self.id) + ":" + self.ip + ":" + toolid + ":::" + ":0:" + str(
                    nb_ip) + ":" + info + ":0:0:0:0:0:0:0:0:0:0:0:0"
                if "nmap done" in childbefore:
                    msg = str(self.id) + ":" + self.ip + ":" + toolid + ":::" + ":0:" + str(
                        nb_ip) + ":Finished:0:0:0:0:0:0:0:0:0:0:0:0"
                    break

            except pexpect.TIMEOUT:
                print("pexpect timeout")
            except pexpect.EOF:
                # print child.before
                print("pexect eof")
                break
            except Exception as e:
                print("unexpected error pexpect:", e)

        if '0 IP addresses (0 hosts up) scanned' in open(self.output_dir + self.ip + "_nmap.xml").read():
            print("le domaine " + self.ip + " na pas ete resolu")
        return "1:"


def check_dir(out_dir):
    """
    Args:
    out_dir:
    """
    if out_dir[-1:] != '/':
        out_dir = out_dir + "/"
    return out_dir


def exec_nmap_parallel(dir_output, input_file, cmd_nmap, domaine):
    """
    Args:
     dir_output:
     input_file:
     cmd_nmap:
     domaine:
    """
    id_client = ['libre' for i in range(token)]
    nb_ip = 0
    output_dir = os.path.abspath(dir_output) + os.sep
    print(output_dir)
    output_dir = check_dir(output_dir)
    jeton = BoundedSemaphore(token)

    child = os.fork()
    if child != 0:
        try:
            os.wait()
        except KeyboardInterrupt:
            try:
                cmd = "ps ax | grep '#" + domaine + "_nmapcarto' | awk {'print $1'}"
                ids = os.popen(cmd)
                pids = ids.readlines()
                os.kill(child, signal.SIGKILL)
                for pid in pids:
                    os.kill(int(pid), signal.SIGKILL)
            except OSError:
                pass
            sys.exit()
    else:
        time = datetime.now().strftime("[%H:%M:%S]")
        print(cdeb + "35m > " + str(time) + " Processing ... " + cfin)

        if not os.path.isdir(output_dir):
            os.popen("mkdir " + output_dir, "r")

        cmd = os.popen("grep . " + input_file + " | wc -l ")
        nb_ip = int(cmd.readline()[:-1])

        file = open(input_file, 'r')
        lines = file.readlines()

        j = 0

        threads = []

        with open(input_file, 'r') as f:
            for line in f:
                ligne = line.rstrip('\n\r')
                if ligne != "\n":
                    ip = ligne
                    if verbose2:
                        print(cdeb + "30m   - " + ip + " is waiting for token..." + cfin)
                    jeton.acquire()
                    while 1:
                        j += 1
                        if j >= token:
                            j = 0

                        if id_client[j] == "libre":
                            id_client[j] = "occup"
                            ident = j
                            break
                    auditip = Audit(ident, ip, jeton, output_dir, cmd_nmap, domaine)
                    threads.append(auditip)
                    auditip.start()

        for auditip in threads:
            auditip.join()
        file.close()


def check_if_scan_nmap(domaine):
    """
    Args:
     domaine:
    """
    nmap_scan = 0
    while nmap_scan == 0:
        cmd = "ps ax | grep '#" + domaine + "_nmapcarto' | awk {'print $1'}"
        ids = os.popen(cmd)
        pids = ids.readlines()
        nb_pid = 0
        for pid in pids:
            nb_pid = nb_pid + 1
            os.system("ps -o cmd= {}".format(pid))
        if nb_pid <= 2:
            nmap_scan = 1
        else:
            sleep(60)


def check_carto_nmap(domaine, file_domaine):
    """
    Args:
     domaine:
     file_domaine:
    """
    fichier_carto = f"audits/{domaine}/carto_{domaine}.xml"
    functions_rapport.create_reports(domaine)
    dir_rapport = f"audits/{domaine}/nmap/"
    if not os.path.exists(dir_rapport):
        os.mkdir(dir_rapport)
    fichier_domaine_not_scanned = dir_rapport + domaine + "_nmap_not_scanned.txt"
    check_if_scan_nmap(domaine)
    if not os.path.exists(fichier_carto):
        sous_dom_not_scanned, nb_domains_not_scanned = recup_domains_not_scanned(domaine, dir_rapport, file_domaine)
        if len(sous_dom_not_scanned) > 0:
            sous_dom_not_scanned_all = ""
            for x in range(0, len(sous_dom_not_scanned)):
                subdomaine = sous_dom_not_scanned[x]
                sous_dom_not_scanned_all = sous_dom_not_scanned_all + subdomaine + "\n"
            functions_fichiers.ecrire_fichier(fichier_domaine_not_scanned, sous_dom_not_scanned_all)
            cfg_pentest = functions_conf.get_cfg_pentest()
            cmd = cfg_pentest.get("NMAP_CMD_COMMON", 'nmap_cmd_common').replace('"', "")
            exec_nmap_parallel(dir_rapport, fichier_domaine_not_scanned, cmd, domaine)
            if nb_domains_not_scanned > 0:
                check_carto_nmap(domaine, file_domaine)
        else:
            print("tous les domaines sur " + domaine + " ont ete scannes")


def recup_domains_not_scanned(domaine, dir_rapport, file_domaine):
    """
    Args:
     domaine:
     dir_rapport:
     file_domaine:
    """
    domain_not_scanned = []
    nb_domains_max = 6
    nb_domains_scanned = 0
    nb_domains_not_scanned = 0
    with open(file_domaine, 'r') as f:
        for line in f:
            sousdomaine = line.rstrip('\n\r')
            nom_rapport = dir_rapport + "/" + sousdomaine + "_nmap.xml"
            if not os.path.exists(nom_rapport):
                if nb_domains_scanned < nb_domains_max:
                    nb_domains_scanned = nb_domains_scanned + 1
                    domain_not_scanned.append(sousdomaine)
                    print("le domaine " + sousdomaine + " na pas ete scanne avec nmap, on ajoute")
                else:
                    nb_domains_not_scanned = nb_domains_not_scanned + 1
    domain_not_scanned = functions_parsing.remove_duplicates(domain_not_scanned)
    if len(domain_not_scanned) > 0:
        print(domain_not_scanned)

    return domain_not_scanned, nb_domains_not_scanned


def insert_nmap_dir_report(domaine, dir_rapport, liste_doms):
    """
    Args:
     domaine:
     dir_rapport:
     liste_doms:
    """
    cfg_pentest = functions_conf.get_cfg_pentest()
    for i in range(0, len(liste_doms)):
        sousdomaine = liste_doms[i]
        print("sous-domaine analyse " + sousdomaine)
        dir_nmap_file = dir_rapport + "/" + sousdomaine + "_nmap.xml"
        if os.path.exists(dir_nmap_file):
            lports = ""
            print("Le rapport nmap existe bien : " + dir_nmap_file)
            print("pas encore de scan custom sur " + sousdomaine)
            ports = extract_ports(dir_nmap_file, sousdomaine)
            print(str(ports))
            if len(ports) == 0:
                print("pas de ports detectes sur " + sousdomaine + "on va rescanner les ports common")
                print("scan nmap fast sur le domaine " + sousdomaine)
                cmd = cfg_pentest.get("NMAP_CMD_TCP_FAST", 'nmap_cmd_tcp_fast')
                if os.path.exists(dir_nmap_file):
                    os.remove(dir_nmap_file)
                cmd = cmd.replace("<file_report>", dir_nmap_file)
                cmd = cmd.replace("<ip>", sousdomaine)
                cmd = cmd.replace('\"', '')
                print(cmd)
                os.system(cmd)
        else:
            print(sousdomaine + " deja scanne")


def extract_ports(nmap_file, domain):
    """
    Args:
     nmap_file:
     domain:
    """
    try:
        doc = xml.dom.minidom.parse(nmap_file)
    except IOError:
        print("error: file " + str(nmap_file) + " doesn't exist\n")

    ports = ""
    ports_nmap = []
    if os.path.exists(nmap_file):
        for host in doc.getElementsByTagName("host"):
            try:
                address = host.getElementsByTagName("address")[0]
                ip = address.getAttribute("addr")
                protocol = address.getAttribute("addrtype")

            except:
                continue

            try:
                hname = host.getElementsByTagName("hostname")[0]
                hostname = hname.getAttribute("name")
            except:
                hostname = ""

            try:
                ports = host.getElementsByTagName("ports")[0]
                ports = ports.getElementsByTagName("port")
            except:
                continue

            for port in ports:
                pn = port.getAttribute("portid")
                protocol = port.getAttribute("protocol")
                state_el = port.getElementsByTagName("state")[0]
                state = state_el.getAttribute("state")
                ports_nmap.append(pn)

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
    return ports_nmap
