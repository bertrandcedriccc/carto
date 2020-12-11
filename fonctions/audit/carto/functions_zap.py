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
from fonctions.config import functions_notifications

def check_carto_zap(domaine,fichier_domaine):
    """
    Args:
        domaine:
    """
    functions_rapport.create_reports(domaine)
     #f"audits/{domaine}/vulns/vuln_ssl_{domaine}.xml"
    dir_zap = f"audits/{domaine}/zap/"
    cfg_pentest = functions_conf.get_cfg_pentest()
    dir_zap_tmp = os.getcwd() +"/"+ cfg_pentest.get("ZAP_DIR",'zap_dir')
    dir_zap_tmp = dir_zap_tmp.replace('"',"")
    print (dir_zap_tmp)
    if not os.path.exists("/zap"):
        os.mkdir("/zap")
    if not os.path.exists("/zap/wrk"):
        os.mkdir("/zap/wrk/")
    nb_tour = 0
    with open(fichier_domaine, 'r') as f:
        for line in f:
            nb_tour = nb_tour + 1
            ligne = line.rstrip('\n\r')
            sousdomaine,port = ligne.split("|||")
            print (sousdomaine)
            print (port)
            if port == "443": url = "https://"+sousdomaine
            if port == "80": url = "http://"+sousdomaine
            print("scan zap sur " + str(sousdomaine) + " " + url)
            nom_temp_rapport2 = dir_zap_tmp + "zap_"+sousdomaine+".xml"
            nom_temp_rapport = "zap_"+sousdomaine+".xml"
            nom_rapport = dir_zap + "zap_"+sousdomaine+".xml"
            if not os.path.exists(nom_rapport) : 
                cmd = cfg_pentest.get("ZAP_CMD",'zap_cmd')
                cmd = cmd.replace("<file_report>",nom_temp_rapport)
                cmd = cmd.replace("<url>",url)
                cmd = cmd.replace('\"',"")
                print(nom_rapport)
                print(cmd)
                functions_system.lancer_cmd_with_timeout(cmd, 4000)
                if os.path.exists(nom_temp_rapport2):
                    print (nom_temp_rapport2 + " existe bien")
                    os.system("cp "+nom_temp_rapport2 +" " +nom_rapport)
                    print ("deplacement : cp "+nom_temp_rapport2 +" " +nom_rapport)
                    os.system("cp "+nom_temp_rapport2+".html" +" " +nom_rapport+".html")
                else:
                    print (nom_temp_rapport + " existe pas")
            else:
                print ("le scan zap a deja ete effectue sur " + sousdomaine)
    functions_notifications.envoi_notification("zap",domaine)


