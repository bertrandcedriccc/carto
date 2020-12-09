#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import time
import simplejson
from IPy import IP
from glob import glob
from collections import OrderedDict
from datetime import datetime
import functions_parsing
##from bson import json_util
from lxml import etree
from xml.dom.minidom import parse
from xml.etree import ElementTree
from time     import sleep
import functions_conf
import functions_domains_enum
import functions_nmap
import functions_nmap_plugin
from fonctions.audit.carto import functions_carto
from fonctions.audit.carto import functions_domains_enum
from fonctions.audit.carto import functions_nmap
from fonctions.audit.carto import functions_zap

def scan_projets(file_projet):
	#date_audit = time.strftime("%m-%Y")
	with open(file_projet,'r') as f:
		for line in f:
			projet = line.rstrip('\n\r')
			print ("projet analyse " + projet)
			if not os.path.exists("reports_gen/"+projet):os.mkdir("reports_gen/"+projet)
			fichier_domaine = "reports_gen/"+projet+"/domaines_"+projet+".txt"
			if not os.path.exists(fichier_domaine):
				functions_domains_enum.audit_domains(projet,projet,fichier_domaine)
			functions_nmap.check_carto_nmap(projet,fichier_domaine)
			#functions_nmap_plugin.lancer_nmap_plugin_parallel(projet,"cve",fichier_domaine)
			#functions_nmap_plugin.lancer_nmap_plugin_parallel(projet,"git",fichier_domaine)
			#functions_nmap_plugin.lancer_nmap_plugin_parallel(projet,"http-enum",fichier_domaine)
			#functions_nmap_plugin.lancer_nmap_plugin_parallel(projet,"http-backup-finder",fichier_domaine)
			#functions_nmap_plugin.lancer_nmap_plugin_parallel(projet,"http-backup-config",fichier_domaine)
			#functions_nmap(projet)


def scan_domaines(domaine,fichier_domaine):
    """
    Args:
     domaine:
    """
    print ("scan des domaines du projet "+domaine)
    print("domaine analyse " + domaine)
    
    if fichier_domaine == "" : fichier_domaine = "audits/" + domaine + "/domaines_" + domaine + ".txt"
    if not os.path.exists(fichier_domaine):
        functions_domains_enum.audit_domains(domaine, fichier_domaine)
    if os.path.exists(fichier_domaine):
        dir_rapport = "audits/" + domaine + "/nmap/"
        functions_nmap.check_carto_nmap(domaine, fichier_domaine)
        functions_nmap.check_nmap_fast(domaine, fichier_domaine)
    functions_carto.generate_carto(domaine, dir_rapport)


def scan_zap(domaine,fichier_domaine):
    """
    Args:
     domaine:
    """
    print ("scan zap des domaines du projet "+domaine)
    print("domaine analyse " + domaine)
    
    if os.path.exists(fichier_domaine):
        dir_rapport = "audits/" + domaine + "/zap/"
        functions_zap.check_carto_zap(domaine, fichier_domaine)
    else:
    	print ("le fichier domaine "+fichier_domaine + " nexiste pas")
    functions_carto.generate_carto(domaine, dir_rapport)
