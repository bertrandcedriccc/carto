#!/usr/bin/env python
# -*- coding: utf-8 -*-
import httplib
import urlparse
import re,time
import hashlib, urllib, urllib2, json, os
import time
import simplejson
from glob import glob
from collections import OrderedDict
from datetime import datetime
import functions_parsing
##from bson import json_util
from lxml import etree
from xml.dom.minidom import parse
from xml.etree import ElementTree
from time     import sleep
import functions_system
import functions_parsing
import functions_fichiers
import functions_conf

def audit_domains(projet,domaine,file_domaine):
	#date_audit = time.strftime("%m-%Y")

	#list_dnscan = recup_domain_dnscan(projet,domaine,auto)

	check = dns_recon_check(projet,domaine)
	if check != "wildcard":
		list_dnsrecon = dns_recon(projet,domaine,"enum")
	dns_recon(projet,domaine,"transfert_zone")
	list_sublister = recup_domain_sublister(projet,domaine)
	list_acamar = recup_domain_acamar(projet,domaine)
	list_dnscan = recup_domain_dnscan(projet,domaine)
	
	print "acamar " + str(list_acamar)
	print "sublister " + str(list_sublister)
	print "dnscan " + str(list_dnscan)
	print "dnsrecon " + str(list_dnsrecon)
	try:
		list_dom = list_dnscan + list_sublister + list_acamar + list_dnsrecon
		list_dom = functions_parsing.remove_duplicates(list_dom)
		list_dom.sort()
	except:
		print "erreur lors de lajout des listes"
		print "acamar " + str(list_acamar)
		print "sublister " + str(list_sublister)
		print "dnscan " + str(list_dnscan) 
		list_dom = ""
	print "\n Liste des sous-domaines associés à " + projet +" \n"
	domaines = ""
	for z in range(0,len(list_dom)):
		domaines = domaines + list_dom[z].lower() + "\n"
	print "\n \n Fin des sous-domaines \n"
	if os.path.exists("/tmp/domains.txt"):os.remove("/tmp/domains.txt")
	functions_fichiers.ecrire_fichier(file_domaine,domaines)
	print "fichier des domaines ecrit dans :" + file_domaine 



def dns_recon(projet,domain,option):
	cfg_pentest = functions_conf.parse_config_osint()
	if option == "transfert_zone":
		outil = "dnsrecon_zt"
		cmd = cfg_pentest.get("DNSRECON_ZONE",'dnsrecon_zone')
	if option == "enum" :
		outil = "dnsrecon_enum"
		cmd = cfg_pentest.get("DNSRECON_ENUM",'dnsrecon_enum')
		check = dns_recon_check(projet,domain)#check dnssec, check wildcard


		#if str(functions_db_commun.recup_id_scan(domain,"cmsmap","")) == "0":
		print "scan " + outil +" sur " + str(domain)
		nom_rapport = "/tmp/"+domain+".json"
		print nom_rapport
		list_dom = []
		cmd = cmd.replace("<domain>",domain)
		cmd = cmd.replace("<file_report>",nom_rapport)
		cmd = cmd.replace('\"',"")
		cmd = functions_parsing.remove_colors_output(cmd)
		if os.path.exists(nom_rapport):os.remove(nom_rapport)
		timeout = 600 #10 minutes
		print cmd
		#functions_system.lancer_commande_with_timeout(cmd, "600")
		functions_system.lancer_cmd_with_timeout(cmd, timeout)
		os.system(cmd)
		print "scan "+ outil +" fini"
		print "analyse du rapport " + outil + " fini : " + nom_rapport
		if os.path.exists(nom_rapport):
			list_dom = analyse_report_dnsrecon_zone(projet,nom_rapport,domain,cmd,outil)
			if os.path.exists(nom_rapport) :os.remove(nom_rapport)
		else:
			print "Le fichier scan " + outil + " : " +  str(nom_rapport) + " n\'existe pas"
		return list_dom


def dns_recon_check(projet,domain):
	cfg_pentest = functions_conf.parse_config_osint()
	cmd = cfg_pentest.get("DNSRECON_CHECK",'dnsrecon_check')	
	cmd = cmd.replace("<domain>",domain)
	cmd = cmd.replace('\"',"")
	cmd = functions_parsing.remove_colors_output(cmd)
	print cmd
	resultat = functions_system.lancer_cmd(cmd)
	print resultat
	if resultat.find("DNSSEC is not configured")!= -1 or resultat.find("All nameservers failed to answer the DNSSEC") != -1:
		print "pas de dnssec pour " + domain
		functions_fichiers.add_vuln(domain,"dns_nodnssec"+"|||"+""+"|||"+cmd+"|||"+""+"|||"+"53"+"\n")
	if resultat.find("Wildcard resolution is enabled on this domain")!= -1:
		print "wildcar active ! inutile de faire un brute-force des domaines"
		return "wildcard"
	else: return ""



def analyse_report_dnsrecon_zone(projet,report_file,domain,cmd,outil):
	if os.path.exists(report_file):
		filejson = open(report_file ,"r")
		jsonn =  filejson.read() 
		filejson.close()
		results = []
		#print jsonn
		#try:
		list_domains = []
		photon_data  = json.loads(jsonn)
		for item in photon_data :
			#print item
			ns_server = item.get("ns_server")
			name_server = item.get("name")
			type_server = item.get("type")
			address_server = item.get("address")
			zt = item.get("zone_transfer")
			print zt
			if zt == "success" :
				print "zone transfer success pour le serveur " + str(ns_server)
				functions_fichiers.add_vuln(domain,"dns_transfert_zone"+"|||"+report_file+"|||"+cmd+"|||"+zt+"|||"+"53"+"\n")
			print name_server
			#print ns_server
			#print type_server
			if name_server != None and domain in name_server and type_server != "NS":
				print str(domain) + " in " + str(name_server) + " on ajoute"
				list_domains.append(name_server)
	return list_domains

def recup_domain_dnscan(projet,domain):
	outil = "dnscan"
	cfg_pentest = functions_conf.parse_config_osint()
	print "scan " + outil +" sur " + str(domain)
	nom_rapport = "/tmp/dns_scan"+domain+".txt"
	print nom_rapport
	list_dnscan = []
	cmd = cfg_pentest.get("DNSCAN_CMD",'dnscan_cmd')
	cmd = cmd.replace("<domain>",domain)
	cmd = cmd.replace("<file_report>",nom_rapport)
	cmd = cmd.replace('\"',"")
	cmd = functions_parsing.remove_colors_output(cmd)
	if os.path.exists(nom_rapport):os.remove(nom_rapport)
	timeout = 600 #10 minutes
	print cmd
		#functions_system.lancer_commande_with_timeout(cmd, "600")
	functions_system.lancer_cmd_with_timeout(cmd, timeout)
	print "scan "+ outil +" fini"
	print "analyse du rapport " + outil + " fini : " + nom_rapport
	if os.path.exists(nom_rapport):
		list_dnscan = analyse_report_dnscan(projet,nom_rapport,domain,cmd,outil)
		if os.path.exists(nom_rapport) :os.remove(nom_rapport)
	return list_dnscan



def recup_domain_sublister(projet,domain):
	outil = "sublister"
	cfg_pentest = functions_conf.parse_config_osint()
	#if str(functions_db_commun.recup_id_scan(domain,"cmsmap","")) == "0":
	print "scan " + outil +" sur " + str(domain)
	nom_rapport = "/tmp/domains.txt"
	print nom_rapport
	cmd = cfg_pentest.get("SUBLIST3R_CMD",'sublist3r_cmd')
	cmd = cmd.replace("<domain>",domain)
	cmd = cmd.replace("<file_report>",nom_rapport)
	cmd = cmd.replace('\"',"")
	if os.path.exists(nom_rapport):os.remove(nom_rapport)
	print cmd
	os.system(cmd)
	list_sublister = []
	#resultat = functions_system.lancer_cmd(cmd)
	#functions_fichiers.ecrire_fichier(nom_rapport,resultat)
	print nom_rapport
	print "scan "+ outil +" fini"
	print "analyse du rapport " + outil + " fini : " + nom_rapport
	if os.path.exists(nom_rapport):
		list_sublister = analyse_report_sublister(projet,nom_rapport,domain,outil)
		if os.path.exists(nom_rapport) :os.remove(nom_rapport)
	return list_sublister


def recup_domain_acamar(projet,domain):
	outil = "acamar"
	cfg_pentest = functions_conf.parse_config_osint()
	#if str(functions_db_commun.recup_id_scan(domain,"cmsmap","")) == "0":
	print "scan " + outil +" sur " + str(domain)
	nom_rapport = cfg_pentest.get("ACAMAR_DIR",'acamar_dir') + domain + ".txt"
	nom_rapport = nom_rapport.replace('\"',"")
	cmd = cfg_pentest.get("ACAMAR",'acamar')
	cmd = cmd.replace("<domain>",domain)
	cmd = cmd.replace('\"',"")
	if os.path.exists(nom_rapport):os.remove(nom_rapport)
	print cmd
	list_acamar = []
	os.system(cmd)
	print "scan "+ outil +" fini"
	if os.path.exists(nom_rapport):
		list_acamar = analyse_report_acamar(projet,nom_rapport,domain,outil)
		if os.path.exists(nom_rapport) :os.remove(nom_rapport)
	return list_acamar



def analyse_report_sublister(projet,report_file,domain,outil):
	list_domains = []
	with open(report_file,'r') as f:
		print f
		for line in f:
			sdomain = line.rstrip('\n\r')
			sdomain1=""
			sdomain2 = ""
			sdomain3 = ""
			#sdomain = sdomain.replace("www.","")
			#entetes
			if sdomain.find("<BR>") != -1 :
				if sdomain.count("<BR>") == 1:
				#gitlabci-symfony-instance2.dv.cool<BR>www.gitlabci-symfony-instance2.dv.cool
					sdomain,sdomain2 = sdomain.split("<BR>")
				elif sdomain.count("<BR>") == 2:
					sdomain,sdomain2,sdomain3 = sdomain.split("<BR>")
				elif sdomain.count("<BR>") == 3:
					sdomain,sdomain2,sdomain3,sdomain4 = sdomain.split("<BR>")
				elif sdomain.count("<BR>") == 4:
					sdomain,sdomain2,sdomain3,sdomain4,sdomain5 = sdomain.split("<BR>")
			if sdomain.find("<BR>") == -1:
				list_domains.append(sdomain)
	return list_domains

def analyse_report_acamar(projet,report_file,domain,outil):
	print domain
	list_domains = []
	with open(report_file,'r') as f:
			print f
	   		for line in f:
				sdomain = line.rstrip('\n\r')
				#sdomain = sdomain.replace("www.","")
				#entetes
				print sdomain
				if sdomain.find(domain) != -1 :
					if sdomain.find("Acamar.py") == -1 :
						list_domains.append(sdomain)
	print str(list_domains)
	return list_domains


def analyse_report_dnscan(projet,file_report,domain,cmd,outil):
	#id_domain = functions_db_domaines.get_id_domain(domain)
	#id_scan = functions_db_scan.recup_id_scan(domain,outil,"")
	list_domains = []
	domains = []
	delim = "|||"
	transfert_zone = "0"

	with open(file_report,'r') as f:
		lignes_rapport = []
		for line in f:
			ligne = line.rstrip('\n\r')
			lignes_rapport.append(ligne)

	nb_lignes = len(lignes_rapport)
	x = 0

	while x < nb_lignes:
		ok = "0"
		ligne = lignes_rapport[x].replace("'","").rstrip('\n\r')
		#print ligne
		#transfert de zone dns
		#name server
		if ligne.find("[+] Getting nameservers") != -1:
			x = x + 1
			ligne = lignes_rapport[x]
			while ok == "0": 
				if ligne.find('Zone transfer') != -1:
					ok = "1"
					transfert_zone = "1"
				else:
					print ligne
					try:
						ip,new_domain = ligne.split(" - ")
						print "add name server " + str(new_domain)
						domains.append(new_domain+delim+ip+delim+"name_server")
					except:
						print "erreur extract sur la ligne " + ligne
					x = x + 1
					ligne = lignes_rapport[x]

		if ligne.find("Zone transfer sucessful using nameserver") != -1:
			file = open(file_report, "r") 
			result = file.read()
			file.close()
			vuln 
			functions_fichiers.add_vuln(domain,"dns_transfert_zone"+"|||"+file_report+"|||"+cmd+"|||"+result+"|||"+"53"+"\n")
			transfert_zone = "1"


		#serveur mail
		if ligne.find("MX records found") != -1:
			x = x + 1
			ligne = lignes_rapport[x]
			while ok == "0": 
				if ligne.find(' Scanning') != -1:
					ok = "1"
				else:
					try:
						number,new_domain = ligne.split(" ")
						print "add mx server " + str(new_domain)
						domains.append(new_domain+delim+ip+delim+"mail_server")
						#ligne = lignes_rapport[x]
					except:
						print "erreur lors du split de la ligne " + ligne
					try:
						ligne = lignes_rapport[x]
					except:
						print "erreur lors de la jout de la ligne " + ligne
					x = x + 1

		if ligne.find('Scanning') != -1 :
			print "recup des serveurs"
			x = x + 1
			try:
				ligne = lignes_rapport[x]
			except:
				ligne = ""
			ok = "0"
			if transfert_zone == "0":
				print ligne
				raw_input()
				try:
					ip,new_domain = ligne.split(" - ")
					#print new_domain
					#print ip
					#print "new domain detected " + str(new_domain ) + ":" + ip
					domains.append(new_domain+delim+ip+delim+"")
					x = x + 1
				except:
					ok ="1"

				ligne = lignes_rapport[x]

		if ligne.find(domain) != -1:
			if "-" in ligne:
				print ligne
				try:
					ip,nom_dom = ligne.split(" - ")
					nom_dom = nom_dom.replace(" ","")
					ip = ip.replace(" ","")
					domains.append(nom_dom+delim+ip+delim+"")
					print nom_dom
					print ip
				except:
					#pass
					print "erreur de split sur la ligne " + str(ligne)


		if transfert_zone == "1" :
			try:
				nom_dom,valeur,pre1,pre2,ip = ligne.split(" ")
				try: 
					if IP(ip):
						print str(ip) + " est bien une ip "
						domains.append(nom_dom+delim+ip+delim+"")
				except:
					print str(ip) + " nest pas une ip "
					domains.append(non_dom+delim+""+delim+"")
			except:
				pass
		x = x + 1


	for z in range(0,len(domains)):
		sdomain,ip,role = domains[z].split("|||")
		if sdomain.endswith('.') : sdomain = sdomain[:-1]
		if sdomain.startswith('*.') : sdomain = sdomain[2:]
		list_domains.append(sdomain)

	print "fin de l'importation du rapport dnscan " + str(file_report) + "\n"
	return list_domains
