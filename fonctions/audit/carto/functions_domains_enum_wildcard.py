#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re,time
import json
import os
import time
import simplejson
from glob import glob
from collections import OrderedDict
from datetime import datetime
from lxml import etree
from xml.dom.minidom import parse
from xml.etree import ElementTree
from time import sleep
from IPy import IP
from fonctions.config import functions_system
from fonctions.config import functions_parsing
from fonctions.config import functions_fichiers
from fonctions.config import functions_parsing
from fonctions.config import functions_conf
from fonctions.config import functions_rapport
from fonctions.audit.carto import functions_domains_enum


def manage_wildcard (domain):
	ips_wildcard = recup_ip_wildcard(domain)
	list_domain = []
	wordlist_dns = os.path.abspath(os.getcwd()) + "/outils/wordlists/subdomains-top1mil-20000.txt"
	#wordlist_dns = os.path.abspath(os.getcwd()) + "/outils/wordlists/subdomains-100.txt"
	
	file1 = open(wordlist_dns, 'r') 
	lines = file1.readlines() 
	print ("enumeration des domaines avec prise en compte du wildcard")
	for line in lines: 
		keyword = line.strip()
		sdomain = keyword+"."+domain
		sdomain = sdomain.replace("..",".")
		sdomain = sdomain.replace("#","")
		cmd = "dig +short "+sdomain
		#print (cmd)
		result = functions_system.lancer_cmd(cmd)
		for ip in result.splitlines():
			good = check_if_domain_active(ip,ips_wildcard)
			if good == 0 : 
				print (sdomain + " is good")
				list_domain.append(sdomain)
				if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip) == None : #on ajoute pas les ips (seront detectees avec nmap)
					if ip[-1] == "." : ip = ip[:-1]
					list_domain.append(ip)
				print (cmd)

	print ("liste des domaines detectes")
	#list_domain_good = [] #double check car detection de domaines not good avec une liste trop large
	for z in range(0,len(list_domain)):
		print (list_domain[z])
		#cmd = "dig +short "+list_domain[z]
		#result = functions_system.lancer_cmd(cmd)
		#for ip in result.splitlines():
		#	good = check_if_domain_active(ip,ips_wildcard)
		#	if good == 0 : list_domain_good.append(list_domain[z])

	return list_domain

def recup_ip_wildcard(domain):
	ips_wildcard = []
	cmd = "dig A +short *."+domain
	#print (cmd)
	result = functions_system.lancer_cmd(cmd)
	#print (result)
	for ip in result.splitlines():
		print (ip)
		#check if ip or domain
		ips_wildcard.append(ip)
	if len(ips_wildcard)>0:
		print ("il y a bien un wildcard sur le domaine")
	else:
		print ("pas de wildcard detecte")
	return ips_wildcard

def check_if_domain_active(ip_checked,ips_wildcard):
		#check if ip is in wildcard
		#print ("check ip " + ip_checked)
		if ip_checked.find("is not a legal name") != -1 : return 1
		for z in range(0,len(ips_wildcard)):
			if ip_checked.find(ips_wildcard[z]) != -1 : 
				#print ("cest le wildcard")
				return 1
		return 0

