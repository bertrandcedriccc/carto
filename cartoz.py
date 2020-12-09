#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Utilisation fuzzing
import sys,re,os
sys.path.append("fonctions")
sys.path.append("fonctions/config")
sys.path.append("fonctions/audit")
sys.path.append("fonctions/audit/carto")
import functions_scan_projet
import functions_nmap
import functions_conf
import argparse
#copy files
functions_conf.verif_vulneers()



parser = argparse.ArgumentParser()
parser.add_argument("-d", "--domaine", help="Domaine a analyser.", nargs='*')
parser.add_argument("--fichier_domaine", "--fichier_domaine", help="Fichiers contenant les domaines a analyser.", nargs='*')
parser.add_argument("--enum", "--enum", help="Enumerer les domaines", nargs='*')
parser.add_argument("--nmap", "--nmap", help="Cartographie des domaines", nargs='*')
parser.add_argument("--zap", "--zap", help="Audit ZAP des domaines", nargs='*')
parser.add_argument("--scan_file_projet", "--scan_file_projet", help="Scan de fichier de projet via fichier texte", nargs='*')

args = parser.parse_args()


fichier_domaine = ""
file_projet = ""

if args.scan_file_projet:
	file_projet=' '.join(args.scan_file_projet)
	if file_projet == "":
		print("entrez le fichier des projets à scanner (fichier txt)")
	else:
		print("scan de projets contenus dans le fichier "+file_projet)
		functions_scan_projet.scan_projets(file_projet)


if args.domaine :
	domaine=' '.join(args.domaine)
	print("domaine analyse : " + str(domaine))
	check_domaine = re.match(r'^(?=.{4,255}$)([a-zA-Z0-9][a-zA-Z0-9-]{,61}[a-zA-Z0-9]\.)+[a-zA-Z0-9]{2,5}$',domaine)
	if check_domaine is None:
		print("Le domaine " + str(domaine) + " est non-valide. Exemple de domaine valide : asipsante.fr") 
		exit()
else:
	print("le domaine doit etre indique")
	exit()


if args.fichier_domaine is not None:
	fichier_domaine=' '.join(args.fichier_domaine)
	if fichier_domaine == "":
		print("entrez le fichier des domaines à scanner (fichier txt)")
	else:
		print("scan de domaines contenus dans le fichier "+fichier_domaine)


if args.nmap or args.nmap is not None :
	print("cartographie des domaines du projet" + domaine)
	if fichier_domaine != "" :
		if os.path.isfile(fichier_domaine):
			print ("scan des domaines du fichier " + fichier_domaine)
			functions_scan_projet.scan_domaines(domaine,fichier_domaine)
		else:
			print ("le fichier "+fichier_domaine + " nexiste pas")
	else:
		print ("pas de fichier domaine indique, on va faire une enumeration")


if args.zap or args.zap is not None :
	print("audit zap des domaines du projet" + domaine)
	if fichier_domaine != "" :
		if os.path.isfile(fichier_domaine):
			print ("scan des domaines du fichier " + fichier_domaine)
			functions_scan_projet.scan_zap(domaine,fichier_domaine)
		else:
			print ("le fichier "+fichier_domaine + " nexiste pas")
			exit()
	else:
		print ("pas de fichier domaine indique, annulation")
		exit()


if args.enum or args.enum is not None :
	print("cartographie des domaines du projet" + domaine)
	functions_scan_projet.scan_domaines(domaine,"")
