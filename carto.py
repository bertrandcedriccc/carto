#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Utilisation fuzzing
import sys
sys.path.append("fonctions")
import functions_scan_projet
import functions_nmap
import functions_conf
import argparse
#copy files
functions_conf.verif_vulneers()



parser = argparse.ArgumentParser()
parser.add_argument("-d", "--domaine", help="Domaine a analyser.", nargs='*')
parser.add_argument("--file_domaines", "--file_domaines", help="Fichiers contenant les domaines a analyser.", nargs='*')
parser.add_argument("--enum", "--enum", help="Enumerer les domaines", nargs='*')
parser.add_argument("--carto", "--carto", help="Cartographie des domaines", nargs='*')
parser.add_argument("--scan_file_projet", "--scan_file_projet", help="Scan de fichier de projet via fichier texte", nargs='*')

args = parser.parse_args()


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


if args.file_domaines:
	file_domaines=' '.join(args.file_domaines)
	if file_domaines == "":
		print("entrez le fichier des domaines à scanner (fichier txt)")
	else:
		print("scan de projets contenus dans le fichier "+file_domaines)
		functions_scan_projet.scan_projets(file_projet)


if args.import_projet:
	print("importation d'un projet")
	file_xml=' '.join(args.import_projet)
	if file_xml == "":
		print("entrez le chemin du projet à importer (fichier xml)")
	else:
		functions_projet.import_projet(file_xml)


if args.scan_projet is not None:
	print("scan automatise des projets selon la date de planification de l'audit")
	functions_projet.scan_projet()
	exit()

if args.supprssdomain is not None:
	dom_suppr = ' '.join(args.supprssdomain)
	print("Suppression des donnees associees au domaine " + str(dom_suppr))
	functions_nettoyage.nettoie_sous_domaine("",dom_suppr)
	exit()