#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Utilisation fuzzing
import glob,sys,re,os,string,subprocess,os.path,getopt,datetime, os, time, signal
from subprocess import PIPE, Popen
from datetime import datetime
import importlib
import json,simplejson
from glob import glob
from collections import OrderedDict

import functions_error
from time     import sleep
import http.client
import io
from threading import BoundedSemaphore, Thread
from time import sleep
from random import random
import random
import pexpect
import time
import datetime
from re import *
from socket import *


cdeb = "["
cfin = "[0m"

random.seed()
randomid = random.randint(42,65000)

#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# Config Socket
#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

host="localhost"
buffer="128"

#token=32
token=8
#addr = (host,port_nmap)


input_file=datetime.datetime.now().strftime("/tmp/liste_%Y%d%m_%Hh%Mm%S")

global toolid
toolid=input_file

output_dir      = ""
#datetime.datetime.now().strftime("./resultats/%Y%d%m_%Hh%M")
jeton 		= BoundedSemaphore(token)
mk_liste	= True
xml_gen     = False
verbose		= True
verbose2	= False
verbose3	= False
wig = False
#tooldir		= path
id_client	= ['libre']
nb_ip		= 0
range_id = list(range(int(token+1)))

for id in range_id:
   id_client.append('libre') 




#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# Classe Audit
#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class Audit(Thread):

		def __init__(self,_id,_ip,jeton,output_dir,cmd_nmap,ports):
			Thread.__init__(self)
			self.id			= _id
			self.ip			= _ip
			self.jeton 		= jeton
			self.output_dir = output_dir
			self.cmd_nmap 	= cmd_nmap
			self.ports 		= ports
 
		def run(self):
			global nb_ip
			global randomid

			self.mkdir()
			self.date()

			if verbose : print(cdeb+"32m > "+self.ip+" processing... "+cfin)


			s_ntcp = self.nmap()

			nb_ip = nb_ip-1
			time = datetime.datetime.now().strftime("[%H:%M:%S] ")	
			if verbose : print(cdeb+"32m > "+self.ip+" finished ! "+cfin)
			print(cdeb+"34m > "+str(time)+str(nb_ip)+" host remaining.. "+cfin)

			#cmd = bin_echo+" "+self.ip+" >> "+output_dir+"/ipdone_nikto-mt"
			#os.popen(cmd,"r")
			#msg = str(self.id)+":"+self.ip+":"+toolid+":::"+tcp_state+":"+udp_state+":x:"+str(nb_ip)+":0:0:0:0:0:0:0:0:0:0:0:0"
			#		msg = str(self.id)+":"+self.ip+":"+toolid+":::1:1:ok:"+str(nb_ip)+":0:0:0:0:0:0:0:0:0:0:0"

			id_client[self.id] = "libre"
			self.jeton.release()

		def mkdir(self):
			output_dir = self.output_dir
			if not os.path.isdir(output_dir):
				os.popen("mkdir "+output_dir,"r")
			#if not os.path.isdir(output_dir+self.ip):
			#	os.popen("mkdir "+output_dir+"/"+self.ip,"r")
			
		def date(self): os.popen("date > "+self.output_dir+"/date.txt","r")
		


		def nmap(self):
			#nmap_cmd_plugin_git = "nmap -Pn -O -A -sT -p<ports> --script http-git -v -T4 -max-rtt-timeout 20 --host-timeout 3600 --max-scan-delay 20 --max-retries 1 -oX <file_report> <ip>"
			cmd_nmap = self.cmd_nmap
			cmd_nmap = cmd_nmap.replace("<ip>",self.ip)
			cmd_nmap = cmd_nmap.replace("<ports>",self.ports)
			cmd_nmap = cmd_nmap.replace("<file_report>",self.output_dir+self.ip+"_nmap.xml")
			print(cmd_nmap)
			if os.path.exists(self.output_dir+"/"+self.ip+"_nmap.xml"):os.remove(self.output_dir+"/"+self.ip+"_nmap.xml")
			#cmd=bin_wig+" "+tcp_options+" -oA "+output_dir+self.ip+"/nmapTCP "+self.ip+" #nmapartemis"+str(randomid) 
			if verbose : print(cdeb+"31m  > "+self.ip+cfin+" \t"+cmd_nmap.split("#nmapartemis")[0])

			child = pexpect.spawn(cmd_nmap)
			child.expect ('Starting')
			child.sendline ('\n')

			pourcentage=""
			etat=""
			info=""
		
			while 1:
				sleep(2)		
				try:
					child.expect ('\w+\r\n')
					child.sendline ('\n')
					childbefore = (child.before).decode("utf-8")
					p = compile('\d{1,3}\.\d{1,2}%')
					perc = p.findall(childbefore)

					p = compile('^([A-Za-z]+)')
					st = p.findall(childbefore)

					for sample in perc: pourcentage = sample
					for sample in st  : etat = sample

					if (len(etat) > 0) and (len(pourcentage) > 0): 
						info = etat+" "+pourcentage
					else:	info = etat
					
					msg = str(self.id)+":"+self.ip+":"+toolid+":::"+":0:"+str(nb_ip)+":"+info+":0:0:0:0:0:0:0:0:0:0:0:0"
					if ("Nmap done" in childbefore):
						msg = str(self.id)+":"+self.ip+":"+toolid+":::"+":0:"+str(nb_ip)+":Finished:0:0:0:0:0:0:0:0:0:0:0:0"
						#UDPSock.sendto(msg,addr)
						break

				except pexpect.TIMEOUT:
					print("pexpect timeout")
				except pexpect.EOF:
					#print child.before
					print("pexect EOF")
					break
				except:
					print("Unexpected error pexpect:", sys.exc_info()[0])
					#raise

			return "1:"


def check_dir(out_dir):
	if (out_dir[-1:] != '/'): out_dir = out_dir+"/"
	return(out_dir)

#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# Fonction ifconfig
# Creation d'un fichier avec le ifconfig
#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


def exec_nmap_plugin_parallel(dir_output,input_file,cmd_nmap):
	id_client	= ['libre']
	nb_ip		= 0
	output_dir = os.path.abspath(dir_output)+os.sep
	print(output_dir)
	output_dir = check_dir(output_dir)
	jeton 		= BoundedSemaphore(token)
	range_id = list(range(int(token+1)))

	for id in range_id:
		id_client.append('libre') 

	#Watcher()
	child = os.fork()
	if child != 0:
		try:
			os.wait()
		except KeyboardInterrupt:
			# I put the capital B in KeyBoardInterrupt so I can
			# tell when the Watcher gets the SIGINT
			#print 'SIGINT'
			try:
				cmd = "ps ax | grep nmap | awk {'print $1'}"
				ids = os.popen(cmd)
				pids = ids.readlines()
				os.kill(child, signal.SIGKILL)
				for pid in pids:
					os.kill(int(pid), signal.SIGKILL)
				
			except OSError: pass
			sys.exit()

	else:
		
		time = datetime.datetime.now().strftime("[%H:%M:%S]")
		print(cdeb+"35m > "+str(time)+" Processing ... "+cfin)
		
		if not os.path.isdir(output_dir):
		  os.popen("mkdir "+output_dir,"r")
		
		cmd = os.popen("grep . "+input_file+" | wc -l " )
		nb_ip = int(cmd.readline()[:-1])
		
		file = open(input_file,'r')
		lines = file.readlines()
		
		j = 0
		
		threads = []

		with open(input_file,'r') as f:
			for line in f:
				ligne = line.rstrip('\n\r')
				if ligne != "\n":
					print(ligne)
					ip,ports = ligne.split('|||')
					print(ip)
					print(ports)
					if verbose2 : print(cdeb+"30m   - "+ip+" is waiting for token..."+cfin)
					jeton.acquire()
					while 1:
		#					sleep(0.0001)
							j = j + 1
							if j == token+1: j = 1 
							if id_client[j] == "libre":
								id_client[j] = "occup"
								ident = j
								break

					auditip = Audit(ident,ip,jeton,output_dir,cmd_nmap,ports)
					threads.append(auditip)
					auditip.start()
		
		for auditip in threads:
			auditip.join()	
		file.close



def lancer_nmap_plugin_parallel(projet,plugin):
	cfg_pentest = functions_tools.parse_config_pentest_nmap()
	if plugin == "git":
		outil = "scan_git"
		cmd = cfg_pentest.get("NMAP_CMD_PLUGIN_GIT",'nmap_cmd_plugin_git').replace ('"',"")
	if plugin == "svn":
		outil = "scan_svn"
	if plugin == "cve":
		outil = "nmap_vulners"
		cmd = cfg_pentest.get("NMAP_CMD_VULNERS",'nmap_cmd_vulners').replace ('"',"")
	if plugin == "http-backup-finder":
		outil = "nmap_http-backup-finder"
		cmd = cfg_pentest.get("NMAP_CMD_PLUGIN_HTTP_BACKUP_FINDER",'nmap_cmd_plugin_http_backup_finder').replace ('"',"")
	if plugin == "http-backup-config":
		outil = "nmap_http-backup-config"
		cmd = cfg_pentest.get("NMAP_CMD_PLUGIN_HTTP_BACKUP_CONFIG",'nmap_cmd_plugin_http_backup_config').replace ('"',"")
	if plugin == "http-enum":
		outil = "nmap_http-enum"
		cmd = cfg_pentest.get("NMAP_CMD_PLUGIN_HTTP_ENUM",'nmap_cmd_plugin_http_enum').replace ('"',"")

	reports_directory = functions_report.get_directory_tool(projet,outil)

	if os.path.isdir("reports_gen/"+projet):
		fichier_scan = "reports_gen/"+projet+"/traces/liste_domaines_"+outil+"_"+projet+".txt"
	else:
		fichier_scan = "/tmp/liste_domaines_"+outil+"_"+projet+".txt"

	sous_dom = recup_domains_not_scanned(projet,outil)
	all_sous_dom = ""
	if len(sous_dom)>0:
		for x in range(0,len(sous_dom)):
			all_sous_dom = all_sous_dom + sous_dom[x] + "\n" 
		functions_fichiers.ecrire_fichier(fichier_scan,all_sous_dom)
		print("fichier scan " + outil + " ecrit dans " + fichier_scan)
		exec_nmap_plugin_parallel(reports_directory,fichier_scan,cmd)
		print("fin des scans " + outil)
		if os.path.isdir(reports_directory) and os.path.exists(fichier_scan):
			insert_dir_report(projet,reports_directory,fichier_scan,outil,plugin)
			if os.path.exists(fichier_scan):os.remove(fichier_scan)
			lancer_nmap_plugin_parallel(projet,plugin)
		#else:
		#	print "Le repertoire scan " + outil + " " + str(reports_directory) + " n\'existe pas"
		#	print "erreur , checker"
			#functions_error.log_error(projet + " :" + "Le repertoire scan "+outil + " " + str(reports_directory) + " n\'existe pas." + "\n" + "erreur lors du lancement des scans " + outil + " en parallele\n",projet)
	else:
		print("tous les domaines ont ete scannes avec " + outil)

def recup_domains_not_scanned(projet,outil):
	domain_not_scanned = []
	nb_domains_max = 5 # print pas plus de 25 domaines scannes à la fois
	nb_domains_scanned = 0
	if outil == "scan_git" or outil == "scan_svn" or outil =="nmap_http-backup-finder" or outil =="nmap_http-backup-config" or outil == "nmap_http-enum":
		hosts_services = functions_report_services.recup_port_services_web_from_projet(projet)
	elif outil == "nmap_vulners":
		hosts_services = functions_report_services.recup_all_port_from_projet(projet)
	else:
		print(outil)
		input()
	for x in range(0,len(hosts_services)):
		sousdomaine,ports = hosts_services[x].split("|||")
		if str(functions_db_scan.recup_id_scan(sousdomaine,outil,"")) == "0" :
			if nb_domains_scanned < nb_domains_max :
					domain_not_scanned.append(sousdomaine+"|||"+ports) 
					print("le domaine " + sousdomaine + " na pas ete scanne avec " + outil + ", on ajoute")
					nb_domains_scanned = nb_domains_scanned + 1
		else:
			print("scan "+outil + " deja realise sur " + sousdomaine)
	#if len(domain_not_scanned) > 0 : 
	#	print domain_not_scanned
	return domain_not_scanned


def insert_dir_report(projet,dir_rapport,file_doms,outil,plugin):
	with open(file_doms,'r') as f:
		for line in f:
			ligne = line.rstrip('\n\r')
			if ligne != "\n" and ligne != "":
				print(ligne)
				sousdomaine,port = ligne.split('|||')
				print("sous-domaine analyse " + sousdomaine)
				if str(functions_db_scan.recup_id_scan(sousdomaine,outil,"")) == "0" :
					file_scan = sousdomaine+"_nmap.xml"
					dir_file_scan = dir_rapport + "/" + file_scan
					print(dir_file_scan)
					if os.path.exists(dir_file_scan):
						if plugin == "git":
							functions_scripts_nmap.extract_info_script(dir_file_scan,sousdomaine,plugin)
						elif plugin == "cve":
							functions_import_nmap_cve.import_report_nmap_cve_vulners(dir_file_scan,sousdomaine,projet)
						#os.remove(dir_file_scan)
						functions_db_scan.add_scan(sousdomaine,outil,dir_file_scan,"")
					else:
						print("le fichier " + dir_file_scan  + " nexiste pas")
						functions_error.log_error("exec nmap parallel " + sousdomaine + " :" + "le fichier scan " + outil  + str(dir_file_scan) + " n\'existe pas." + "\n" +  "\n",projet,sousdomaine)
						functions_db_scan.add_scan(sousdomaine,outil,dir_file_scan,"")
						#raw_input()
			else:
				print(sousdomaine + " deja scanne avec " + str(outil))