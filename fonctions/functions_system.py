#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Utilisation fuzzing
import glob,sys,re,os,string,subprocess,os.path,getopt 
from subprocess import PIPE, Popen
import urllib2,urllib
from datetime import datetime
import importlib
import json,re,time
import simplejson
import platform
from glob import glob
from collections import OrderedDict
from datetime import datetime
import zipfile
import MySQLdb
import urllib
import subprocess
import signal
from time     import sleep
import ConfigParser
import fnmatch
import datetime

RED = '\x1b[91m'
RED1 = '\033[31m'
BLUE = '\033[94m'
GREEN = '\033[32m'
BOLD = '\033[1m'
NORMAL = '\033[0m'
ENDC = '\033[0m'

  
#vérifier si script lancé en root (nécessaire pour scan nmap)
def check_if_root():
  if not os.geteuid() == 0:
    print "le script doit etre execute en root"
    sys.exit('Script must be run as root')
		#return 0
	#else:
	#	return 1


def get_current_dir():
    return str(os.getcwd() + "/")

def lancer_cmd(commande):
  #print "Lancement de la commande " + commande
  p = subprocess.Popen(commande, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  result=""
  line=""
  try:
	  for line in p.stdout.readlines():
	    result=result + line
	    #print line
	  retval = p.wait()
  except:
  	print "stop erreur ?"
  	result = ""
  return result


def lancer_cmd_with_timeout(commande, timeout):
  #output = timeout_command(["sleep", "10"], 2)
  """call shell-command and either return its output or kill it
  if it doesn't normally exit within timeout seconds and return None"""
  
  start = datetime.datetime.now()
  process = subprocess.Popen(commande, shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  while process.poll() is None:
    time.sleep(0.1)
    now = datetime.datetime.now()
    if (now - start).seconds > timeout:
      os.kill(process.pid, signal.SIGKILL)
      os.waitpid(-1, os.WNOHANG)
      return None
  return process.stdout.read()


def print_and_flush(message, same_line=False):
    if same_line:
        print (message),
    else:
        print (message)
    if not sys.stdout.isatty():
        sys.stdout.flush()


def get_user():
  user = ""
  if os.path.exists("/home/cedric/"):user = "cedric"
  if os.path.exists("/home/ohmmm/"):user = "ohmmm"
  return user



def compress_file(fichier_a_decompresser):
  nom_zip = fichier_a_decompresser + ".zip"

  filezip = zipfile.ZipFile(nom_zip, 'w', zipfile.ZIP_DEFLATED)
  filezip.write(fichier_a_decompresser)
  filezip.close()

  for info in filezip.infolist():
    print (info.filename, info.file_size, info.compress_size)

  return fichier_a_decompresser + ".zip"

#logging.info("Checking Host: %s" % url)
#print_and_flush(GREEN + " * Please enter the IP address and tcp PORT of your listening server for try to get a REVERSE SHELL.\n"
#                            "   OBS: You can also use the --cmd \"command\" to send specific commands to run on the server."+NORMAL)


def search_report(chemin,domain,ext,pattern):
  report = ""
  if pattern == "" : pattern = "*."+ext 
  print pattern
  for path, dirs, files in os.walk(os.path.abspath(chemin)):
    print files
    print path
    print dirs
    for filename in fnmatch.filter(files, pattern):
      print os.path.join(path, filename)
      report = os.path.join(path, filename)
  return report 


def get_actual_date():
  current_month = datetime.datetime.now().strftime('%m')
  current_year_short = datetime.datetime.now().strftime('%y')
  current_day = datetime.datetime.now().strftime('%d')
  return str(current_day) + "/" + str(current_month) + "/" + str(current_year_short)



def get_date_today_long():
  current_month = datetime.datetime.now().strftime('%m')
  current_year_short = datetime.datetime.now().strftime('%Y')
  current_day = datetime.datetime.now().strftime('%d')
  return str(current_day) + "-" + str(current_month) + "-" + str(current_year_short)

def get_date_today_compare():
  current_month = datetime.datetime.now().strftime('%m')
  current_year_short = datetime.datetime.now().strftime('%Y')
  current_day = datetime.datetime.now().strftime('%d')
  return  str(current_year_short) + "-" + str(current_month) + "-" + str(current_day)



def get_file_content(file):
  contenu = ""
  try:
    file = open(file, "r") 
    contenu = file.read()
    file.close()
  except:
    print "erreur lors de la lecture du fichier " +str(file)
  return contenu 


def get_os():
  system_os =  platform.platform()
  return system_os.lower()
