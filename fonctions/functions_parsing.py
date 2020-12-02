#!/usr/bin/env python
# -*- coding: utf-8 -*-
import glob,sys,re,os,string,subprocess,os.path,getopt 
from subprocess import PIPE, Popen
from datetime import datetime
import importlib
import json,re,time
import simplejson
from glob import glob
from collections import OrderedDict
from datetime import datetime
###from bson import json_util
import MySQLdb
from urlparse import urlparse
import functions_error

def remove_charac_spec(chaine):
  
  chaine = chaine.replace("é","e")
  chaine = chaine.replace("è","e")
  chaine = chaine.replace("ê","e")
  chaine = chaine.replace("à","a")
  chaine = chaine.replace("ç","c")
  chaine = chaine.replace("ô","o")
  chaine = chaine.replace("ù","u")

  return chaine

def extract_domain_from_file(file):
	cmd = "grep -oE '[[:alnum:]]+[.][[:alnum:]_.-]+'"
	resultat = functions_system.lancer_cmd(cmd)
 

def remove_duplicates(values):
    output = []
    seen = set()
    for value in values:
        # If value has not been encountered yet,
        # ... add it to both list and set.
        if value not in seen:
            output.append(value)
            seen.add(value)
    return output

def filtre_url(url,port):
  if port == "443": url = url.replace(":443","")
  if port == "80": url = url.replace(":80","")
  if url[-2:] == "//" : url = url[:-1]
  if url[-1:] != "/" : url = url + "/"
  return url

def filtre_port(port):
  port = port.replace("/","")
  return port

def extract_http_server_from_whatweb (url):
   #functions_fichiers.ecrire_fichier("tmp.txt",whatweb_content)
   #sed -e "s|.*HTTPServer\(.*\)], |\1|" | cut -d"," -f 1
   sed = "sed -e \"s|.*HTTPServer\\(.*\\)], |\\1|\" | cut -d\",\" -f 1 "
   cmd = "whatweb -a 3 " + url + " | " + sed +" | grep -v 'deprecated' | grep -v 'duplicated' | grep -v 'overwritten'"
   result = functions_system.lancer_cmd(cmd)
   functions_fichiers.ecrire_fichier("tmp.txt",result)
   cmd = "cat tmp.txt | iconv -c -f utf-8 -t ascii | grep -v 'deprecated' | grep -v 'duplicated' | grep -v 'overwritten'"
   result = functions_system.lancer_cmd(cmd).rstrip('\n\r')
   if os.path.exists("tmp.txt"):os.remove("tmp.txt")
   return result

def nettoie_whatweb(url):
    cmd = "whatweb -a 3 " + url 
    result = functions_system.lancer_cmd(cmd)
    functions_fichiers.ecrire_fichier("tmp.txt",result)
    cmd = "cat tmp.txt | iconv -c -f utf-8 -t ascii | grep -v 'deprecated' | grep -v 'duplicated' | grep -v 'overwritten'"
    result = functions_system.lancer_cmd(cmd)
    
    print result
    result = result.replace('"',"")
    result = result.replace("'","")

    result = result.replace("//","")
    result = str(result).rstrip('\n\r')
    if os.path.exists("tmp.txt"):os.remove("tmp.txt")
    return result


def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


def escape_data(s): #echapper les caratcères 
    '''Replace special characters "&", "<" and ">" to HTML-safe sequences.
    If the optional flag quote is true, the quotation mark character (")
is also translated.'''
    s = s.replace("&", "&amp;") # Must be done first!
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    s = s.replace('"', "&quot;")
    s = s.replace("'", '&#39')
    s = s.replace("/", '&frasl;')
    s = s.replace("{", '&#123;')
    s = s.replace("}", '&#125;')
    s = s.replace("~", '&#126;')
    s = s.replace("|", '&#124;')
    s = s.replace("%", '&permil;')
    s = s.replace("[", '&#91;')
    s = s.replace("/", '&#92;')
    s = s.replace("]", '&#93;')
    return s


def filtre_list(a):
  a = str(a).replace("u'","")
  a = a.replace("']","")
  a = a.replace("[","")
  a = a.replace("'","")
  a = a.replace(","," - ")
  a = a.replace("  ", " ")
  return a

def parse_banniere(banniere):
  banniere = "OpenSSH 5.9p1 Debian 5ubuntu1.10 Ubuntu Linux; protocol 2.0"
  chaine_search = re.compile(r'Plugin (.*) detected. Version: (.*)')
  for version in re.findall(chaine_search9, test_str):
    print "version spip " + str(version)
    #https://stackoverflow.com/questions/43836155/extract-name-and-version-number-and-avoid-mismatch
    #ss = ['substudy-0.4.1-pre.1.crate','google-reseller1_sandbox-cli-0.3.6+20160329.crate','tis-100-0.1.3.crate','gobject-2-0-sys-0.46.0.crate']
    #ISC BIND 9.7.3

def enc_chaine_latin(a):
  return str(a).decode("latin1","ignore")

def enc_chaine(chaine):
  #a = str(chaine).decode("latin1","ignore")
  try:
    a = chaine.decode('utf8','ignore')
  except:
    a = chaine.encode('utf8','ignore')
  #a = chaine.encode('utf8', 'ignore')
  return a


def decode_utf(a):
  return a.encode('utf8','ignore')

  
def remove_colors_output(cmd):
  cmd = cmd + " | sed -r \"s/\\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g\""
  return cmd


#check if string contains number (utile pour banniere)
def has_numbers(inputString):
  return any(char.isdigit() for char in inputString)


def well_xml(chaine):
  new_chaine = "<![CDATA["+chaine+ "]]>"
  return new_chaine


def check_banniere(banniere):
  keywords = [" (debian)"," debian 5", " webmin"," debian 4"," httpd"," debian 6"," debian 7"," debian 8"," or later","  "," (pre-release)","(red hat enterprise linux)","protocol 2.0", "ubuntu","linux", "workgroup: training", "isc", "smtpd " ]
  banniere = banniere.lower()
  #print banniere + " (before)"
  if banniere != "" and len(banniere)>3 and has_numbers(banniere):
    if not ("pop3d") in banniere and not ("rpc") in banniere : 
      if banniere.count("+") == 1 :
        banniere1,reste = banniere.split("+")
        banniere = banniere1
        if banniere1.count("-"):
          banniere1.split("-")
          banniere,version =  banniere1.split("-")
      if ("openssl") in banniere :
        banniere1,banniere2 = banniere.split("openssl")
        print banniere1
        banniere ="openssl" + str(banniere2)
      
      for i in range(0,len(keywords)):
        banniere = banniere.replace(keywords[i],"")
    else:
      banniere = ""
  else:
    banniere = ""

  banniere = banniere.replace(";","")
  banniere = banniere.replace("  ","")
  banniere = banniere.replace("</title>","")

  return banniere

def echap_xml(banniere):
  return "<![CDATA["+ banniere + "]]>"



def extract_data (debut,fin,data):
  start = data.find(debut)
  end = data.find(fin, start)
  extract = data[start:end] 
  return extract


def filtre_banniere_nmap(services_nmap):
  #remove banniere
  delim = "|||"
  serv = []
  for i in range(0,len(services_nmap)):
    port,protocol,banniere = services_nmap[i].split("|||")
    present = "0"
    for z in range(0,len(serv)):
      old_port,old_protocol,old_banniere = serv[z].split("|||")
      if old_protocol == protocol and old_banniere == banniere :
        present = "1"
    if present == "0":
      serv.append(port+delim+protocol+delim+banniere)
  return serv


def filtre_doublons_banniere(applis_w):
  delim = "|||"
  applis = []
  for i in range(0,len(applis_w)):
    domaine,nom_appli,version_appli,port,categ = applis_w[i].split("|||")

    present = "0"
    for z in range(0,len(applis)):
      domaine_old,nom_appli_old,version_appli_old,port_old,categ_old = applis[z].split("|||")
      if nom_appli == nom_appli_old and version_appli == version_appli_old :
        present = "1"
    if present == "0":
      applis.append(domaine+delim+nom_appli+delim+version_appli+delim+port+delim+categ)
  return applis


def clean_version(banniere):
  banniere = banniere.replace("RELEASE_","")
  banniere = banniere.replace("_",".")
  if banniere.count("-") == 1: #5.5.9-1ubuntu4.29+esm3
    banniere,junk = banniere.split("-")
  banniere = banniere.replace("/","")
  banniere = banniere.replace(" v","")
  return banniere

def filtre_headers(headers):
  new_headers = []
  delim = "|||"
  for i in range(0,len(headers)):
    domain,vuln_header,url= headers[i].split("|||")

    present = "0"
    for z in range(0,len(new_headers)):
      domain_old,vuln_header_old,url_old= new_headers[z].split("|||")
      if vuln_header == vuln_header_old and domain == domain_old :
        present = "1"
    if present == "0":
      new_headers.append(domain+delim+vuln_header+delim+url)
  return new_headers

def parsing_url(url):
  o = urlparse(url)
  url_d = o.scheme + "://" + o.netloc
  dir_scan = o.path


#check if uri contains params, not worpress dir, etc.
def check_if_scan_uri(url):
  scan = 1
  o = urlparse(url)
  proto = o.scheme
  path = o.path
  query = o.query
  params = o.params
  port = o.port
  filename_w_ext = os.path.basename(path)
  filename, file_extension = os.path.splitext(filename_w_ext)
  print "proto:" +str(proto) + " - path:" + str(path) + " - query:" +str(query)+ " - params:"+str(params) + " -port:"+str(port)
  if path == ""  : scan = 0
  if query == "" : scan = 0
  return scan



def extract_domain_from_url(url):
    #try : 
    o = urlparse(url)
    domain = o.netloc
    return domain

#traiter file dorks
def traite_file_url(file_url):
  # check dir_listing
  # filtrer urls (pas 2 fois les mêmes)
  # fichier doit être filtré avant
  print "filtrage du fichier " + file_url
  resultat = functions_system.lancer_cmd("cat "+ file_url + " | sort | uniq")
  functions_fichiers.ecrire_fichier(file_url,resultat)
  print "fichier " + file_url + " traite"
  url_current = ""
  old_uri = ""
  tab_urls = []

  print "Verifier les directory listing ? (peut-être très long) (o/n)"
  rep = raw_input()
  if rep == "o":
    dir_listing = "1"
  else:
    print "pas de verification des directory listing"
    dir_listing = "0"

  with open(file_url,'r') as f:
    for line in f:
      url = line.rstrip('\n\r')
      o = urlparse(url)
      proto = o.scheme
      path = o.path
      query = o.query
      params = o.params
      port = o.port
      domain = o.netloc
      #print "url " + str(url) + " - proto:" +str(proto) + " - path:" + str(path) + " - query:" +str(query)+ " - params:"+str(params) + " -port:"+str(port)
      print "url " + str(url) + " - path:" + str(path) + " - query:" +str(query)+ " - params:"+str(params) 
      # si pas de param, on teste les directory listing
      if params == "" and query == "" and dir_listing == "1" : 
        #print " check dir_listing sur " + url
        result = functions_db_vuln_web_conf.detect_dir_listing(domain,port,url)
        if result == "1" :
          print "  directory listing detecte sur " + url
          #print result
          #functions_db_vuln.add_vuln(domain,"directory_listing",file_url,"","nessus",url,port,"web")
      if params != "" or query != "":
        if old_uri == "": 
          old_uri = url
        else:
          print "ressemblance entre 2 uris " + str(functions_checking.similar(url,old_uri))
          print "diff " + url + " - " + old_uri
          if functions_checking.similar(url,old_uri) < 0.60 :
            tab_urls.append(url)
            print url + " ajoutee pour scan"
            old_uri = url

  print "fin traitement des urls"
  print "liste des urls filtrees"
  total_uri = ""
  for i in range(0,len(tab_urls)):
    print tab_urls[i]
    total_uri = total_uri + tab_urls[i] + "\n"
  functions_fichiers.ecrire_fichier(file_url+"_filered",total_uri)
  return file_url+"_filered"

    

def clean_nessus_output(traces):
  traces = traces.replace("Using the GET HTTP method, Nessus found that :","")
  traces = traces.replace("Nessus was able to exploit the issue using the following request :","")
  traces = traces.replace("Credentials werre guessed for these resources :","")
  traces = traces.replace("Here is a trace of the traffic that demonstrates the issue :","")
  return traces

def echap_uri(uri):
    uri = uri.replace("&", "&amp;") 
    uri = uri.replace("<", "&lt;")
    uri = uri.replace(">", "&gt;")
    uri = uri.replace('"', "&quot;")
    uri = uri.replace("'", "&lsquo;")
    return uri
