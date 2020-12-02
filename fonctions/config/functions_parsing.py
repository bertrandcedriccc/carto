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
