#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys,os
import traceback
import logging
import functions_system, functions_fichiers
#https://zonca.github.io/2013/10/how-to-log-exceptions-in-python.html
#https://zonca.github.io/2013/10/how-to-log-exceptions-in-python.html
#import exceptions

#    try:
#        if appli == "joomla!":
#            result_cve=get_cve_vuln_spec(appli,v_install)
#        else:
#            result_cve=get_cve_vuln(appli,v_install)
#    except exceptions.Exception as e:
#            functions_error.log_exception(e)
#            print "erreur lors de la recup des cves"

def setup_logging_to_file(filename):
    logging.basicConfig( filename=filename,
                         filemode='w',
                         level=logging.DEBUG,
                         format= '%(asctime)s - %(levelname)s - %(message)s',
                       )

def extract_function_name():
    """Extracts failing function name from Traceback
    by Alex Martelli
    http://stackoverflow.com/questions/2380073/\
    how-to-identify-what-function-call-raise-an-exception-in-python
    """
    tb = sys.exc_info()[-1]
    stk = traceback.extract_tb(tb, 1)
    fname = stk[0][3]
    return fname

def log_exception(e):
    logging.error(
    "Function {function_name} raised {exception_class} ({exception_docstring}): {exception_message}".format(
    function_name = extract_function_name(), #this is optional
    exception_class = e.__class__,
    exception_docstring = e.__doc__,
    exception_message = e.message))

def log_msg(msg):
    logging.error(msg)


def log_error(msg,domain):
    file_error = "erreurs.txt"
    print (file_error)
    functions_fichiers.ajouter_fichier(file_error,msg)
    functions_system.print_and_flush(functions_system.RED + "Erreur enregistree " +msg + " dans " + file_error+ functions_system.NORMAL)