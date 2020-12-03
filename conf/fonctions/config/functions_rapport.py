#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os


def create_reports(domaine):
    """
    Args:
     domaine:
    """
    if not os.path.exists("audits/"):
        os.mkdir("audits/")
    if not os.path.exists("audits/" + domaine):
        os.mkdir("audits/" + domaine)
    if not os.path.exists("audits/" + domaine + "/enum"):
        os.mkdir("audits/" + domaine + "/enum")
    if not os.path.exists("audits/" + domaine + "/vulns"):
        os.mkdir("audits/" + domaine + "/vulns")



def gen_nom_rapport(domaine, outil, ext):
    """
    Args:
     domaine:
     outil:
     ext:
    """
    if not os.path.exists("audits/"):
        os.mkdir("audits/")
    if not os.path.exists("audits/" + domaine):
        os.mkdir("audits/" + domaine)
    nom_rapport = "audits/" + domaine + "/" + domaine + "_" + outil + "." + ext
    return nom_rapport
