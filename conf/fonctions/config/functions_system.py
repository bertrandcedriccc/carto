#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Utilisation fuzzing
#import datetime
import os
import signal
import subprocess
import time
from datetime import datetime

RED = '\x1b[91m'
RED1 = '\033[31m'
BLUE = '\033[94m'
GREEN = '\033[32m'
BOLD = '\033[1m'
NORMAL = '\033[0m'
ENDC = '\033[0m'


def lancer_cmd(commande):
    # print (commande)
    """
    Args:
        commande:
    """
    p = subprocess.Popen(commande, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    result = p.stdout.read()
    result = result.decode("utf-8")
    return result


def lancer_cmd_with_timeout(commande, timeout):
    """
    Args:
        commande:
        timeout:
    """
    start = datetime.now()
    process = subprocess.Popen(commande, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = ""
    while process.poll() is None:
        time.sleep(0.1)
        now = datetime.now()
        if (now - start).seconds > timeout:
            os.kill(process.pid, signal.SIGKILL)
            os.waitpid(-1, os.WNOHANG)
            print("process killed")
            return None
    result = process.stdout.read()
    # result = result.encode("utf-8").decode("utf-8")
    result = result.decode("utf-8")
    # print (result)
    return result
