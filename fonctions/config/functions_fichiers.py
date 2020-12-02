


def ecrire_fichier(name_file,contenu_file):
    file = open(name_file, "w")
    file.write(contenu_file) 
    file.close()
    #print "ecriture du fichier " + name_file + " contenu : " + contenu_file

def ajouter_fichier(name_file,contenu_file):
  file = open(name_file, "a")
  file.write(contenu_file) 
  file.close()


def lire_fichier(name_file):
  with open(name_file) as f:
    content = f.readlines()
  return content


def add_vuln(projet,vuln):
  name_file= "reports_gen/"+projet+"/vulns.txt"
  file = open(name_file, "a")
  file.write(vuln) 
  file.close()
