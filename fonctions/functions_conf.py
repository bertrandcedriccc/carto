import glob,sys,re,os,string,subprocess,os.path,getopt 
import ConfigParser
#https://stackoverflow.com/questions/4029946/multiple-configuration-files-with-python-configparser

def parse_config():
	global Config
	Config = ConfigParser.ConfigParser()
	Config.read("conf/tools.conf")
	Config.sections()


def parse_config_osint():
	cfg_osint = ConfigParser.ConfigParser()
	cfg_osint.read("conf/osint.conf")
	#Config.sections()
	return cfg_osint


def parse_config_pentest_services():
	global Config
	cfg_pentest_services = ConfigParser.ConfigParser()
	cfg_pentest_services.read("conf/pentest_services.conf")
	#Config.sections()
	return cfg_pentest_services


def verif_vulneers():
	dir_nmap = "/usr/share/nmap/scripts/"
	if not os.path.exists(dir_nmap + "vulners.nse"):
		print "script vulners not installed"
		os.system("cp outils/nmap/vulners.nse " + dir_nmap)


	if not os.path.exists(dir_nmap + "http-vulners-regex.nse"):
		print "script http-vulners not installed"
		os.system("cp outils/nmap/http-vulners-regex.nse " + dir_nmap)

	dir_nmap_nselib = "/usr/share/nmap/nselib/data/"
	if not os.path.exists(dir_nmap_nselib + "http-vulners-regex.json"):
		print "script http-vulners-regex.json not installed"
		os.system("cp outils/nmap/http-vulners-regex.json " + dir_nmap_nselib)

	if not os.path.exists(dir_nmap_nselib + "http-vulners-paths.txt"):
		print "script http-vulners-paths.txt not installed"
		os.system("cp outils/nmap/http-vulners-paths.txt " + dir_nmap_nselib)