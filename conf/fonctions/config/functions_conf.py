import glob,sys,re,os,string,subprocess,os.path,getopt 
import configparser

#https://stackoverflow.com/questions/4029946/multiple-configuration-files-with-python-configparser

def Config_Section_Map(section):
    """
    Args:
        section:
    """
    dict1 = {}
    options = Config.options(section)
    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            if dict1[option] == -1:
                print("skip: %s" % option)
        except:
            print(("exception on %s!" % option))
            dict1[option] = None
        return dict1


def parse_config():
	global Config
	Config = ConfigParser.ConfigParser()
	Config.read("conf/tools.conf")
	Config.sections()


def get_cfg_osint():
	cfg_osint = ConfigParser.ConfigParser()
	cfg_osint.read("conf/osint.conf")
	#Config.sections()
	return cfg_osint


def get_cfg_pentest():
    global Config
    config_pentest = configparser.ConfigParser()
    config_pentest.read("conf/pentest_services.conf")
    return config_pentest


def verif_vulneers():
	dir_nmap = "/usr/share/nmap/scripts/"
	if not os.path.exists(dir_nmap + "vulners.nse"):
		print ("script vulners not installed")
		os.system("cp outils/nmap/vulners.nse " + dir_nmap)


	if not os.path.exists(dir_nmap + "http-vulners-regex.nse"):
		print ("script http-vulners not installed")
		os.system("cp outils/nmap/http-vulners-regex.nse " + dir_nmap)

	dir_nmap_nselib = "/usr/share/nmap/nselib/data/"
	if not os.path.exists(dir_nmap_nselib + "http-vulners-regex.json"):
		print ("script http-vulners-regex.json not installed")
		os.system("cp outils/nmap/http-vulners-regex.json " + dir_nmap_nselib)

	if not os.path.exists(dir_nmap_nselib + "http-vulners-paths.txt"):
		print ("script http-vulners-paths.txt not installed")
		os.system("cp outils/nmap/http-vulners-paths.txt " + dir_nmap_nselib)