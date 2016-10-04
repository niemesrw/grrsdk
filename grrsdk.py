# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
import argparse
import base64
import ConfigParser
import json
import logging
import logging.config
import os
import time
import requests

config = ConfigParser.ConfigParser()
config.read('grrsdk.ini')

baseurl = config.get('grrsdk','baseurl')
username = config.get('grrsdk','username')
password = config.get('grrsdk','password')

logging.config.fileConfig('logging.conf')

# create logger
logger = logging.getLogger('grrsdk')

def read_file_contents(path):
    logger.debug('in function read_file_contents')
    if os.path.exists(path):
        with open(path) as infile:
            return infile.read().strip()

def read_file_contents(path):
    logger.debug('in function read_file_contents')
    if os.path.exists(path):
        with open(path) as infile:
            return infile.read().strip()

class GRRClient:
    logger.debug('in class GRRClient')
    token = None
    session = requests.Session()
    jdata = {}
    
    def __init__(self):
        self.token = self.load_token()
        self.end = int(time.time() * 1000)   # time we are running this script

        if self.token:
            self.session.headers.update({'X-csrftoken': self.token})
        else:
            # if no token, do login
            if not self.token:
                try:
                    self.login()
                except requests.HTTPError:
                    sys.exit('Username-password invalid')

       # if self.start == None:
       #     self.start = 1463441314000

    def login(self):
        logger.debug('inside method login()')
        base64string = base64.encodestring('%s:%s' % (username,password)).replace('\n', '')
        authheader = "Basic %s" % base64string
        self.index_response = requests.get(baseurl, auth=(username,password))
        csrf_token = self.index_response.cookies.get("csrftoken")
        self.headers = {
        	"Authorization": authheader,
        	"x-csrftoken": csrf_token,
        	"x-requested-with": "XMLHttpRequest"
			}

    def is_installed(self,ip):
        """
        is_installed(ip) takes the argument of an IP address and returns 1 if grr is installed on that host, 0 otherwise
        """
        logger.debug('inside method is_installed()')
        self.grr_query_ip(ip)
    	if self.jdata['items']:
            logger.debug('grr is already installed on %s' % (ip))
            return 1
    	else:
            logger.debug('grr is not installed on %s' % (ip))
            return 0

    def load_token(self):
        return read_file_contents('token')

    def grr_query_ip(self,ip):
        logger.debug('inside grr_query_ip, args: %s' % (ip))
        req = ('%s/api/clients?query=%s' % (baseurl, ip))
        # the text[5:] is to remove the first few characters that are in the JSON response for XSSI protection
        r = requests.get(req, auth=(username, password)).text[5:]
        self.jdata = json.loads(r)
        return 0

    def grr_get_all_clients(self):
        """
        grr_get_all_clients has no returns, simply loading up the json object of self.jdata with the results
        """
        req = ('%s/api/clients' % (baseurl))
        # the text[5:] is to remove the first few characters that are in the JSON response for XSSI protection
        r = requests.get(req, auth=(username,password)).text[5:]
        self.jdata = json.loads(r)

    def iterate_clients(self):
        """
        iterate_clients prints the fqdn and urn of every client in grr
        """
        self.grr_get_all_clients()
        for host in self.jdata['items']:
            try:
                print '%s,%s' % (host['value']['os_info']['value']['fqdn']['value'], host['value']['urn']['value'][6:])
            except KeyError as e:
                print "unknown,%s" % (host['value']['urn']['value'][6:])

    def print_client_info(self,ip):
        """
        this method takes an IP address and prints basic information about the host
        """
        if self.is_installed(ip):
        #    print json.dumps(self.jdata, indent=4, sort_keys=True)
            try:
                print '%s,%s' % (self.jdata['items'][0]['value']['os_info']['value']['fqdn']['value'],
                                 self.jdata['items'][0]['value']['urn']['value'][6:])
            except KeyError as e:
                print "unknown,%s" % (self.jdata['items'][0]['value']['urn']['value'][6:])
        else:
            print 'client unknown: %s' % (ip)

#def install_grr(ip):
#    #hclogger.info(message="inside method install_grr(): installing grr on %s" % (ip))
#    command = "%s \\\\%s -c -f -s %s" % (myconf.take('executable_locations.psexec'), ip, myconf.take('executable_locations.grr_64bit'))
#    #hclogger.info(message="full command line %s" % (command))
#    try:
#    #    hclogger.info(message='install_grr running')
#        subprocess.call(command)
#        #hclogger.info(message='install_grr proc return code' % (proc))
#    except:
#        print 'exception in install_grr'
#    #    hclogger.info(message="exception inside install_grr %s" % (sys.exc_info()[0]))
#
#        #stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
#    return proc


    def get_urn_from_ip(self,ip):
        logger.debug('inside method get_urn_from_ip')
        req = ('%s/api/clients?query=%s' % (baseurl, ip))
        # the text[5:] is to remove the first few characters that are in the JSON response for XSSI protection
        r = requests.get(req, auth=(username, password)).text[5:]
        jdata = json.loads(r)
        urn = jdata['items'][0]['value']['urn']['value'][6:]
        return urn

    def execute_python_hack(self,hack_name,ip):
        python_hack = {
            "flow": {
                "args": {
                    "hack_name": hack_name,
                },
                "name": "ExecutePythonHack",
                "runner_args": {
                    "notify_to_user": 0,
                    "output_plugins": [],
                    "priority": "HIGH_PRIORITY"
                }
            }
        }
        print python_hack
        urn = self.get_urn_from_ip(ip)
        print urn
        req = ('%s/api/clients/%s/flows' % (baseurl, urn))
        r = requests.post(req, auth=(username, password)).text[5:]
        logger.debug('full req %s' % (req))
        r = requests.post(req, data=json.dumps(python_hack), headers=self.headers, cookies=self.index_response.cookies)    

    def run_flow(self,flow_name,urn):
        flow = {
            "flow": {
                "name": flow_name,
                "runner_args": {
                    "notify_to_user": 0,
                    "output_plugins": [],
                    "priority": "MEDIUM_PRIORITY"
                }
            }
        }
        req = ('%s/api/clients/%s/flows' % (baseurl, urn))
        r = requests.post(req, auth=(username, password)).text[5:]
        logger.debug('full req %s' % (req))
        r = requests.post(req, data=json.dumps(flow), headers=self.headers, cookies=self.index_response.cookies)    
    
    def get_flows(self,urn):
        req = ('%s/api/clients/%s/flows' % (baseurl, urn))
        r = requests.get(req, auth=(username, password)).text[5:]
        jdata = json.loads(r)
        print json.dumps(self.jdata, indent=4, sort_keys=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    #group = parser.add_mutually_exclusive_group()
    #group.add_argument("-v", "--verbose", action="store_true")
    #group.add_argument("-q", "--quiet", action="store_true")
    #group.add_argument('-c', '--c', help='print all clients to standard output', action='store_true')
    parser.add_argument('-n', '--n', help='run netstat flow on client', action='store_true')
    parser.add_argument('-l', '--l', help='run listprocesses flow on client', action='store_true')
    parser.add_argument('-g', '--g', help='list flows on client')
    parser.add_argument('ip_address', help='ip address to query')
    args = parser.parse_args()
    g = GRRClient()
    #q = g.is_installed(args.ip)
    #print q
    #if args.q:
    #    g.print_client_info(args.ip_address)
    #if args.c:
    #    g.iterate_clients()
    #g.grr_get_all_clients()
    g.print_client_info(args.ip_address)
    urn = g.get_urn_from_ip(args.ip_address)
    if args.n:
        g.run_flow('Netstat',urn)
    if args.l:
        g.run_flow('ListProcesses',urn)
    #g.execute_python_hack('get_mbambr.py',args.ip_address)
