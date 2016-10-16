import argparse
import base64
import ConfigParser
import json
import logging
import logging.config
import os
import sys
import requests
import time

config = ConfigParser.ConfigParser()
config.read('grrsdk.ini')
baseurl = config.get('grrsdk', 'baseurl')
username = config.get('grrsdk', 'username')
password = config.get('grrsdk', 'password')

logging.config.fileConfig('logging.conf')

# create logger
logger = logging.getLogger('grrsdk')

def read_file_contents(path):
    logger.debug('in function read_file_contents')
    if os.path.exists(path):
        with open(path) as infile:
            return infile.read().strip()

class GRRClient:
    logger.debug('in class GRRClient')

    def __init__(self):
        self.data = {}
        # self.token = None
        self.token = self.load_token()
        self.start = int(time.time() * 1000)
        self.session = requests.Session()
        self.session.auth = (username, password)

        if self.token:
            #self.session.headers.update({'X-csrftoken': self.token})
            self.session.cookies.update({'csrftoken': self.token})
            #self.session.cookies.set({'csrftoken': self.token,
            #                          'domain': 'grr.illumina.com'})
        else:
            # if no token, do login
            if not self.token:
                try:
                    self.login()
                except requests.HTTPError:
                    sys.exit('Username-password invalid')

       # if self.start == None:
       #     self.start =
        self.headers = {
#            "Authorization": authheader,
            "x-csrftoken": self.token,
            "x-requested-with": "XMLHttpRequest"
        }

    def login(self):
        print 'running login'
        # self.index_response = requests.get(baseurl, auth=(username,password))
        # self.session = requests.Session()
        # self.session.auth = (username, password)
        self.session.get(baseurl)
        print self.session.cookies

        xsrf_token = self.session.cookies.get('csrftoken')
        self.session.headers.update({'x-csrftoken': xsrf_token,
                                     'x-requested-with': 'XMLHttpRequest'})

        print xsrf_token
        with open('token', 'w') as f:
            f.write(xsrf_token)

        self.headers = {
           # "Authorization": authheader,
            "x-csrftoken": xsrf_token,
            "x-requested-with": "XMLHttpRequest"
        }

    def is_installed(self, ip):
        """
        is_installed(ip) takes the argument of an IP address and returns 1 if grr is installed on that host, 0 otherwise
        """
        logger.debug('method=is_installed')
        self.query_ip(ip)
        print self.session.headers

        if self.data['items']:
            logger.debug('grr is already installed on %s' % (ip))
            return 1
        else:
            logger.debug('grr is not installed on %s' % (ip))
            return 0

    def load_token(self):
        return read_file_contents('token')

    def query_ip(self, ip):
        logger.debug('method=query_ip, args=%s' % ip)
        req = ('%s/api/clients?query=%s&strip_type_info=1' % (baseurl, ip))
        # the text[5:] is to remove the first few characters that are in the JSON response for XSSI protection
        r = self.session.get(req, cookies=self.session.cookies).text[5:]
        self.data = json.loads(r)
        return 0

    def get_all_clients(self):
        """
        grr_get_all_clients has no returns, simply loading up the json object of self.data with the results
        """
        req = ('%s/api/clients&strip_type_info=1' % (baseurl))
        # the text[5:] is to remove the first few characters that are in the JSON response for XSSI protection
        r = self.session.get(req, cookies=self.session.cookies)
        print r
        r.raise_for_status()

        self.data = json.loads(r)
        print json.dumps(r, indent=4, sort_keys=True)

    def iterate_clients(self):
        """
        iterate_clients prints the fqdn and urn of every client in grr
        """
        self.get_all_clients()
        for host in self.data['items']:
            try:
                print '%s,%s' % (host['os_info']['fqdn'], host['urn'][6:])
            except KeyError as e:
                print "unknown,%s" % (host['urn'][6:])

    def print_client_info(self, ip):
        """
        this method takes an IP address and prints basic information about the host
        """
        if self.is_installed(ip):
            try:
                print '%s,%s' % (self.data['items'][0]['os_info']['fqdn'],
                                 self.data['items'][0]['urn'][6:])
            except KeyError as e:
                print 'Error in method print_client_info: %s' % e, ': %s'
        else:
            print 'client unknown: %s' % (ip)

    def get_urn_from_ip(self, ip):
        """
        this method returns the client URN from a given IP address
        :param ip:
        :return:
        """
        logger.debug('inside method get_urn_from_ip')
        req = ('%s/api/clients?query=%s' % (baseurl, ip))
        # the text[5:] is to remove the first few characters that are in the JSON response for XSSI protection
        # r = requests.get(req, auth=(username, password)).text[5:]
        r = self.session.get(req).text[5:]
        jdata = json.loads(r)
        urn = jdata['items'][0]['value']['urn']['value'][6:]
        return urn

    def execute_python_hack(self, hack_name, ip, notify=0):
        """
        this method runs a python hack on the IP address passed to the method
        :param hack_name:
        :param ip:
        :return: success or an error message
        """
        python_hack = {
            "flow": {
                "args": {
                    "hack_name": hack_name,
                },
                "name": "ExecutePythonHack",
                "runner_args": {
                    "notify_to_user": notify,
                    "output_plugins": [],
                    "priority": "HIGH_PRIORITY"
                }
            }
        }
        urn = self.get_urn_from_ip(ip)
        req = ('%s/api/clients/%s/flows?strip_type_info=1' % (baseurl, urn))
        result = self.session.post(req, data=json.dumps(python_hack), headers=self.headers, cookies=self.session.cookies).text[5:]
        #print result
        print json.dumps(result, indent=4, sort_keys=True)
        #return result

    def run_flow(self, flow_name, urn):
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
