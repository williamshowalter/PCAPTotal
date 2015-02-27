__author__ = 'Travis'
import requests
from ConfigParser import SafeConfigParser
from pkg_resources import Requirement, resource_filename
import os
from os import sys

# Following block resolves bug in python2 trying to establish SSLv23 by default, where not supported
from requests.adapters import HTTPAdapter
from urllib3 import PoolManager
import ssl
class MyAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_TLSv1)
# END BLOCK

class VirusTotalApi(object):
    parser = SafeConfigParser()
    parser.read(os.path.join('/usr/local/VirusTotalAPI','config.ini'))
    key = parser.get('VirusTotalAPIKey','api_key')
    url = 'https://www.virustotal.com/vtapi/v2/'
    session = None

    def __init__(self):
        self.session = requests.Session()
	# Fix ssl
        self.session.mount ('https://', MyAdapter());

    def fileScan(self, f):
        params = {"apikey": self.key}
        r = self.session.post(self.url+"file/scan", params=params, files=f)
        return r.json()

    def fileReScan(self, resource):
        params = {"apikey": self.key, "resource": resource}
        r = self.session.post(self.url+"file/rescan/", params=params)
        return r.json()

    def fileReport(self, resource):
        params = {"apikey": self.key, "resource": resource}
        r = self.session.post(self.url+"file/report", params=params)
        return r.json()

    def urlScan(self, url):
        params = {"apikey": self.key, "url": url}
        r = self.session.post(self.url+"url/scan", params=params)
        return r.json()

    def urlReport(self, url, scan=0):
        params = {"apikey": self.key, "url": url, "scan": scan}
        r = self.session.post(self.url+"url/report", params=params)
        return r.json()

    def ipReport(self,ip):
        params = {"apikey": self.key, "ip": ip}
        r = self.session.get(self.url+"ip-address/report", params=params)
        return r.json()

    def domainReport(self, domain):
        url = self.url+"domain/report"
        params = {"apikey": self.key, "domain": domain}
        r = self.session.get(url, params=params)
        return r.json()



"""
Default SSL versions are sometimes causing errors for being unsupported by VirusTotal's servers
-- Will 2014-Dec-10
"""
import ssl
from functools import wraps
def sslwrap(func):
    @wraps(func)
    def bar(*args, **kw):
        kw['ssl_version'] = ssl.PROTOCOL_TLSv1
        return func(*args, **kw)
    return bar

ssl.wrap_socket = sslwrap(ssl.wrap_socket)


# Sample Usage
#
# vt = VirusTotalApi()
# print "Testing Domain"
# print vt.domainReport("google.com")
#
# print "Testing IP"
# print vt.ipReport("8.8.8.8")
#
# print "Testing fileReport"
# print vt.fileReport("99017f6eebbac24f351415dd410d522d")

