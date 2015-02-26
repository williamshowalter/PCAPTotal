""" PCAPTotal - virus checking library
	By Travis Payton & William Showalter

	Built using modified version of tcpextract library
    Copyright (C) 2012  https://www.abnorm.org/contact/

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
import threading
import hashlib
import time
from Nids import Nids
from PCAPTotal import FileExtractor,ProtocolNotSupported
from VirusTotalAPI import VirusTotalApi

def checkReport(fileName, hashString):
	vt = VirusTotalApi()
	fileReport = vt.fileReport(hashString)
	# If file is in VirusTotal database
	if fileReport["response_code"]:
		print ""
		print "Following known issues in file", fileName,":"
		reports = fileReport["scans"]
		for site in reports:
			#If site detected known virus
			if (reports[site]["detected"] == True):
				print site, "detected: ", reports[site]["result"], ", Date: ", reports[site]["update"]
		print "**** END REPORT ON FILE", fileName,"****"
		print ""
	else:
		print "No known issues in file", fileName
		print ""

class Parser(threading.Thread):
	def __init__(self,nids):
		threading.Thread.__init__(self)
		self.nids=nids
		self.files=[]
	def run(self):
		i=0
		count = 0
		while self.nids.isAlive() or not Nids.queue.empty():
			try:
				tmp=Nids.queue.get()
				s=FileExtractor(tmp)
			except ProtocolNotSupported:
				continue
			s.getFiles()
			for f in s.files:
				count+=1
				if f[0]:
					fileName=f[0]
				else:
					fileName='file%02d.%s'+i+f[1]
					i+=1
				hashObj = hashlib.sha256()
				hashObj.update(f[2])
				checkReport (fileName, hashObj.hexdigest())
				if (count==4): #stop for a minute after every 4 requests, as the API is limited
								# A better method would be to keep a list of lookups in the last 60 seconds, cleaning old ones out, and waiting if that list has 4 items
					time.sleep(60)
					count=0
			s.files[:] = [] #clear so we don't see them multiple times - theoretically shouldn't happen?
