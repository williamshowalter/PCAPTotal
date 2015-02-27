==========
PCAPTotal
==========
PCAPTotal - virus checking library
	By Travis Payton & William Showalter

	Built using modified version of tcpextract library
    Copyright (C) 2012  https://www.abnorm.org/contact/

==========
tcpextract
==========

`https://www.abnorm.org/projects/tcpextract/ <https://www.abnorm.org/projects/tcpextract/>`_

Extract files from captured TCP sessions. Support live streams and pcap files.

Supported protocols are:

* HTTP (GET)

Requirements
^^^^^^^^^^^^
* Python 2.5 or Python 3 or later
* pynids (http://jon.oberheide.org/pynids/)

*********
* a VirusTotal.com API key, set in /usr/local/VirusTotalAPI/config.ini file.
Can set config file before install.

*********


VIRUS TOTAL MAY RETURN SSL ERRORS IF THE FOLLOWING ARE NOT PRESENT:
apt-get install libpcap-dev pkg-config python-dev libgtk2.0-dev libnet1-dev libnids1.21 libnids-dev

Install pynids-0.6.1 from source (Ubuntu repo build has errors, other repos may or may not)
(follow instructions: http://xgusix.com/blog/installing-pynids-in-ubuntu-12-10-x64/)

pip install urllib3
pip install pyopenssl
pip install ndg-httpsclient
pip install pyasn1


Install
^^^^^^^
Gentoo users:
-------------
You should first enable the `Abnorm Overlay <https://www.abnorm.org/portage/>`_ then you can install it::

	emerge tcpextract

-----------------------------------------

To install from git please run::

	$ git clone https://github.com/williamshowalter/PCAPTotal.git
	$ cd PCAPTotal
	$ sudo python setup.py build install

Usage
^^^^^
When you run PCAPTotal, by default, it will listen on any avaible interface and will put extracted files in './output'.
Please remember that capturing live streams will require root privileges.
Live sniffing is really slow. If you can, use tcpdump or something else to capture data.

If you want further information on how to change default behavior please run::

	$ pcaptotal-run --help

Licensing
^^^^^^^^^
PCAPTotal is released under `GPLv3 <https://www.gnu.org/licenses/gpl-3.0.html>`_ or later.
