from distutils.core import setup

with open('README.rst') as file:
    long_description = file.read()

setup(name='PCAPTotal',
      version='1.0',
      description='Extract files from captured TCP sessions. Check against virustotal.com',
      author='Showalter & Payton',
      author_email='washowalter@alaska.edu',
      url='https://github.com/williamshowalter/PCAPTotal.git',
      download_url='https://github.com/williamshowalter/PCAPTotal.git',
      license='GNU General Public License v3 or later (GPLv3+)',
      long_description=long_description,
      keywords='pcap sniff capture analyzer virus virustotal',
      packages=['PCAPTotal', 'PCAPTotal.modules', 'VirusTotalAPI'],
      scripts=['pcaptotal'],
      data_files=[('/usr/local/VirusTotalAPI',['config.ini'])],
      classifiers=['Development Status :: 5 - Production/Stable',
'Environment :: Console',
'Intended Audience :: Information Technology',
'Intended Audience :: System Administrators',
'Intended Audience :: Telecommunications Industry',
'Intended Audience :: Developers',
'Intended Audience :: Education',
'Intended Audience :: End Users/Desktop',
'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
'Natural Language :: English',
'Programming Language :: Python :: 2.5',
'Programming Language :: Python :: 2.6',
'Programming Language :: Python :: 2.7',
'Programming Language :: Python :: 3',
'Topic :: Education :: Testing',
'Topic :: Internet :: Log Analysis',
'Topic :: Security',
'Topic :: Software Development :: Testing',
'Topic :: System :: Networking :: Monitoring']
     )
