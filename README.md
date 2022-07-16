# DomainScanner
## _Automate subdomains scanning_

DomainScanner is small tool written in python 3 for automate search and scan subdomains. 

-   Find subdomains using sublist3r and DNSTrails
-   Scan subdomains with nmap
-   Checks for ssl and http port availability for the web browser

## Based On 
-----
- [Sublist3r](https://github.com/aboul3la/Sublist3r) By Ahmed Aboul-Ela - twitter.com/aboul3la
- [Nmap](https://nmap.org/)

## Recommended Python version
---
Domain Scanner currently supports only Python 3.8+

## Installation
---
Domain Scanner depends on argparse, dnspython and requests.
It is necessary that the PATH variable contains the directory with the nmap executable file
- Installing with venv from source on Linux:
```sh
git clone https://github.com/JubyL3y/DomainScanner
cd DomainScanner
python3 -m venv venv
source ./venv/bin/activate
python -m pip install -r requirements.txt
```

- Installing with venv from source on Windows with powershell:
```sh
git clone https://github.com/JubyL3y/DomainScanner
cd DomainScanner
python3 -m venv venv
.\venv\Scripts\activate.ps1
python -m pip install -r requirements.txt
```
## Usage
----
```
cd Domain Scanner
source ./venv/bin/activate
python -m domain_scanner [-h] -d DOMAIN [-p PROJECT_FOLDER] [-nf NMAP_FLAGS] [-dk DNSTRAILS_KEY_FILE] [-n NTHREADS]
```

## Options
----
```
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain name to scan
  -p PROJECT_FOLDER, --project-folder PROJECT_FOLDER
                        Folder for scan files
  -nf NMAP_FLAGS, --nmap-flags NMAP_FLAGS
                        Flags for nmap scan
  -dk DNSTRAILS_KEY_FILE, --dnstrails-key-file DNSTRAILS_KEY_FILE
                        File with api keys for dnstrails
  -n NTHREADS, --nthreads NTHREADS
                        Number of threads
```

## License
Sublist3r is licensed under the GNU GPL license. take a look at the domain_scanner/sublist3r/LICENSE for more information.
Domain Scanner is licensed under the GNU GPL-3.0 license. take a look at the LICENSE for more information.
