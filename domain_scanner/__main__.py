import argparse
import os
from threading import Thread, Lock
import requests
from .sublist3r import sublist3r
from .dnstrails import DNSTrailsScanner, DNSTrailsScannerException
from .nmap_parser import NMAPScanObject, PortInfo

version = "0.0.1"
print(
    """
______                      _           
|  _  \                    (_)          
| | | |___  _ __ ___   __ _ _ _ __      
| | | / _ \| '_ ` _ \ / _` | | '_ \     
| |/ / (_) | | | | | | (_| | | | | |    
|___/ \___/|_| |_| |_|\__,_|_|_| |_|    
                                        
                                        
 _____                                  
/  ___|                                 
\ `--.  ___ __ _ _ __  _ __   ___ _ __  
 `--. \/ __/ _` | '_ \| '_ \ / _ \ '__| 
/\__/ / (_| (_| | | | | | | |  __/ |    
\____/ \___\__,_|_| |_|_| |_|\___|_|    
                                        

By JubyLey. Version %s
Based on:
    Sublist3r By Ahmed Aboul-Ela - twitter.com/aboul3la
    Nmap by https://nmap.org 
    """%version
)

argument_parser = argparse.ArgumentParser(description="Domain scanner utility. Get domain subdomains and check their availability.")
argument_parser.add_argument('-d', '--domain', help="Domain name to scan", required=True)
argument_parser.add_argument('-p', '--project-folder', help="Folder for scan files", required=False, default="")
argument_parser.add_argument('-nf', '--nmap-flags', help="Flags for nmap scan", required=False, default="-sV -v -O -A -sT")
argument_parser.add_argument('-dk', '--dnstrails-key-file', help="File with api keys for dnstrails", required=False, default=None)
argument_parser.add_argument('-n', '--nthreads', help="Number of threads", required=False, default=1)
args = argument_parser.parse_args()

domain = args.domain
nmap_flags = args.nmap_flags
dnstrails_keys = args.dnstrails_key_file
project_folder = args.project_folder
nthreads = int(args.nthreads)
if project_folder=="":
    project_folder = domain

if os.path.exists(project_folder):
    if len(os.listdir(project_folder)) != 0:
        print("Error: Project folder must be empty")
        exit(-1)
else:
    os.mkdir(project_folder)
print("Project folder: %s"%project_folder)

if dnstrails_keys:
    with open(dnstrails_keys, "r") as i_f:
        keys = list(map(lambda x: x.strip(), iter(i_f)))
else:
    keys = []
print()
dnstrails_scanner = []
dnstrails_scanner_found = False
dnstrails_scanner_quota = -1
for k in keys:
    try:
        dnstrails_scanner = DNSTrailsScanner(k)
        dnstrails_scanner_quota = dnstrails_scanner.get_qouta()
        if dnstrails_scanner_quota>0:
            dnstrails_scanner_found = True
            break
    except DNSTrailsScannerException as e:
        print(f"DNSTrails APIKEY: {k}. Error: {e}")

if dnstrails_scanner_found:
    descr = dnstrails_scanner.description()
    print(f"{descr}. Quota: {dnstrails_scanner_quota}")

sublist3r_subdomains = list(sublist3r.main(domain, nthreads, None, None, True, False, False, None))
dnstrails_subdomains = []
if dnstrails_scanner_found:
    dnstrails_subdomains = dnstrails_scanner.get_subdomains(domain)

domains =  list(set(sublist3r_subdomains+dnstrails_subdomains))
with open(f"{project_folder}/subdomains", "w") as o_f:
    for d in domains:
        o_f.write(f"{d}\n")

targets = domains.copy()
targets_lock = Lock()
print()
def nmap_scan():
    global targets
    global targets_lock
    global project_folder
    global nmap_flags

    while True:
        targets_lock.acquire()
        if len(targets) == 0:
            targets_lock.release()
            return
        current_target = targets[0]
        print(f"Start scanning {current_target}")
        targets = targets[1:]
        targets_lock.release()
        os.system(f"nmap {nmap_flags} {current_target} > {project_folder}/{current_target}")

threads = []
for i in range(nthreads):
    t = Thread(target=nmap_scan)
    threads.append(t)
    t.start()

for t in threads:
    t.join()

print()
print("Start parsing scanning info")
scans = {}
for f in os.listdir(project_folder):
    if f == "subdomains":
        continue
    with open(f"{project_folder}/{f}", "r") as i_f:
        data = i_f.read()
    scans[f] = NMAPScanObject(data)
    print(f"Found {len(scans[f].ports)} ports at {f} scan")

print()
print("Start checking http and https ports")

with open(f"{project_folder}/webportsinfo", "w") as o_f:
    for k, v in scans.items():
        if len(v.ports) == 0:
            pass
        for p in v.ports:
            try:
                if p.service == "http":
                    url = f"http://{k}:{p.port}"
                    resp = requests.get(url)
                    print(f"Found http port: {url} with status code: {resp.status_code}")
                    o_f.write(f"{url}    {resp.status_code}\n")
                if p.service.find("ssl")!=-1:
                    url = f"https://{k}:{p.port}"
                    resp = requests.get(url)
                    print(f"Found ssl port: {url} with status code: {resp.status_code}")
                    o_f.write(f"{url}    {resp.status_code}\n")
            except Exception as e:
                print(f"[ERROR} {e}")
