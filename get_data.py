import os
import sys
import requests
import gzip
import csv
from datetime import datetime

# Exit when not on shell
if 'REMOTE_ADDR' in os.environ:
    print("This should be run from the CLI")
    sys.exit(0)

regs = ["ripencc", "apnic", "arin", "afrinic", "lacnic"]
indir = "in"
outdir = "out"

print("Time: ", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

dbs = {
    'ripe': {
        'serial': "https://ftp.ripe.net/ripe/dbase/RIPE.CURRENTSERIAL",
        'db': "https://ftp.ripe.net/ripe/dbase/ripe.db.gz"
    },
    'apnic': {
        'serial': "https://ftp.apnic.net/apnic/whois/APNIC.CURRENTSERIAL",
        'db': "https://ftp.apnic.net/apnic/whois/apnic.db.route.gz"
    },
    'apnic6': {
        'serial': "https://ftp.apnic.net/apnic/whois/APNIC.CURRENTSERIAL",
        'db': "https://ftp.apnic.net/apnic/whois/apnic.db.route6.gz"
    },
    'lacnic': {
        'serial': "https://ftp.lacnic.net/lacnic/irr/LACNIC.CURRENTSERIAL",
        'db': "https://ftp.lacnic.net/lacnic/irr/lacnic.db.gz"
    },
    'arin': {
        'serial': "https://ftp.arin.net/pub/rr/ARIN.CURRENTSERIAL",
        'db': "https://ftp.arin.net/pub/rr/arin.db.gz"
    },
    'afrinic': {
        'serial': "https://ftp.afrinic.net/dbase/AFRINIC.CURRENTSERIAL",
        'db': "https://ftp.afrinic.net/dbase/afrinic.db.gz"
    }
}

cdbs = {
    'ripe': {
        'hash': "https://ftp.ripe.net/ripe/stats/delegated-ripencc-extended-latest.md5",
        'db': "https://ftp.ripe.net/ripe/stats/delegated-ripencc-extended-latest"
    },
    'apnic': {
        'hash': "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest.md5",
        'db': "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest"
    },
    'lacnic': {
        'hash': "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest.md5",
        'db': "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest"
    },
    'arin': {
        'hash': "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest.md5",
        'db': "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"
    },
    'afrinic': {
        'hash': "https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest.md5",
        'db': "https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest"
    }
}

# Function to download files
def download_file(url, dest):
    response = requests.get(url, stream=True)
    if response.status_code == 200:
        with open(dest, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    return False

# Function to safely convert to float
def safe_float_convert(value):
    try:
        return float(value)
    except ValueError:
        return None

# Download current DB
for rir, db in dbs.items():
    print(f"Check serial for RIR {rir}")
    onlineserial = requests.get(db['serial']).text.strip()
    dbfile = os.path.basename(db['db'])
    localserial = ""
    
    if os.path.isfile(f"{indir}/{dbfile}.serial"):
        with open(f"{indir}/{dbfile}.serial", 'r') as f:
            localserial = f.read().strip()

    online_serial_float = safe_float_convert(onlineserial)
    local_serial_float = safe_float_convert(localserial)

    if online_serial_float is None or local_serial_float is None:
        print(f"Warning: Unable to convert serial values to float for RIR {rir}. Skipping download check.")
        continue

    if (localserial == "") or (online_serial_float > local_serial_float):
        print(f"Download file {db['db']}")
        if download_file(db['db'], f"{indir}/{dbfile}"):
            print(f"File {dbfile} downloaded successfully")
            with open(f"{indir}/{dbfile}.serial", 'w') as f:
                f.write(onlineserial)
        else:
            print(f"Failed to download {dbfile}")

# Download current DB
for rir, db in cdbs.items():
    print(f"Check hash for RIR {rir}")
    onlineserial = requests.get(db['hash']).text.strip()
    dbfile = os.path.basename(db['db'])
    localserial = ""
    
    if os.path.isfile(f"{indir}/{dbfile}.hash"):
        with open(f"{indir}/{dbfile}.hash", 'r') as f:
            localserial = f.read().strip()

    if (localserial == "") or (onlineserial != localserial):
        print(f"Download file {db['db']}")
        if download_file(db['db'], f"{indir}/{dbfile}"):
            print(f"File {dbfile} downloaded successfully")
            with open(f"{indir}/{dbfile}.hash", 'w') as f:
                f.write(onlineserial)
        else:
            print(f"Failed to download {dbfile}")

rirs = {}
for reg in regs:
    file_path = f"{indir}/delegated-{reg}-extended-latest"
    if os.path.isfile(file_path):
        rirs[reg] = {'file': file_path}

# Function to calculate subnet bits
def calc_snbits(nr):
    sn = 0
    while nr > 1:
        nr /= 2
        sn += 1
    return sn

# Function to validate CIDR notation
def validate_cidr(cidr):
    parts = cidr.split('/')
    if len(parts) != 2:
        return False
    
    ip, netmask = parts
    if not netmask.isdigit():
        return False
    
    netmask = int(netmask)
    if netmask < 0:
        return False
    
    if '.' in ip:  # IPv4
        return netmask <= 32
    elif ':' in ip:  # IPv6
        return netmask <= 128
    return False

rip = {}
cip = {}
guid = {}
asn = {}
asguid = {}
asroutes = {}

print("Parse RIR allocations")
for rir, info in rirs.items():
    if os.path.isfile(info['file']):
        print(f"Parsing file {info['file']}")
        with open(info['file'], 'r') as f:
            for entry in f:
                el = entry.strip().split('|')
                if len(el) < 8:
                    continue
                
                el[3] = el[3].strip()
                el[7] = el[7].strip()
                if el[2] == "asn":
                    asn[el[3]] = el[7]
                    asguid[el[7]] = el[3]
                elif el[2] in ["ipv4", "ipv6"]:
                    if "assigned" in el[6] or "allocated" in el[6]:
                        bits = 32 - calc_snbits(int(el[4])) if el[2] == "ipv4" else int(el[4])
                        cidr = f"{el[3]}/{bits}"
                        if validate_cidr(cidr):
                            cip.setdefault(el[1], []).append(cidr)
                            rip.setdefault(rir, []).append(cidr)
                            guid.setdefault(el[7], []).append(cidr)
                        else:
                            print(f"Address '{cidr}' is not valid in {info['file']}, skipping")

print("Parse RIR GUID ASN routes")
for as_num, id in asn.items():
    if id in guid:
        if as_num not in asroutes:
            asroutes[as_num] = guid[id]
        else:
            asroutes[as_num] += guid[id]

regions = {}
if os.path.isfile("all.csv"):
    with open("all.csv", 'r') as csvfile:
        csvreader = csv.reader(csvfile)
        try:
            header = next(csvreader)  # Skip header
        except StopIteration:
            print("all.csv is empty, skipping region processing")
        for row in csvreader:
            if row[6]:
                regions.setdefault(row[6], []).append(row[1])
else:
    print("all.csv file not found, skipping region processing")

print("Write Aggregate RIR lists")
os.makedirs(f"{outdir}/rir", exist_ok=True)
for rir, arr in rip.items():
    with open(f"{outdir}/rir/{rir}.txt", 'w') as f:
        f.write("\n".join(arr))

print("Write Aggregate country lists from all RIRs")
os.makedirs(f"{outdir}/country", exist_ok=True)
for country, arr in cip.items():
    with open(f"{outdir}/country/{country}.txt", 'w') as f:
        f.write("\n".join(arr))

print("Parse RIR DB for ASN routes")
for rir, db in dbs.items():
    db_path = f"{indir}/{os.path.basename(db['db'])}"
    if os.path.isfile(db_path):
        print(f"Parsing {db_path}")
        with gzip.open(db_path, 'rt', errors='replace') as f:
            for line in f:
                if line.startswith("route:") or line.startswith("route6:"):
                    route = line.split()[1].strip()
                elif line.startswith("origin:"):
                    as_num_str = line.split()[1].strip().upper().replace("AS", "")
                    try:
                        as_num = int(as_num_str)
                        asroutes.setdefault(as_num, []).append(route)
                    except ValueError:
                        print(f"Warning: Invalid ASN '{as_num_str}' in {db_path}")
                    route = None

print("Write ASN files")
os.makedirs(f"{outdir}/asn", exist_ok=True)
for as_num, routes in asroutes.items():
    if routes:
        with open(f"{outdir}/asn/AS{as_num}.txt", 'w') as f:
            f.write("\n".join(set(routes)))

print("Time: ", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
