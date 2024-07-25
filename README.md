Python version of https://github.com/smos/ip-edl/ with a few minor additions

ASNs
/data?asn=44477
/data?asn=44477;62240

Country
/data?country=RU
/data?country=RU;CN

Output Data
/data?asn=44477&output=csv
/data?asn=44477&output=txt

From command line
usage: query_data.py [-h] [-asn ASN] [-country COUNTRY] [-rir RIR] [-output {csv,txt}]

Process ASN, country, and RIR data

options:
  -h, --help         show this help message and exit
  -asn ASN           List of ASNs separated by semicolons
  -country COUNTRY   List of countries separated by semicolons
  -rir RIR           List of RIRs separated by semicolons
  -output {csv,txt}  Output format: 'csv' or 'txt'
