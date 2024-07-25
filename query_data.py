import os

outdir = "out"

def rlimit(cl):
    return cl[:7]

def climit(cl):
    return cl[:2]

def aslimit(asn):
    return asn[:6]

def process_rir(rir_list):
    data = {rir: [] for rir in rir_list}
    for rir in rir_list:
        rir_file = f"{outdir}/rir/{rir}.txt"
        if os.path.isfile(rir_file):
            with open(rir_file, 'r') as f:
                data[rir].extend(f.read().splitlines())
    return data

def process_country(country_list):
    data = {country: [] for country in country_list}
    for country in country_list:
        country_file = f"{outdir}/country/{country}.txt"
        if os.path.isfile(country_file):
            with open(country_file, 'r') as f:
                data[country].extend(f.read().splitlines())
    return data

def process_asn(asn_list):
    data = {asn: [] for asn in asn_list}
    for asn in asn_list:
        asn_file = f"{outdir}/asn/AS{asn}.txt"
        if os.path.isfile(asn_file):
            with open(asn_file, 'r') as f:
                data[asn].extend(f.read().splitlines())
    return data

def output_data(data, output_format, headers):
    if output_format == 'csv':
        max_len = max(len(data[key]) for key in headers)
        with open('output.csv', 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            for i in range(max_len):
                row = [data[header][i] if i < len(data[header]) else '' for header in headers]
                writer.writerow(row)
        print(f"CSV output written to 'output.csv'")
    elif output_format == 'txt':
        with open('output.txt', 'w') as txtfile:
            for key in headers:
                txtfile.write(f"{key}:\n")
                for line in data[key]:
                    txtfile.write(f"{line}\n")
        print(f"TXT output written to 'output.txt'")
    else:  # default to Palo Alto dynamic list format
        combined_data = []
        for key in headers:
            combined_data.extend(data[key])
        with open('output.txt', 'w') as txtfile:
            txtfile.write(' '.join(combined_data))
        print(f"Palo Alto dynamic list format output written to 'output.txt'")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Process ASN, country, and RIR data")
    parser.add_argument('-asn', type=str, help="List of ASNs separated by semicolons")
    parser.add_argument('-country', type=str, help="List of countries separated by semicolons")
    parser.add_argument('-rir', type=str, help="List of RIRs separated by semicolons")
    parser.add_argument('-output', type=str, choices=['csv', 'txt'], help="Output format: 'csv' or 'txt'")

    args = parser.parse_args()
    output_format = args.output if args.output else 'paloalto'

    if not args.asn and not args.country and not args.rir:
        with open("README", 'r') as f:
            print(f.read())
        exit()

    data = {}
    headers = []
    processed_messages = []

    if args.rir:
        rir_list = [rlimit(r.strip().lower()) for r in args.rir.split(';')]
        rir_data = process_rir(rir_list)
        data.update(rir_data)
        headers.extend(rir_list)
        processed_messages.append(f"RIR data for {', '.join(rir_list).upper()} processed")

    if args.country:
        country_list = [climit(c.strip().upper()) for c in args.country.split(';')]
        country_data = process_country(country_list)
        data.update(country_data)
        headers.extend(country_list)
        processed_messages.append(f"Country data for {', '.join(country_list)} processed")

    if args.asn:
        asn_list = [aslimit(a.strip().upper()) for a in args.asn.split(';') if a.strip().isdigit()]
        asn_data = process_asn(asn_list)
        data.update(asn_data)
        headers.extend(asn_list)
        processed_messages.append(f"ASN data for {', '.join(asn_list)} processed")

    output_data(data, output_format, headers)

    if processed_messages:
        print(" and ".join(processed_messages))

