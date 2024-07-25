from flask import Flask, request, jsonify, Response
import os
import csv
import io
from query_data import process_rir, process_country, process_asn, output_data

app = Flask(__name__)

@app.route('/')
def home():
    return "Welcome to the Data Processing API!"

@app.route('/data')
def data():
    asn = request.args.get('asn')
    country = request.args.get('country')
    rir = request.args.get('rir')
    output_format = request.args.get('output', 'paloalto')

    data = {}
    headers = []
    processed_messages = []

    if rir:
        rir_list = [rir.strip().lower() for rir in rir.split(';')]
        rir_data = process_rir(rir_list)
        data.update(rir_data)
        headers.extend(rir_list)
        processed_messages.append(f"RIR data for {', '.join(rir_list).upper()} processed")

    if country:
        country_list = [country.strip().upper() for country in country.split(';')]
        country_data = process_country(country_list)
        data.update(country_data)
        headers.extend(country_list)
        processed_messages.append(f"Country data for {', '.join(country_list)} processed")

    if asn:
        asn_list = [asn.strip() for asn in asn.split(';') if asn.strip().isdigit()]
        asn_data = process_asn(asn_list)
        data.update(asn_data)
        headers.extend(asn_list)
        processed_messages.append(f"ASN data for {', '.join(asn_list)} processed")

    if output_format == 'csv':
        output = io.StringIO()
        max_len = max(len(data[key]) for key in headers)
        writer = csv.writer(output)
        writer.writerow(headers)
        for i in range(max_len):
            row = [data[header][i] if i < len(data[header]) else '' for header in headers]
            writer.writerow(row)
        return Response(output.getvalue(), mimetype='text/csv')
    elif output_format == 'txt':
        output = io.StringIO()
        for key in headers:
            output.write(f"{key}:\n")
            for line in data[key]:
                output.write(f"{line}\n")
        return Response(output.getvalue(), mimetype='text/plain')
    else:  # default to Palo Alto dynamic list format
        combined_data = []
        for key in headers:
            combined_data.extend(data[key])
        return Response(' '.join(combined_data), mimetype='text/plain')

@app.route('/status')
def status():
    return jsonify({"status": "Running"})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)

