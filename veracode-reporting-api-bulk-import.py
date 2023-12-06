import time
import csv
import os
import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
from veracode_api_signing.credentials import get_credentials
import argparse
import datetime

json_data_template = {
    "scan_type": ["Static Analysis", "Dynamic Analysis", "Manual Analysis", "SCA"],
    "policy_sandbox": "Policy",
    "report_type": "findings",
    "last_updated_start_date": "",
    "last_updated_end_date": ""
}
max_poll_attempts=60
poll_interval_seconds=5
headers = {"User-Agent": "Veracode Report Script"}
api_base = "https://api.veracode.{intance}/appsec/v1"
auth = RequestsAuthPluginVeracodeHMAC() 

def update_api_base():
    global api_base
    api_key_id, api_key_secret = get_credentials()
    if api_key_id.startswith("vera01"):
        api_base = api_base.replace("{intance}", "eu", 1)
    else:
        api_base = api_base.replace("{intance}", "com", 1)


def request_report(json_data):
    global api_base
    global headers
    global auth
    report_request_endpoint = f"{api_base}/analytics/report"
    response = requests.post(report_request_endpoint, auth=auth, headers=headers, json=json_data)

    if response.ok:
        data = response.json()
        print("Report initiation successful. Report ID:", data['_embedded']['id'])
        return data['_embedded']['id']
    else:
        response.raise_for_status()

def get_report_data(report_id):
    global api_base
    global headers
    global auth
    report_status_endpoint = f"{api_base}/analytics/report/{report_id}"
    response = requests.get(report_status_endpoint, auth=auth, headers=headers)

    if response.ok:
        data = response.json()
        if data and data['_embedded']:
            return data
    return None

def save_report_to_csv(output_file, output_data):
    with open(output_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        flaws_list = output_data['_embedded']['findings']

        if flaws_list:
            csv_writer.writerow(flaws_list[0].keys())
            for entry in flaws_list:
                csv_writer.writerow(entry.values())
            print("Veracode report saved to", output_file)
        else:
            print("No flaws found in the Veracode report.")

def get_report_results(report_id, current_start_date, end_date, directory):
    for status_attempt in range(1, max_poll_attempts + 1):
        print(f"Checking Veracode report status for date range {current_start_date}-{end_date}. Attempt {status_attempt}/{max_poll_attempts}...")
        report_data = get_report_data(report_id)

        if report_data is None:
            print(f"Error generating report for date range {current_start_date}-{end_date}. Skipping it")
            return
        status = report_data['_embedded']['status']
        if status == "COMPLETED":
            print("Veracode report completed. Saving it to a file...")
            output_file = f'veracode_data_dump {current_start_date.strftime("%Y-%m-%d")} to {end_date.strftime("%Y-%m-%d")}.csv'
            save_report_to_csv(os.path.join(directory, output_file), report_data)
            break
        elif status == "PROCESSING":
            time.sleep(poll_interval_seconds)
        else:
            print(f"Unexpected report status: {status} found for date range {current_start_date}-{end_date}. Skipping it")
            return
    print (f"Report timed out after {max_poll_attempts*poll_interval_seconds} seconds for range {current_start_date}-{end_date}. Try it later with id: {report_id}")
            

def get_report_for_start_date(current_start_date, current_time, directory):
    global json_data_template    

    end_date = current_start_date + datetime.timedelta(days=180)
    if end_date > current_time:
        end_date = current_time

    json_data = json_data_template.copy()
    json_data["last_updated_start_date"] = current_start_date.strftime("%Y-%m-%d")
    json_data["last_updated_end_date"] = end_date.strftime("%Y-%m-%d")

    get_report_results(request_report(json_data), current_start_date, end_date, directory)
    return end_date

def get_all_reports(start_date, directory):
    current_start_date = datetime.datetime.strptime(start_date, "%Y-%m-%d").date()
    current_time = datetime.date.today()
    if current_start_date >= current_time:
        current_start_date = current_start_date - datetime.timedelta(days=4)

    while current_start_date < current_time:
        current_start_date = get_report_for_start_date(current_start_date, current_time, directory)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Veracode Bulk Reporting API Import")
    parser.add_argument("-s", "--start", required=True, help="Start date for the first report in the format 'YYYY-MM-DD'")
    parser.add_argument("-d", "--directory", required=False, help="A directory to save the files to (defaults to current directory)")
    return parser.parse_args()

def main():
    args = parse_arguments()
    start_date = args.start
    directory = args.directory
    if (not directory):
        directory = '.'    

    update_api_base()
    get_all_reports(start_date, directory)

if __name__ == "__main__":
    main()
