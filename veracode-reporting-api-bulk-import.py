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

max_poll_attempts=100
poll_interval_seconds=15
headers = {"User-Agent": "Veracode Reporting API Bulk Script"}
api_base = "https://api.veracode.{intance}"
auth = RequestsAuthPluginVeracodeHMAC()

application_dict = {}
application_custom_fields = set()

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
    report_request_endpoint = f"{api_base}/appsec/v1/analytics/report"
    response = requests.post(report_request_endpoint, auth=auth, headers=headers, json=json_data)

    if response.ok:
        data = response.json()
        print("Report initialization successful. Report ID:", data['_embedded']['id'])
        return data['_embedded']['id']
    else:
        response.raise_for_status()

def get_report_data(report_id, page):
    global api_base
    global headers
    global auth
    report_status_endpoint = f"{api_base}/appsec/v1/analytics/report/{report_id}?page={page}"
    response = requests.get(report_status_endpoint, auth=auth, headers=headers)

    if response.ok:
        data = response.json()
        if data and data['_embedded']:
            return data
    return None

def save_report_to_csv(output_file, flaw_list):
    with open(output_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)

        if flaw_list:
            csv_writer.writerow(flaw_list[0].keys())
            for entry in flaw_list:
                csv_writer.writerow(entry.values())
            print("Veracode report saved to", output_file)
        else:
            print("No flaws found in the Veracode report.")

def parse_custom_fields(custom_fields):
    global application_custom_fields
    if not custom_fields:
        return {}
    parsed_custom_fields = {}
    for custom_field in custom_fields:
        application_custom_fields.add(custom_field["name"])
        parsed_custom_fields[custom_field["name"]] = custom_field["value"]

    return parsed_custom_fields

def parse_teams(teams_json):
    teams_string = ""
    for team_json in teams_json:
        if teams_string:
            teams_string = teams_string + ", "
        teams_string = teams_string + team_json["team_name"]
    return teams_string

def parse_business_unit(business_unit_json):
    bu_name = business_unit_json["name"]
    if bu_name and bu_name != "Not Specified":
        return bu_name
    return ""

def parse_application(application_json):
    application = {}
    profile = application_json["profile"]
    application['Teams'] = parse_teams(profile["teams"])
    application['Business Unit'] = parse_business_unit(profile["business_unit"])

    business_owners = profile["business_owners"]
    if business_owners:
        if business_owners[0]:
            owner = business_owners[0]
            application['Business Owner'] = owner["name"] if "name" in owner else ""
            application['Owner email'] = owner["email"] if "email" in owner else ""
    else:
        application['Business Owner'] = ""
        application['Owner email'] = ""

    policies = profile["policies"]
    if policies:
        application['Policy'] = policies[0]["name"]
    else:
        application['Policy'] = ""

    application["custom_fields"] =  parse_custom_fields(profile['custom_fields'])
    return application    

def get_application(app_id):
    global api_base
    global headers
    global auth
    global application_dict

    if app_id in application_dict:
        return application_dict[app_id]
    
    report_request_endpoint = f"{api_base}/appsec/v1/applications?legacy_id={app_id}"
    response = requests.get(report_request_endpoint, auth=auth, headers=headers)

    if response.ok:
        data = response.json()
        if "_embedded" in data:
            embedded = data["_embedded"]
            if "applications" in embedded:
                applications = embedded["applications"]
                if applications:
                    application = parse_application(applications[0])
                    application_dict[app_id] = application
                    return application
        application_dict[app_id] = None
        print("Unable to find application for ID:", app_id)
    else:
        response.raise_for_status()

def add_custom_fields(flaw, custom_fields):
    global application_custom_fields
    for custom_field in application_custom_fields:
        flaw[custom_field] = ""

    if custom_fields:
        for name in custom_fields.keys():
            flaw[name] = custom_fields[name]

def parse_flaw_list(flaw_list, is_application_data):
    global application_custom_fields
    if not is_application_data:
        return flaw_list
    
    for flaw in flaw_list:
        flaw["Application"] = get_application(flaw['app_id'])

    for flaw in flaw_list:
        application = flaw["Application"]
        flaw['Teams'] = application['Teams']
        flaw['Business Unit'] = application['Business Unit']
        flaw['Business Owner'] = application['Business Owner']
        flaw['Owner email'] = application['Owner email']
        flaw['Policy'] = application['Policy']
        add_custom_fields(flaw, application['custom_fields'])
        del flaw["Application"]

    return flaw_list

def get_findings_for_all_pages(report_id, embedded_node):
    findings = embedded_node["findings"]
    if not "page_metadata" in embedded_node:
        return findings
    page_metadata = embedded_node["page_metadata"]
    current_page = page_metadata["number"]
    max_page = page_metadata["total_pages"]
    if max_page <= 1:
        return findings
    
    print(f"Parsing additional pages for report {report_id}")
    current_page = current_page + 1

    while current_page < max_page:
        print(f"Parsing page {current_page}/{max_page}")
        next_page = get_report_data(report_id, current_page)
        if next_page and "_embedded" in next_page and "findings" in next_page["_embedded"]:
            findings = findings + next_page["_embedded"]["findings"]
        current_page = current_page + 1

    return findings


def get_report_results(report_id, current_start_date, end_date, directory, is_application_data):
    for status_attempt in range(1, max_poll_attempts + 1):
        print(f"Checking Veracode report status for date range {current_start_date}-{end_date}. Attempt {status_attempt}/{max_poll_attempts}...")
        report_data = get_report_data(report_id, 0)

        if report_data is None:
            print(f"ERROR: empty report for date range {current_start_date}-{end_date}. Skipping it")
            return
        status = report_data['_embedded']['status']
        if status == "COMPLETED":
            print("SUCCESS: report fetched successfully. Saving it to a file...")
            output_file = f'veracode_data_dump {current_start_date.strftime("%Y-%m-%d")} to {end_date.strftime("%Y-%m-%d")}.csv'
            save_report_to_csv(os.path.join(directory, output_file), parse_flaw_list(get_findings_for_all_pages(report_id, report_data['_embedded']), is_application_data))
            return
        elif status == "PROCESSING":
            time.sleep(poll_interval_seconds)
        else:
            print(f"ERROR: unexpected report status {status} found for date range {current_start_date}-{end_date}. Skipping it")
            return
    print (f"Report timed out after {max_poll_attempts*poll_interval_seconds} seconds for range {current_start_date}-{end_date}. Try it later with id: {report_id}")
            

def get_report_for_start_date(current_start_date, current_time, directory, is_application_data):
    global json_data_template    

    end_date = current_start_date + datetime.timedelta(days=180)
    if end_date > current_time:
        end_date = current_time

    json_data = json_data_template.copy()
    json_data["last_updated_start_date"] = current_start_date.strftime("%Y-%m-%d")
    json_data["last_updated_end_date"] = end_date.strftime("%Y-%m-%d")

    get_report_results(request_report(json_data), current_start_date, end_date, directory, is_application_data)
    return end_date

def get_all_reports(start_date, directory, is_application_data):
    current_start_date = datetime.datetime.strptime(start_date, "%Y-%m-%d").date()
    current_time = datetime.date.today()
    if current_start_date >= current_time:
        current_start_date = current_start_date - datetime.timedelta(days=4)

    while current_start_date < current_time:
        current_start_date = get_report_for_start_date(current_start_date, current_time, directory, is_application_data)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Veracode Bulk Reporting API Import")
    parser.add_argument("-s", "--start", required=True, help="Start date for the first report in the format 'YYYY-MM-DD'")
    parser.add_argument("-d", "--directory", required=False, help="A directory to save the files to (defaults to current directory)")
    parser.add_argument("-a", "--application_data", required=False, help="Set to TRUE to read additional fields from the application profile")
    return parser.parse_args()

def main():
    args = parse_arguments()
    start_date = args.start
    directory = args.directory
    is_application_data = args.application_data
    if (not directory):
        directory = '.'    

    update_api_base()
    get_all_reports(start_date, directory, is_application_data)

if __name__ == "__main__":
    main()
