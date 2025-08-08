import time
import csv
import os
import requests
import sys
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
from veracode_api_signing.credentials import get_credentials
import argparse
import datetime
from colored import Fore, Style

RESET_STYLE = Style.reset
WARNING_COLOUR=Fore.rgb(212, 105, 32)
WARNING_MESSAGE_COLOUR=Fore.rgb(255, 127, 39)
ERROR_PREFIX_COLOUR = Fore.rgb(136, 0, 21)
INFO_PREFIX_COLOUR = Fore.rgb(112, 146, 190)
INFO_SUFFIX_COLOUR = Fore.rgb(153, 217, 234)
SUCCESS_PREFIX_COLOUR = Fore.rgb(30, 215, 96)

max_poll_attempts=100
poll_interval_seconds=15
retry_wait_seconds=1
retry_max_attempts=10
headers = {"User-Agent": "Veracode Reporting API Bulk Script"}
api_base = "https://api.veracode.{intance}"
auth = RequestsAuthPluginVeracodeHMAC()

application_dict = {}
application_custom_fields = set()

def update_api_base():
    global api_base
    api_key_id, _ = get_credentials()
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

    if response and response.ok:
        data = response.json()
        print(f'{INFO_PREFIX_COLOUR}Report initialization successful.{RESET_STYLE} Report ID: {INFO_SUFFIX_COLOUR}{data["_embedded"]["id"]}{RESET_STYLE} ')
        return data['_embedded']['id']
    else:
        print(f"{ERROR_PREFIX_COLOUR}ERROR:{RESET_STYLE} unable to create report {response.status_code}")
        if response and response.json():
            print(f"{WARNING_COLOUR}-- {response.json()}{RESET_STYLE}")
        print()
        return None

def get_report_data(report_id, page):
    global api_base
    global headers
    global auth
    report_status_endpoint = f"{api_base}/appsec/v1/analytics/report/{report_id}{f"?page={page}" if page else ""}"
    response = requests.get(report_status_endpoint, auth=auth, headers=headers)

    if response.ok:
        data = response.json()
        if data and data['_embedded']:
            return data
    else:
        print(f"{ERROR_PREFIX_COLOUR}ERROR:{RESET_STYLE} unable to fetch report for id {report_id} and page {page}")
        if response.json():
            print(f"{WARNING_COLOUR}-- {response.json()}{RESET_STYLE}")
        response.raise_for_status()
        return None

def save_report_to_csv(output_file, flaw_list, fields_to_include):
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        csv_writer = csv.writer(csvfile)

        if flaw_list:
            if fields_to_include:
                csv_writer.writerow(fields_to_include)
                for entry in flaw_list:
                    csv_writer.writerow(map(lambda field_to_include: entry[field_to_include] if field_to_include in entry else "INVALID FIELD NAME", fields_to_include))
            else:
                csv_writer.writerow(flaw_list[0].keys())
                for entry in flaw_list:
                    csv_writer.writerow(entry.values())
            print(f"{INFO_PREFIX_COLOUR}Veracode report saved to: {RESET_STYLE}{INFO_SUFFIX_COLOUR}{output_file}{RESET_STYLE}")
            print()
        else:
            print(f"{WARNING_COLOUR}No flaws found in the Veracode report.{RESET_STYLE}")
            print()

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
    application['Tags'] = profile["tags"]

    return application    

def get_application(app_id, attempt=0):
    global api_base
    global headers
    global auth
    global application_dict
    global retry_max_attempts
    global retry_wait_seconds

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
        print(f"{WARNING_COLOUR}Unable to find application for ID: {RESET_STYLE}{app_id}")
    else:
        print(f"{ERROR_PREFIX_COLOUR}ERROR:{RESET_STYLE} unable to get application information for app {app_id}")
        if response.json():
            print(f"{WARNING_COLOUR}-- {response.json()}{RESET_STYLE}")
        if attempt < retry_max_attempts:
            time.sleep(retry_wait_seconds*(attempt+1))
            return get_application(app_id, attempt+1)
        response.raise_for_status()

def add_custom_fields(flaw, custom_fields):
    global application_custom_fields
    for custom_field in application_custom_fields:
        flaw[custom_field] = ""

    if custom_fields:
        for name in custom_fields.keys():
            flaw[name] = custom_fields[name]

def parse_flaw_list(flaw_list, is_application_data, include_tags):
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
        if include_tags:
            flaw['Tags'] = application['Tags']
        add_custom_fields(flaw, application['custom_fields'])
        del flaw["Application"]

    return flaw_list

def get_findings_for_all_pages(report_id, embedded_node, list_node_name):
    findings = embedded_node[list_node_name]
    if not "page_metadata" in embedded_node:
        return findings
    page_metadata = embedded_node["page_metadata"]
    current_page = page_metadata["number"]
    max_page = page_metadata["total_pages"]
    if max_page <= 1:
        return findings
    
    print(f"{INFO_PREFIX_COLOUR}Parsing additional pages for report:{RESET_STYLE} {report_id}")
    current_page = current_page + 1

    while current_page < max_page:
        print(f"{INFO_PREFIX_COLOUR}Parsing page:{RESET_STYLE} {current_page}/{max_page}")
        next_page = get_report_data(report_id, current_page)
        if next_page and "_embedded" in next_page and list_node_name in next_page["_embedded"]:
            findings = findings + next_page["_embedded"][list_node_name]
        current_page = current_page + 1

    return findings

def get_report_results(base_name, report_id, current_start_date, end_date, directory, is_application_data, fields_to_include, list_node_name, include_tags):
    if not report_id:
        return
    
    for status_attempt in range(1, max_poll_attempts + 1):
        print(f"{INFO_PREFIX_COLOUR}Checking Veracode report status for date range{RESET_STYLE}: {current_start_date}-{end_date if end_date else "today"}. {WARNING_COLOUR}Attempt {status_attempt}/{max_poll_attempts}...{RESET_STYLE}")
        report_data = get_report_data(report_id, 0)

        if report_data is None:
            print(f"{ERROR_PREFIX_COLOUR}ERROR:{RESET_STYLE} empty report for date range {current_start_date}-{end_date}. Skipping it")
            return
        status = report_data['_embedded']['status']
        if status == "COMPLETED":
            print(f"{SUCCESS_PREFIX_COLOUR}SUCCESS:{RESET_STYLE} report fetched successfully.")
            if report_data['_embedded']['page_metadata']['total_elements'] == 0:
                print(f"{INFO_PREFIX_COLOUR} - No data found for range:{RESET_STYLE} {current_start_date}-{end_date if end_date else "today"} - Skipping")
                return
            output_file = f'{base_name} {current_start_date.strftime("%Y-%m-%d")} to {end_date.strftime("%Y-%m-%d") if end_date else datetime.date.today().strftime("%Y-%m-%d")}.csv'
            save_report_to_csv(os.path.join(directory, output_file), parse_flaw_list(get_findings_for_all_pages(report_id, report_data['_embedded'], list_node_name), is_application_data, include_tags), fields_to_include)
            return
        elif status == "PROCESSING" or status == "SUBMITTED":
            time.sleep(poll_interval_seconds)
        else:
            print(f"{ERROR_PREFIX_COLOUR}ERROR:{RESET_STYLE} unexpected report status {status} found for date range {current_start_date}-{end_date}. Skipping it")
            return
    print(f"{WARNING_COLOUR}Report timed out after {max_poll_attempts*poll_interval_seconds} seconds for range {current_start_date}-{end_date}.{RESET_STYLE} Try it later with id: {report_id}")

def get_report_for_start_date(base_name, current_start_date, end_date, directory, is_application_data, report_type, scan_types, fields_to_include, is_ending_on_today, include_tags):
    end_date_for_period = current_start_date + datetime.timedelta(days=180)
    if end_date_for_period >= end_date:
        if is_ending_on_today:
            end_date_for_period = None
        else:
            end_date_for_period = end_date

    is_findings_report = not report_type or report_type.strip().lower() == "findings"

    json_data = {"policy_sandbox": "Policy"}
    report_start_date = current_start_date.strftime("%Y-%m-%d")
    report_end_date = (f'{end_date_for_period.strftime("%Y-%m-%d")} 23:59:59') if end_date_for_period else None
    is_audit_report = False
    if report_type and report_type.strip().lower() == "audit":
        json_data = {}
        is_audit_report = True
        json_data["start_date"] = report_start_date
        list_node_name = "audit_logs"
        if report_end_date:
            json_data["end_date"] = report_end_date
    elif report_type and report_type.strip().lower() == "deletedscans":
        json_data["deletion_start_date"] = report_start_date
        if report_end_date:
            json_data["deletion_end_date"] = report_end_date
    else:
        json_data["last_updated_start_date"] = report_start_date
        if report_end_date:
            json_data["last_updated_end_date"] = report_end_date

    json_data["report_type"] = report_type    
    if is_findings_report:
        json_data["scan_type"] = ["Static Analysis", "Dynamic Analysis", "Manual Analysis", "SCA"]
        list_node_name = "findings"
    elif not is_audit_report:
        json_data["scan_type"] = ["Static Analysis", "Dynamic Analysis"]
        list_node_name = "scans" if report_type.strip().lower() == "scans" else "deleted_scans"
    if scan_types and not is_audit_report:
        json_data["scan_type"] = scan_types

    get_report_results(base_name, request_report(json_data), current_start_date, end_date_for_period, directory, is_application_data, fields_to_include, list_node_name, include_tags)
    return end_date_for_period

def get_all_reports(base_name, start_date, end_date, directory, is_application_data, report_type, scan_types, fields_to_include, include_tags):
    passed_scan_types = scan_types

    supported_scan_types = ["Static Analysis", "Dynamic Analysis", "Manual Analysis", "SCA"] if report_type == "findings" else ["Static Analysis", "Dynamic Analysis"]
    if scan_types:        
        has_error = False
        for scan_type in scan_types:
            if not scan_type in supported_scan_types:
                print(f"{ERROR_PREFIX_COLOUR}Scan Type {scan_type} is invalid.{RESET_STYLE} {report_type} reports only support these scan types: {str(supported_scan_types)}")
                has_error = True
        if has_error:
            sys.exit(-1)
    else:
        scan_types = supported_scan_types

    current_start_date = datetime.datetime.strptime(start_date, "%Y-%m-%d").date()
    if not end_date:
        end_date = datetime.date.today()
        is_ending_on_today = True
    else:
        end_date = datetime.datetime.strptime(end_date, "%Y-%m-%d").date()
        is_ending_on_today = False
    if current_start_date >= end_date:
        current_start_date = current_start_date - datetime.timedelta(days=4)

    print(f"{INFO_PREFIX_COLOUR}Running with parameters:{RESET_STYLE}")
    print(f"    Base Name: {base_name if base_name else "veracode_data_dump (default)"}")
    print(f"    Start Date: {current_start_date}")
    print(f"    End Date: {end_date if end_date else "TODAY (default)"}")
    print(f"    Taget Directory: {directory if directory else ".// (default)"}")
    print(f"    Application Data: {str(is_application_data) if is_application_data else "FALSE (default)"}")
    print(f"    Report Type: {report_type if report_type else "Findings (default)"}")
    print(f"    Scan Types: {str(passed_scan_types) if passed_scan_types else "ALL (default)"}")
    print(f"    Fields to Include: {str(fields_to_include) if fields_to_include else "ALL (default)"}")
    print(f"    Include Tags: {str(include_tags) if include_tags else "FALSE (default)"}")
    print()

    if not directory:
        directory = './/'
    if not base_name:
        base_name = "veracode_data_dump"

    while current_start_date and current_start_date < end_date:
        current_start_date = get_report_for_start_date(base_name, current_start_date, end_date, directory, is_application_data, report_type, scan_types, fields_to_include, is_ending_on_today, include_tags)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Veracode Bulk Reporting API Import")
    parser.add_argument("-s", "--start", required=True, help="Start date for the first report in the format 'YYYY-MM-DD'")
    parser.add_argument("-e", "--end", required=False, help="(optional) End date for the report range in the format 'YYYY-MM-DD' (defaults to today)")
    parser.add_argument("-d", "--directory", required=False, help="(optional) A directory to save the files to (defaults to current directory)")
    parser.add_argument("-a", "--application_data", required=False, help="(optional): Set to true to import additional fields from the Application Profile (defaults to false) * these additional fields are: Policy, Business Unit, Teams (comma-delimited list), and all custom fields (one per column).")
    parser.add_argument("-f", "--fields", required=False, help="(optional) Comma-delimited list of fields to include in the output files (defaults to all fields)")
    parser.add_argument("-rt", "--report_type", required=False, help="(optional) Report Type to fetch (default: findings)")
    parser.add_argument("-bn", "--base_name", required=False, help="(optional) Base csv file name (default: veracode_data_dump)")
    parser.add_argument("-st", "--scan_type", required=False, action="append", help="(optional) Scan types to fetch, takes 0 or more. (if empty, defaults to all scan types available for report type)")
    parser.add_argument("-it", "--include_tags", required=False, help="(optional) Set to TRUE to include Application Profile Tags (requires application_data)")
    return parser.parse_args()

def main():
    args = parse_arguments()
    base_name = args.base_name
    start_date = args.start
    directory = args.directory
    is_application_data = args.application_data
    end_date = args.end
    fields_to_include = args.fields
    report_type = args.report_type
    scan_types = args.scan_type
    include_tags = args.include_tags
    if not report_type:
        report_type = "findings"
    else:
        report_type = report_type.strip().lower()
        supported_report_types = ["findings", "scans", "deletedscans", "audit"]
        if not report_type in supported_report_types:
            print(f"{ERROR_PREFIX_COLOUR}Report Type {report_type} is invalid, supported types are:{RESET_STYLE} {str(supported_report_types)}")
            sys.exit(-1)

    update_api_base()
    get_all_reports(base_name, start_date, end_date, directory, is_application_data, report_type, scan_types, list(map(lambda field: field.strip(), fields_to_include.split(","))) if fields_to_include else None, include_tags)

if __name__ == "__main__":
    main()
