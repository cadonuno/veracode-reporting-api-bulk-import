# Veracode Bulk Reporting API Import

Retrieves all the data available from **findings** in the Veracode Reporting API for a specific range

## Setup

Clone this repository:

    git clone https://github.com/cadonuno/veracode-reporting-api-bulk-import

Install dependencies:

    cd veracode-reporting-api-bulk-import
    pip install -r requirements.txt

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

## Workflow

The reporting API returns all records modified during a time period, therefore, the implementation of this script is usually done in 2 steps:
- Run it once with a start date before your first scan.
  - Save this to an internal system.
  - Set the following fields as your Primary Key:
    - app_id
    - flaw_id (will be null for SCA findings)
    - cve_id (will be null for SAST findings)
    - component_id (will be null for SAST findings)
- Set up a recurring job to run this script every day/month/week, setting start date to the last time the script was run.
  - Save this on top of the previous results, overriding records if the Primary key matches.

## Run

If you have saved credentials as above you can run:

    python veracode-reporting-api-bulk-import.py (arguments)

Otherwise you will need to set environment variables:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python veracode-reporting-api-bulk-import.py (arguments)

Arguments supported include:

* `--start`, `-s`  Start date for the first report in the format 'YYYY-MM-DD'
* `--end`, `-e` (optional): End date for the report range in the format 'YYYY-MM-DD' (defaults to today)
* `--directory`, `-d` (optional): A directory to save the files to (defaults to current directory)
* `--application_data`, `-a` (optional): Set to true to import additional fields from the Application Profile (defaults to false) * these additional fields are: Policy, Business Unit, Teams (comma-delimited list), and all custom fields (one per column).
* `--fields`, `-f` (optional): Comma-delimited list of fields to include in the output files (defaults to all fields)