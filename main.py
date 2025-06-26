import argparse
import os
import re
import logging
import yaml
import json
from jsonpath_ng.ext import parse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default credentials dictionary
DEFAULT_CREDENTIALS = {
    "username": ["admin", "root", "user", "administrator"],
    "password": ["password", "admin", "root", "123456", "Password123!", "changeme"]
}

# Define patterns for infrastructure-as-code (IaC) template file extensions
IAC_FILE_EXTENSIONS = ['.tf', '.yml', '.yaml', '.json', '.template']  # Terraform, CloudFormation, etc.


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Checks configuration files for default credentials and misconfigurations.")
    parser.add_argument("path", help="Path to the file or directory to scan.")
    parser.add_argument("-c", "--custom-credentials", help="Path to a YAML file containing custom default credentials.", required=False)
    parser.add_argument("-r", "--rules", help="Path to a YAML file containing custom misconfiguration rules.", required=False)  # Added for misconfiguration detection
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    return parser.parse_args()


def load_custom_credentials(filepath):
    """
    Loads custom default credentials from a YAML file.

    Args:
        filepath (str): Path to the YAML file.

    Returns:
        dict: A dictionary containing the custom credentials, or None if an error occurs.
    """
    try:
        with open(filepath, 'r') as f:
            custom_credentials = yaml.safe_load(f)
        logging.info(f"Successfully loaded custom credentials from {filepath}")
        return custom_credentials
    except FileNotFoundError:
        logging.error(f"Custom credentials file not found: {filepath}")
        return None
    except yaml.YAMLError as e:
        logging.error(f"Error parsing custom credentials file: {filepath} - {e}")
        return None


def load_rules(filepath):
    """
    Loads misconfiguration rules from a YAML file.

    Args:
        filepath (str): Path to the YAML file.

    Returns:
        dict: A dictionary containing the misconfiguration rules, or None if an error occurs.
    """
    try:
        with open(filepath, 'r') as f:
            rules = yaml.safe_load(f)
        logging.info(f"Successfully loaded rules from {filepath}")
        return rules
    except FileNotFoundError:
        logging.error(f"Rules file not found: {filepath}")
        return None
    except yaml.YAMLError as e:
        logging.error(f"Error parsing rules file: {filepath} - {e}")
        return None


def check_file_for_default_credentials(filepath, default_credentials, verbose=False):
    """
    Checks a file for the presence of default credentials.

    Args:
        filepath (str): Path to the file to scan.
        default_credentials (dict): A dictionary of default credentials.
        verbose (bool): Enable verbose output.
    """
    try:
        with open(filepath, 'r') as f:
            content = f.read()

        for credential_type, default_values in default_credentials.items():
            for value in default_values:
                if re.search(r'\b' + re.escape(value) + r'\b', content, re.IGNORECASE):
                    logging.warning(f"Possible default {credential_type} found in {filepath}: {value}")
                    if verbose:
                        print(f"Possible default {credential_type} found in {filepath}: {value}")

    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
    except Exception as e:
        logging.error(f"Error processing file {filepath}: {e}")


def is_iac_file(filename):
    """
    Checks if a file is an infrastructure-as-code template based on its file extension.

    Args:
        filename (str): The name of the file.

    Returns:
        bool: True if the file is an IaC template, False otherwise.
    """
    _, ext = os.path.splitext(filename)
    return ext.lower() in IAC_FILE_EXTENSIONS


def check_file_for_misconfigurations(filepath, rules, verbose=False):
    """
    Checks a file for misconfigurations based on predefined rules.

    Args:
        filepath (str): Path to the file to scan.
        rules (dict): A dictionary of misconfiguration rules.
        verbose (bool): Enable verbose output.
    """
    try:
        with open(filepath, 'r') as f:
            file_content = f.read()

        # Attempt to parse the file content as JSON or YAML.
        try:
            data = json.loads(file_content)
        except json.JSONDecodeError:
            try:
                data = yaml.safe_load(file_content)
            except yaml.YAMLError:
                logging.warning(f"Could not parse {filepath} as JSON or YAML. Skipping misconfiguration checks.")
                return

        for rule in rules:
            try:
                jsonpath_expression = parse(rule['jsonpath'])
                matches = jsonpath_expression.find(data)

                if matches:
                    for match in matches:
                        if rule['condition'] == 'exists':
                            logging.warning(f"Misconfiguration detected in {filepath}: {rule['description']}")
                            if verbose:
                                print(f"Misconfiguration detected in {filepath}: {rule['description']}")
                        elif rule['condition'] == 'equals':
                            if match.value == rule['value']:
                                logging.warning(f"Misconfiguration detected in {filepath}: {rule['description']}")
                                if verbose:
                                    print(f"Misconfiguration detected in {filepath}: {rule['description']}")
            except Exception as e:
                logging.error(f"Error processing rule for {filepath}: {e}")

    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
    except Exception as e:
        logging.error(f"Error processing file {filepath}: {e}")


def scan_directory(path, default_credentials, rules, verbose=False):
    """
    Scans a directory for configuration files and checks them for default credentials and misconfigurations.

    Args:
        path (str): Path to the directory to scan.
        default_credentials (dict): A dictionary of default credentials.
        rules (dict): A dictionary of misconfiguration rules.
        verbose (bool): Enable verbose output.
    """
    for root, _, files in os.walk(path):
        for file in files:
            filepath = os.path.join(root, file)
            check_file_for_default_credentials(filepath, default_credentials, verbose)

            if is_iac_file(file):
                check_file_for_misconfigurations(filepath, rules, verbose)


def main():
    """
    Main function to execute the default credentials checker.
    """
    args = setup_argparse()

    # Load custom credentials if provided
    default_creds = DEFAULT_CREDENTIALS
    if args.custom_credentials:
        custom_credentials = load_custom_credentials(args.custom_credentials)
        if custom_credentials:
            default_creds = custom_credentials  # Override default credentials if custom ones are loaded

    # Load misconfiguration rules if provided
    rules = []  # Initialize rules to an empty list
    if args.rules:
        loaded_rules = load_rules(args.rules)
        if loaded_rules:
            rules = loaded_rules

    # Determine if the path is a file or directory
    if os.path.isfile(args.path):
        check_file_for_default_credentials(args.path, default_creds, args.verbose)
        if is_iac_file(args.path):
            check_file_for_misconfigurations(args.path, rules, args.verbose)
    elif os.path.isdir(args.path):
        scan_directory(args.path, default_creds, rules, args.verbose)
    else:
        logging.error(f"Invalid path: {args.path}")


if __name__ == "__main__":
    main()