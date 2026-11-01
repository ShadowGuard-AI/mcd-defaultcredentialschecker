import argparse
import os
import re
import sys
import logging
import yaml
import json
from jsonpath_ng.ext import parse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default credentials dictionary
# These are the values I check when the operator hands me nothing
# of their own. They are a starter list from vendor manuals, not a
# claim about what any given device still ships with.
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
    except Exception as e:
        logging.error(f"Error loading custom credentials file: {filepath} - {e}")
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
    except Exception as e:
        logging.error(f"Error loading rules file: {filepath} - {e}")
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

        # I trust the shape of a custom credentials file here. If a value
        # in it is a plain string instead of a list, this loop walks it
        # one character at a time and checks single letters. Nothing
        # validates the file before this point.
        for credential_type, default_values in default_credentials.items():
            for value in default_values:
                # The word boundaries keep a short value from firing inside a
                # longer word, but they cannot tell context apart: the word
                # password in a comment or a sentence still matches the password
                # entry. I accept those false positives rather than guess at
                # which lines are real assignments.
                if re.search(r'\b' + re.escape(value) + r'\b', content, re.IGNORECASE):
                    logging.warning(f"Possible default {credential_type} found in {filepath}: {value}")
                    # Verbose adds a print on top of the warning that was just logged,
                    # so the finding lands in both streams. That duplication is the
                    # point: a piped log keeps one copy and the terminal shows one.
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
    # The extension list is wider than the parsers below can honour.
    # .tf counts as IaC here, but native Terraform is neither JSON nor
    # YAML, so those files fail parsing in the misconfiguration check
    # and only ever get the plain text credential scan.
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
            # I try JSON first because it is the stricter parse. YAML would
            # accept most JSON anyway, so this order is about getting the
            # clean failure that drops through to the YAML attempt.
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
                        # Only two conditions exist in my handling: exists and equals.
                        # Anything else a rules file spells is ignored in silence, no
                        # warning and no match, which makes a typo in a rule look exactly
                        # like a file that passed.
                        elif rule['condition'] == 'equals':
                            if match.value == rule['value']:
                                logging.warning(f"Misconfiguration detected in {filepath}: {rule['description']}")
                                if verbose:
                                    print(f"Misconfiguration detected in {filepath}: {rule['description']}")
            # A broken rule is logged and the rest still run. I would rather
            # report the rules that did work than lose the whole file's
            # results to one bad jsonpath expression.
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
            # The credential check runs on every file in the tree, whatever
            # its type. Only the misconfiguration check is gated by extension
            # below, so images and binaries get opened as text here and their
            # decode failures show up as processing errors in the log.
            check_file_for_default_credentials(filepath, default_credentials, verbose)

            if is_iac_file(file):
                check_file_for_misconfigurations(filepath, rules, verbose)


def main():
    """
    Main function to execute the default credentials checker.
    """
    args = setup_argparse()

    # Load custom credentials if provided. A file the operator named
    # that cannot be loaded is a failed run, not a reason to fall back
    # to the built in dictionary without saying the scan changed.
    default_creds = DEFAULT_CREDENTIALS
    if args.custom_credentials:
        custom_credentials = load_custom_credentials(args.custom_credentials)
        if custom_credentials is None:
            logging.error(f"Failed to load custom credentials file: {args.custom_credentials}. Exiting.")
            sys.exit(1)
        default_creds = custom_credentials

    # Load misconfiguration rules if provided. The same rule applies:
    # an unloadable rules file means the requested checks never ran.
    rules = []  # Initialize rules to an empty list
    if args.rules:
        loaded_rules = load_rules(args.rules)
        if loaded_rules is None:
            logging.error(f"Failed to load rules file: {args.rules}. Exiting.")
            sys.exit(1)
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
        sys.exit(1)


if __name__ == "__main__":
    main()