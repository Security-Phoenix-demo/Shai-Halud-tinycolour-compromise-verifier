import requests
from requests.auth import HTTPBasicAuth
import json
import os
import time
import difflib
import configparser
from pathlib import Path

def load_configuration():
    """
    Load configuration from environment variables or config file.
    Priority: Environment variables > config.ini file > defaults
    
    :return: Dictionary containing configuration values and batch information
    """
    config = {}
    
    # Try to load from environment variables first
    config['CLIENT_ID'] = os.getenv('PHOENIX_CLIENT_ID')
    config['CLIENT_SECRET'] = os.getenv('PHOENIX_CLIENT_SECRET')
    config['API_BASE_URL'] = os.getenv('PHOENIX_API_BASE_URL')
    
    # Load batch configurations
    config['batches'] = []
    
    # If any config is missing, try to load from config file
    config_file_path = Path(__file__).parent / 'config.ini'
    if config_file_path.exists():
        parser = configparser.ConfigParser()
        parser.read(config_file_path)
        
        if 'phoenix' in parser:
            phoenix_section = parser['phoenix']
            if not config['CLIENT_ID']:
                config['CLIENT_ID'] = phoenix_section.get('client_id')
            if not config['CLIENT_SECRET']:
                config['CLIENT_SECRET'] = phoenix_section.get('client_secret')
            if not config['API_BASE_URL']:
                config['API_BASE_URL'] = phoenix_section.get('api_base_url')
            
            # Load batch configuration from phoenix section if present
            if phoenix_section.get('FILE_PATH'):
                batch = {
                    'FILE_PATH': phoenix_section.get('FILE_PATH', '').strip("'\""),
                    'SCAN_TYPE': phoenix_section.get('SCAN_TYPE', '').strip("'\""),
                    'ASSESSMENT_NAME': phoenix_section.get('ASSESSMENT_NAME', '').strip("'\""),
                    'IMPORT_TYPE': phoenix_section.get('IMPORT_TYPE', 'new').strip("'\""),
                    'SCAN_TARGET': phoenix_section.get('SCAN_TARGET', '').strip("'\""),
                    'AUTO_IMPORT': phoenix_section.getboolean('AUTO_IMPORT', True),
                    'WAIT_FOR_COMPLETION': phoenix_section.getboolean('WAIT_FOR_COMPLETION', True)
                }
                config['batches'].append(batch)
            
            # Load global batch delay setting
            config['BATCH_DELAY'] = phoenix_section.getint('BATCH_DELAY', 10)  # Default 10 seconds
        
        # Look for additional batch sections (batch1, batch2, etc.)
        batch_sections = [section for section in parser.sections() if section.lower().startswith('batch')]
        for section_name in batch_sections:
            section = parser[section_name]
            batch = {
                'FILE_PATH': section.get('FILE_PATH', '').strip("'\""),
                'SCAN_TYPE': section.get('SCAN_TYPE', '').strip("'\""),
                'ASSESSMENT_NAME': section.get('ASSESSMENT_NAME', '').strip("'\""),
                'IMPORT_TYPE': section.get('IMPORT_TYPE', 'new').strip("'\""),
                'SCAN_TARGET': section.get('SCAN_TARGET', '').strip("'\""),
                'AUTO_IMPORT': section.getboolean('AUTO_IMPORT', True),
                'WAIT_FOR_COMPLETION': section.getboolean('WAIT_FOR_COMPLETION', True)
            }
            config['batches'].append(batch)
    
    # Check for required configuration
    missing_configs = []
    if not config['CLIENT_ID']:
        missing_configs.append('CLIENT_ID')
    if not config['CLIENT_SECRET']:
        missing_configs.append('CLIENT_SECRET')
    if not config['API_BASE_URL']:
        missing_configs.append('API_BASE_URL')
    
    if missing_configs:
        raise ValueError(f"Missing required configuration: {', '.join(missing_configs)}.\n"
                        f"Please set environment variables: PHOENIX_CLIENT_ID, PHOENIX_CLIENT_SECRET, PHOENIX_API_BASE_URL\n"
                        f"Or create a config.ini file with [phoenix] section containing: client_id, client_secret, api_base_url")
    
    return config

# Load configuration
try:
    config = load_configuration()
    CLIENT_ID = config['CLIENT_ID']
    CLIENT_SECRET = config['CLIENT_SECRET']
    API_BASE_URL = config['API_BASE_URL']
    BATCHES = config['batches']
    BATCH_DELAY = config.get('BATCH_DELAY', 10)  # Default 10 seconds
    print(f"Configuration loaded successfully. Using API base URL: {API_BASE_URL}")
    print(f"Found {len(BATCHES)} batch(es) to process")
    print(f"Batch delay configured: {BATCH_DELAY} seconds between batches")
except ValueError as e:
    print(f"Configuration error: {e}")
    exit(1)

# Scanner types file path
SCANNER_TYPES_FILE = 'Utils/mimecast/Scanner_Selection.txt'

def load_scanner_types(file_path=SCANNER_TYPES_FILE):
    """
    Load valid scanner types from the specified file.
    
    :param file_path: Path to the file containing valid scanner types
    :return: List of valid scanner types
    """
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Warning: Scanner types file '{file_path}' not found.")
        return []

def find_closest_scanner_type(scanner_type, valid_scanner_types):
    """
    Find the closest matching scanner type from the list of valid types.
    
    :param scanner_type: The scanner type to validate
    :param valid_scanner_types: List of valid scanner types
    :return: The closest matching scanner type or None if no close match
    """
    if not valid_scanner_types:
        return None
    
    matches = difflib.get_close_matches(scanner_type, valid_scanner_types, n=1, cutoff=0.6)
    return matches[0] if matches else None

def validate_scanner_type(scanner_type):
    """
    Validate if the provided scanner type is in the list of valid types.
    If not, suggest the closest match.
    
    :param scanner_type: The scanner type to validate
    :return: The validated scanner type (either the original or the closest match)
    """
    valid_scanner_types = load_scanner_types()
    
    if scanner_type in valid_scanner_types:
        return scanner_type
    
    closest_match = find_closest_scanner_type(scanner_type, valid_scanner_types)
    if closest_match:
        print(f"Warning: '{scanner_type}' is not a valid scanner type.")
        print(f"Did you mean '{closest_match}'?")
        return closest_match
    else:
        print(f"Warning: '{scanner_type}' is not a valid scanner type.")
        print("Using the provided scanner type anyway.")
        return scanner_type

def get_access_token(client_id, client_secret):
    # The line `url = "https://api.https://demo2.appsecphx.io//v1/auth/access_token"` is defining the URL
    # endpoint for obtaining an access token. This URL is used in the `get_access_token` function to make
    # a GET request with HTTP basic authentication using the provided client ID and client secret. The
    # response from this URL is expected to contain the access token needed for authentication in
    # subsequent API requests.
    url = f"{API_BASE_URL}/v1/auth/access_token"

    response = requests.get(url, auth=HTTPBasicAuth(client_id, client_secret))
    if response.status_code == 200:
        return response.json()['token']
    else:
        print(response.status_code)
        print("Failed to obtain token:", response.text)
    return None

def check_import_status(request_id, client_id, client_secret):
    """
    Check the status of an import request.
    
    :param request_id: The UUID identifying the import request
    :param client_id: Client ID for authentication
    :param client_secret: Client secret for authentication
    :return: The status response from the API
    """
    token = get_access_token(client_id, client_secret)
    if token is None:
        return None
    
    url = f"{API_BASE_URL}/v1/import/assets/file/translate/request/{request_id}"
    
    headers = {
        'Authorization': f'Bearer {token}'
    }
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Status Code: {response.status_code}")
        print(f"Failed to check import status: {response.text}")
        return None

def wait_for_import_completion(request_id, client_id, client_secret, check_interval=10, timeout=3600):
    """
    Continuously check the status of an import until it completes or times out.
    
    :param request_id: The UUID identifying the import request
    :param client_id: Client ID for authentication
    :param client_secret: Client secret for authentication
    :param check_interval: Time in seconds between status checks (default: 10)
    :param timeout: Maximum time in seconds to wait for completion (default: 3600 = 1 hour)
    :return: The final status response from the API
    """
    start_time = time.time()
    
    while True:
        status_response = check_import_status(request_id, client_id, client_secret)
        
        if status_response is None:
            print("Failed to get status response")
            return None
        
        current_status = status_response.get('status')
        print(f"Current import status: {current_status}")
        
        if current_status == "IMPORTED":
            print("Import completed successfully!")
            return status_response
        elif current_status == "ERROR":
            print(f"Import failed with error: {status_response.get('error', 'Unknown error')}")
            return status_response
        elif current_status in ["TRANSLATING", "READY_FOR_IMPORT"]:
            # Check if we've exceeded the timeout
            if time.time() - start_time > timeout:
                print(f"Import timed out after {timeout} seconds")
                return status_response
            
            # Wait before checking again
            print(f"Waiting {check_interval} seconds before checking again...")
            time.sleep(check_interval)
        else:
            print(f"Unknown status: {current_status}")
            return status_response

def send_results(file_path, scan_type, assessment_name, import_type, client_id, client_secret, scan_target=None, auto_import=True, wait_for_completion=True):
    """
    Send scan results to the API and optionally wait for the import to complete.
    
    :param file_path: Path to the file to be imported
    :param scan_type: Type of scan (e.g., "SonarQube Scan")
    :param assessment_name: Name of the assessment
    :param import_type: Type of import ("new" or "merge")
    :param client_id: Client ID for authentication
    :param client_secret: Client secret for authentication
    :param scan_target: Target of the scan (optional)
    :param auto_import: Whether to automatically import after processing (default: True)
    :param wait_for_completion: Whether to wait for the import to complete (default: True)
    :return: The import request ID and final status response if wait_for_completion is True
    """
    # Validate scanner type
    scan_type = validate_scanner_type(scan_type)
    
    token = get_access_token(client_id, client_secret)
    if token is None:
        return None, None
    
    url = f"{API_BASE_URL}/v1/import/assets/file/translate"

    headers = {
        'Authorization': f'Bearer {token}'
    }
    files = {
        'file': (file_path, open(file_path, 'rb'), 'application/octet-stream')
    }
    data = {
        'scanType': scan_type,
        'assessmentName': assessment_name,
        'importType': import_type,
        'scanTarget': scan_target if scan_target else '',
        'autoImport': 'true' if auto_import else 'false'
    }
    
    response = requests.post(url, headers=headers, files=files, data=data)
    files['file'][1].close() # Make sure to close the file
    
    print("Status Code:", response.status_code)
    
    if response.status_code != 200:
        print("Failed to send results:", response.text)
        return None, None
    
    response_data = response.json()
    print("Response:", response_data)
    
    request_id = response_data.get('id')
    
    if wait_for_completion and request_id:
        print(f"Waiting for import to complete (request ID: {request_id})...")
        final_status = wait_for_import_completion(request_id, client_id, client_secret)
        return request_id, final_status
    
    return request_id, response_data

def process_all_batches():
    """
    Process all batches defined in the configuration and collect results.
    
    :return: List of results for each batch
    """
    if not BATCHES:
        print("No batches found in configuration. Please check your config.ini file.")
        return []
    
    all_results = []
    
    for i, batch in enumerate(BATCHES, 1):
        print(f"\n{'='*60}")
        print(f"Processing Batch {i}/{len(BATCHES)}")
        print(f"File: {batch['FILE_PATH']}")
        print(f"Assessment: {batch['ASSESSMENT_NAME']}")
        print(f"Scan Type: {batch['SCAN_TYPE']}")
        print(f"{'='*60}")
        
        # Validate required batch parameters
        required_params = ['FILE_PATH', 'SCAN_TYPE', 'ASSESSMENT_NAME']
        missing_params = [param for param in required_params if not batch.get(param)]
        
        if missing_params:
            error_msg = f"Batch {i} missing required parameters: {', '.join(missing_params)}"
            print(f"ERROR: {error_msg}")
            result = {
                'batch_number': i,
                'batch_config': batch,
                'success': False,
                'error': error_msg,
                'request_id': None,
                'final_status': None
            }
            all_results.append(result)
            continue
        
        try:
            # Process the batch
            request_id, final_status = send_results(
                batch['FILE_PATH'],
                batch['SCAN_TYPE'],
                batch['ASSESSMENT_NAME'],
                batch['IMPORT_TYPE'],
                CLIENT_ID,
                CLIENT_SECRET,
                batch['SCAN_TARGET'],
                batch['AUTO_IMPORT'],
                batch['WAIT_FOR_COMPLETION']
            )
            
            # Determine success based on final status
            success = False
            if final_status:
                if isinstance(final_status, dict):
                    success = final_status.get('status') == 'IMPORTED'
                else:
                    success = request_id is not None
            
            result = {
                'batch_number': i,
                'batch_config': batch,
                'success': success,
                'error': None,
                'request_id': request_id,
                'final_status': final_status
            }
            
        except Exception as e:
            error_msg = f"Exception processing batch {i}: {str(e)}"
            print(f"ERROR: {error_msg}")
            result = {
                'batch_number': i,
                'batch_config': batch,
                'success': False,
                'error': error_msg,
                'request_id': None,
                'final_status': None
            }
        
        all_results.append(result)
        
        # Add configurable delay between batches to avoid overwhelming the API
        if i < len(BATCHES):
            # Calculate adaptive delay based on file size
            adaptive_delay = BATCH_DELAY
            try:
                if os.path.exists(batch['FILE_PATH']):
                    file_size = os.path.getsize(batch['FILE_PATH'])
                    # Add extra delay for large files (>10MB gets extra 5 seconds, >50MB gets extra 15 seconds)
                    if file_size > 50 * 1024 * 1024:  # 50MB
                        adaptive_delay += 15
                        print(f"Large file detected ({file_size / (1024*1024):.1f}MB), extending delay by 15 seconds")
                    elif file_size > 10 * 1024 * 1024:  # 10MB
                        adaptive_delay += 5
                        print(f"Medium file detected ({file_size / (1024*1024):.1f}MB), extending delay by 5 seconds")
            except Exception as e:
                print(f"Could not check file size for adaptive delay: {e}")
            
            print(f"Waiting {adaptive_delay} seconds before processing next batch...")
            for remaining in range(adaptive_delay, 0, -1):
                print(f"  {remaining} seconds remaining...", end='\r')
                time.sleep(1)
            print("  Starting next batch...        ")  # Clear the countdown line
    
    return all_results

def display_final_results(results):
    """
    Display a summary of all batch processing results.
    
    :param results: List of batch processing results
    """
    print(f"\n{'='*80}")
    print("FINAL RESULTS SUMMARY")
    print(f"{'='*80}")
    
    successful_batches = [r for r in results if r['success']]
    failed_batches = [r for r in results if not r['success']]
    
    print(f"Total Batches Processed: {len(results)}")
    print(f"Successful: {len(successful_batches)}")
    print(f"Failed: {len(failed_batches)}")
    
    if successful_batches:
        print(f"\n{'='*40}")
        print("SUCCESSFUL BATCHES:")
        print(f"{'='*40}")
        for result in successful_batches:
            batch = result['batch_config']
            print(f"Batch {result['batch_number']}: {batch['ASSESSMENT_NAME']}")
            print(f"  File: {batch['FILE_PATH']}")
            print(f"  Request ID: {result['request_id']}")
            if result['final_status'] and isinstance(result['final_status'], dict):
                status = result['final_status'].get('status', 'Unknown')
                print(f"  Final Status: {status}")
            print()
    
    if failed_batches:
        print(f"\n{'='*40}")
        print("FAILED BATCHES:")
        print(f"{'='*40}")
        for result in failed_batches:
            batch = result['batch_config']
            print(f"Batch {result['batch_number']}: {batch.get('ASSESSMENT_NAME', 'Unknown')}")
            print(f"  File: {batch.get('FILE_PATH', 'Unknown')}")
            print(f"  Error: {result['error']}")
            print()
    
    print(f"{'='*80}")

# Main execution
if __name__ == "__main__":
    print("Starting Phoenix Import Script")
    print("Processing all batches from configuration...")
    
    # Process all batches
    results = process_all_batches()
    
    # Display final results
    display_final_results(results)