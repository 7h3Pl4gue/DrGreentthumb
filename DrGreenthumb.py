import requests
from bs4 import BeautifulSoup
import os
import re
from termcolor import colored
import datetime

# print header
header = colored("""
▓█████▄  ██▀███            ▄████  ██▀███  ▓█████ ▓█████  ███▄    █ ▄▄▄█████▓ ██░ ██  █    ██  ███▄ ▄███▓ ▄▄▄▄   
▒██▀ ██▌▓██ ▒ ██▒         ██▒ ▀█▒▓██ ▒ ██▒▓█   ▀ ▓█   ▀  ██ ▀█   █ ▓  ██▒ ▓▒▓██░ ██▒ ██  ▓██▒▓██▒▀█▀ ██▒▓█████▄ 
░██   █▌▓██ ░▄█ ▒        ▒██░▄▄▄░▓██ ░▄█ ▒▒███   ▒███   ▓██  ▀█ ██▒▒ ▓██░ ▒░▒██▀▀██░▓██  ▒██░▓██    ▓██░▒██▒ ▄██
░▓█▄   ▌▒██▀▀█▄          ░▓█  ██▓▒██▀▀█▄  ▒▓█  ▄ ▒▓█  ▄ ▓██▒  ▐▌██▒░ ▓██▓ ░ ░▓█ ░██ ▓▓█  ░██░▒██    ▒██ ▒██░█▀  
░▒████▓ ░██▓ ▒██▒ ██▓    ░▒▓███▀▒░██▓ ▒██▒░▒████▒░▒████▒▒██░   ▓██░  ▒██▒ ░ ░▓█▒░██▓▒▒█████▓ ▒██▒   ░██▒░▓█  ▀█▓
 ▒▒▓  ▒ ░ ▒▓ ░▒▓░ ▒▓▒     ░▒   ▒ ░ ▒▓ ░▒▓░░░ ▒░ ░░░ ▒░ ░░ ▒░   ▒ ▒   ▒ ░░    ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ░  ░░▒▓███▀▒
 ░ ▒  ▒   ░▒ ░ ▒░ ░▒       ░   ░   ░▒ ░ ▒░ ░ ░  ░ ░ ░  ░░ ░░   ░ ▒░    ░     ▒ ░▒░ ░░░▒░ ░ ░ ░  ░      ░▒░▒   ░ 
 ░ ░  ░   ░░   ░  ░      ░ ░   ░   ░░   ░    ░      ░      ░   ░ ░   ░       ░  ░░ ░ ░░░ ░ ░ ░      ░    ░    ░ 
   ░       ░       ░           ░    ░        ░  ░   ░  ░         ░           ░  ░  ░   ░            ░    ░      ░ 
 ░                 ░                                                                                          ░ 
""", "green")

print(header)

print("Hello, my name is Dr. Greenthumb")
print("Made by 7h3_Pl4gue")

# Prompt the user to enter the URL of the website to scrape
url = input("Enter the website URL: ")

current_directory = os.getcwd()
print(f"Current Directory: {current_directory}")


# Initialize a list to store results
results = []

#results_file
result_file = None

# Function to log results to the console and the results list
def print_result(text, results_file=None):
    print(text)
    results.append(text)
    if results_file:
        results_file.write(text + '\n')

    
# Set a User-Agent header to mimic a web browser
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
}

try:
    # Send an HTTP GET request to the URL with headers
    response = requests.get(url, headers=headers)
    
    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Parse the HTML content of the page using BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        # Create a timestamp for the results file
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        results_filename = os.path.join(current_directory, f'results_{timestamp}.txt')
        print(f"Results Filename: {results_filename}")

        results_file = open(results_filename, 'w', encoding='utf-8')

        # Perform security testing checks
        
        # Cross-Site Scripting (XSS)
        potential_xss_vulnerabilities = soup.find_all(lambda tag: (
            tag and (
                tag.has_attr("onclick") or
                tag.has_attr("onmouseover") or
                tag.has_attr("onload") or
                tag.has_attr("onerror") or
                tag.has_attr("onfocus") or
                tag.has_attr("onblur") or
                tag.has_attr("onchange") or
                tag.has_attr("onsubmit") or
                tag.has_attr("onreset") or
                tag.has_attr("onselect") or
                tag.has_attr("onkeydown") or
                tag.has_attr("onkeypress") or
                tag.has_attr("onkeyup") or
                tag.has_attr("ondblclick") or
                tag.has_attr("onmousedown") or
                tag.has_attr("onmouseup") or
                tag.has_attr("onmousemove") or
                tag.has_attr("onmouseout") or
                tag.has_attr("onmouseenter") or
                tag.has_attr("onmouseleave") or
                tag.has_attr("ondrag") or
                tag.has_attr("ondragstart") or
                tag.has_attr("ondragend") or
                tag.has_attr("ondragover") or
                tag.has_attr("ondragenter") or
                tag.has_attr("ondragleave") or
                tag.has_attr("ondrop") or
                tag.has_attr("oncontextmenu") or
                tag.has_attr("onscroll") or
                tag.has_attr("onresize") or
                tag.has_attr("onmessage") or
                tag.has_attr("onloadstart") or
                tag.has_attr("onloadeddata") or
                tag.has_attr("onloadedmetadata") or
                tag.has_attr("oncanplay") or
                tag.has_attr("oncanplaythrough") or
                tag.has_attr("ontimeupdate") or
                tag.has_attr("onended")
            )
        ))
        if potential_xss_vulnerabilities:
            print_result("Potential XSS vulnerabilities found:", results_file)
            for tag in potential_xss_vulnerabilities:
                result_text = tag.prettify()
            results.append(result_text)  # Add the result to the list
            print_result(result_text, results_file)  # Debugging: Print to console
        else:
            print_result("No potential XSS vulnerabilities found.", results_file)
       

        # Cross-Site Request Forgery (CSRF)
        potential_csrf_forms = soup.find_all('form')
        if potential_csrf_forms:
            print_result("Potential CSRF forms found:", results_file)
            for form in potential_csrf_forms:
                csrf_token_input = form.find('input', {'name': 'csrf_token'})  # Adjust this based on the form
                if csrf_token_input is None:
                    result_text = form.prettify()
                    print_result(result_text)
        else:
            print_result("No potential CSRF forms found.", results_file)
        
        # Sensitive Data Exposure
        sensitive_info_keywords = [
        'api_key',
        'password',
        'session_token',
        'username',
        'email',
        'credit_card',
        'bank_account',
        'credit_score',
        'pci',
        'financial_account',
        'medical_record',
        'health_insurance',
        'diagnosis',
        'patient_id',
        'health_history',
        'access_token',
        '2fa',
        'oauth_token',
        'jwt',
        'api_secret',
        'social_security_act',
        'gdpr',
        'nda',
        'privacy_policy',
        'legal_notice',
        'employee_id',
        'salary_info',
        'performance_review',
        'employment_contract',
        'hr_records',
        'student_id',
        'academic_transcript',
        'enrollment_records',
        'educational_assessments',
        'teacher_notes',
        'email_content',
        'chat_logs',
        'text_messages',
        'voicemail_transcripts',
        'meeting_notes',
        'ip_address',
        'vulnerability_report',
        'incident_log',
        'firewall_rules',
        'security_policies',
        'classified_information',
        'top_secret',
        'classified_documents',
        'military_strategy',
        'government_contracts',
        'fingerlog_result',
        'retina_scan',
        'dna_sequence',
        'biometric_templates',
        'facial_recognition_data',
        'geographic_coordinates',
        'gps_data',
        'geolocation_information',
        'geofencing_parameters',
        'race',
        'religion',
        'gender',
        'ethnic_background',
        'patents',
        'trademarks',
        'copyrights',
        'trade_secrets',
        'invention_details',
        'supplier_contracts',
        'vendor_agreements',
        'supplier_pricing',
        'supplier_contact_info',
        'purchase_orders',
        'invoices',
        'receipts',
        'financial_statements',
        'tax_records',
        'aws_access_key',
        'azure_key_vault',
        'google_cloud_service_account_key',
        'cloud_api_token',
        'customer_names',
        'customer_addresses',
        'customer_contact_info',
        'customer_purchase_history',
        'customer_support_tickets',
        'license_keys',
        'software_activation_codes',
        'license_agreement',
        'device_serial_numbers',
        'imei_numbers',
        'mac_addresses',
        'social_security_number',
        'driver_license',
        'passport_number',
        'social_media_tokens',
        'payment_information',
        'bank_routing_number',
        'tax_identification_number',
        'contract_details',
        'confidential_information',
        'personally_identifiable_information',
        'encryption_key',
        'secret_question_answer',
        'security_question_answer',
        'online_credentials',
        'private_key',
        'public_key',
        'access_code',
        'security_code',
        'code_verification',
        'phone_verification',
        'location_data',
        'access_log',
        'error_log',
        'audit_log',
        'authentication_log',
        'activity_log',
        'audit_trail',
        'authorization_code'
    ]

        for keyword in sensitive_info_keywords:
            matches = re.findall(rf'(?i){keyword}\s*=\s*["\'](.*?)["\']', response.text)
            if matches:
                print_result(f"Potential sensitive data exposed: {keyword}", results_file)
                for match in matches:
                    print_result(match)
            else:
                print_result(f"No potential {keyword} data found.", results_file)
        
        # Security Headers
        csp_header = response.headers.get('Content-Security-Policy')
        hsts_header = response.headers.get('Strict-Transport-Security')
        if csp_header:
            print_result(f"Content Security Policy (CSP) Header: {csp_header}", results_file)
        else:
            print_result("No CSP header found.", results_file)
        
        if hsts_header:
            print_result(f"HTTP Strict Transport Security (HSTS) Header: {hsts_header}", results_file)
        else:
            print_result("No HSTS header found.", results_file)
        
        # SQL Injection Detection
        potential_sql_injections = re.findall(r'\'\s*OR\s+1=1\s*--', response.text)
        if potential_sql_injections:
            print_result("Potential SQL injection vulnerabilities found.", results_file)
        else:
            print_result("No potential SQL injection vulnerabilities found.", results_file)
        
        # Directory Traversal Detection
        potential_directory_traversal = re.findall(r'\.\./', response.text)
        if potential_directory_traversal:
            print_result("Potential directory traversal vulnerabilities found.", results_file)
        else:
            print_result("No potential directory traversal vulnerabilities found.", results_file)
        
        # File Inclusion Vulnerability Detection
        potential_file_inclusion = re.findall(r'\binclude\s*\(.*\);', response.text)
        if potential_file_inclusion:
            print_result("Potential file inclusion vulnerabilities found.", results_file)
        else:
            print_result("No potential file inclusion vulnerabilities found.", results_file)

        # Insecure Cross-Origin Resource Sharing (CORS)
        cors_policy = response.headers.get('Access-Control-Allow-Origin')
        if cors_policy:
            if cors_policy == '*':
                print_result("Insecure CORS policy (allows any domain).", results_file)
            else:
                print_result(f"CORS policy: {cors_policy}", results_file)
        else:
            print_result("No CORS policy found.", results_file)

        # IDOR and LFI Check: Look for indicators in query parameters and form inputs
        potential_idor_lfi_indicators = re.findall(r'\.\./|etc/passwd|../../|file\:\/\/', response.text)
        if potential_idor_lfi_indicators:
            print_result("Potential IDOR and LFI indicators found:", results_file)
            for indicator in potential_idor_lfi_indicators:
                print_result(indicator, results_file)
        else:
            print_result("No potential IDOR or LFI indicators found.", results_file)

        # Authorization Flaw check:
        unauthorized_actions = [
            '/admin',
            '/user/profile',
            '/private',
            '/edit',
            '/api/v1/admin',
            '/checkout',
            '/delete',
            '/user/settings',
            '/user/orders',
            '/user/messages',
            '/download',
            '/reset-password',
            '/admin/logs',
            '/privileged-action',
            '/admin/users',
            '/admin/settings',
            '/user/inbox',
            '/user/outbox',
            '/user/documents',
            '/download/report',
            '/checkout/process',
            '/checkout/confirm',
            '/order/history',
            '/order/details',
            '/user/notifications',
            '/user/settings/security',
            '/user/billing',
            '/user/preferences',
            '/admin/reports',
            '/admin/analytics',
            '/checkout/payment',
            '/order/cancel',
            '/download/restricted',
            '/admin/reports/export',
            '/user/documents/private',
            '/user/settings/privacy',
            '/checkout/payment/confirm',
            '/order/cancel/confirmation',
            '/download/internal',
            '/restricted/resource',
            '/admin/settings/permissions',
            '/user/invoices',
            '/user/settings/notifications',
            '/checkout/confirm/payment',
            '/order/cancel/request',
            '/download/private-data',
            '/restricted/resource2',
        ]

        for action in unauthorized_actions:
            if action in response.text:

                full_path = url + action

                print_result(f"Potential authorization flaw detected: {full_path} accessable without proper authentication.", results_file)
            
        
        # Remote Code Execution
        rce_payloads = [';ls', ';id', '|ls', '|id']
        for payload in rce_payloads:
            if payload in response.url:
                print_result(f"Potential RCE vulnerability detected in URL: {payload}", results_file) 

        # Business Logic Vulnerabilities
        admin_indicator = soup.find(string='Admin')
        if admin_indicator:
            print_result("Potential privilege escalation vulnerability: Admin role found.". results_file) 

          
        # Open Redirect Vulnerability Detection
        potential_open_redirect = re.findall(r'window\.location\s*=\s*["\'](https?://[^"\']+)["\']', response.text)
        if potential_open_redirect:
            print_result("Potential open redirect vulnerabilities found.", results_file)
        
        # Check for potential interesting files
        potential_files = soup.find_all('a', href=True)
        file_extensions = [
        'zip',
        'pdf',
        'doc',
        'xls',
        'csv',
        'php',
        'html',
        'sql',
        'json',
        'cfg',
        'ini',
        'bak',
        'backup',
        'dump',
        'tar',
        'gzip',
        '7z',
        'rar',
        'aspx',
        'log',
        'png',
        'jpg',
        'gif',
        'bmp',
        'tiff',
        'svg',
        'mp3',
        'mp4',
        'wav',
        'avi',
        'mov',
        'flv',
        'rtf',
        'ppt',
        'odt',
        'odp',
        'ods',
        'xml',
        'csv',
        'db',
        'js',
        'css',
        'py',
        'rb',
        'pl',
        'java',
        'c',
        'config',
        'settings',
        'properties',
        'sys',
        'log',
        'error',
        'debug',
        'bz2',
        'lzma',
        'z',
        'tgz',
        'tbz',
        'xz',
        'exe',
        'dll',
        'bin',
        'jar',
        'war',
        'elf',
        'xml',
        'soap',
        'rest',
        'bak',
        'svn',
        'gitignore',
        'gitattributes',
        'dwg',
        'dxf',
        'stl',
        'vmdk',
        'vdi',
        'vbox',
        'ico',
        'eps',
        'tif',
        'tiff',
        'wav',
        'webp',
        'ai',
        'ps',
        'indd',
        'raw',
        'torrent',
        'magnet',
        'env',
        'envrc',
        'env.example',
        'env.production',
        'npmignore',
        'editorconfig',
        'jshintrc',
        'eslintrc',
        'eslintignore',
        'stylelint',
        'stylelintignore',
        'browserslist',
        'prettierrc',
        'prettierignore',
        'dockerfile',
        'docker-compose.yml',
        'requirements.txt',
        'pipfile',
        'pipfile.lock',
        'pyproject.toml',
        'setup.py',
        'MANIFEST.in',
        'pylintrc',
        'tox.ini',
        'pytest.ini',
        'setup.cfg',
        'babel.config.js',
        'postcss.config.js',
        'karma.conf.js',
        'protractor.conf.js',
        'wallaby.js',
        'jest.config.js',
        'rollup.config.js',
        'webpack.config.js',
        'jest.config.js',
        'tsconfig.json',
        'jsconfig.json',
        'babel.config.js',
        'vue.config.js',
        'nuxt.config.js',
        'angular.json',
        'nx.json',
        'nest-cli.json',
        'pm2.json',
        'nodemon.json',
        'now.json',
        'vercel.json',
        'netlify.toml',
        'webpack.config.js',
        'config.js',
        'config.json',
        'config.yaml',
        'config.yml',
        'config.toml',
        'settings.py',
        'wsgi.py',
        'urls.py',
        'asgi.py',
        'manage.py'
    #add more as needed
]

        if potential_files:
            print("Potential interesting files found:")
            for link in potential_files:
                href = link['href']
                file_extension = href.split('.')[-1].lower()
                if file_extension in file_extensions:
                    print_result(href, results_file)
        else:
            print_result("No potential interesting files found.", results_file)        
        

        # API
        api_endpoints = [
            '/api/v1/user/profile',
            '/api/v1/products',
            '/api/v1/orders',
            '/api/v1/payments',
            '/api/v1/invoices',
            '/api/v1/customers',
            '/api/v1/employees',
            '/api/v1/sales',
            '/api/v1/transactions',
            '/api/v1/settings',
            '/api/v1/reviews',
            '/api/v1/notifications',
            '/api/v1/categories',
            '/api/v1/shipping',
            '/api/v1/locations',
            '/api/v1/search',
            '/api/v2/user/profile',
            '/api/v2/products',
            '/api/v3/orders',
            '/api/v3/payments',
            '/api/v3/invoices',
            '/api/v3/customers',
            '/api/v3/employees',
            '/api/v3/sales',
            '/api/v3/transactions',
            '/api/v3/settings',
            '/api/v3/reviews',
            '/api/v3/notifications',
            '/api/v3/categories',
            '/api/v3/shipping',
            '/api/v3/locations',
            '/api/v3/search',
        ]

        for endpoint in api_endpoints:
            api_url = f"{url.rstrip('/')}{endpoint}"
            api_response = requests.get(api_url, headers=headers)

            if api_response.status_code == 200:
                print_result(f"API endpoint '{endpoint}' is accessible.", results_file)

        # Mixed Content
        resources = soup.find_all(['img', 'script', 'link'], {'src': True, 'href': True})

        mixed_content_found = False

        for resource in resources:
            resource_url = resource.get('src') or resource.get('href')
            if resource_url.startswith('http://') and not resource_url.startswith('https://'):
                print_result(f"Mixed content found: {resource_url}",results_file)
                mixed_content_found = True
        if not mixed_content_found:
            print_result("No mixed content issues found.", results_file)


        # Check for Potential Backup File
        backup_file_extensions =['.bak', '.backup', '.old']

        potential_links = soup.find_all('a', href=True)

        for extension in backup_file_extensions:
            potential_backup_files = [link for link in potential_links if re.search(fr'.*{extension}$', link['href'], re.IGNORECASE)]
            if potential_backup_files:
                print_result(f"Potential {extension} backup files found:", results_file)
                for link in potential_backup_files:
                    print_result(link['href'], results_file)
                    debug_mode_detected=True
                if not debug_mode_detected:
                        print_result("No potential debug mode indicators found.", results_file)

            else:
                print_result(f"No potential {extension} backup files found.", results_file)
        # SSI
        ssi_misconfigurations = re.findall(r'<!--\s*#include\s*(file|virtual|cgi)=["\'](.+?)["\']\s*-->', response.text, re.IGNORECASE)
        if ssi_misconfigurations:
            print_result("Potential Server-Side Includes (SSI) misconfigurations found.", results_file)
            for match in ssi_misconfigurations:
                print_result(f"SSI Directive: {match[0]}, Resource: {match[1]}", results_file)
        else:
            print_result("No potential SSI misconfigurations found.", results_file)
        # Debug Mode
        debug_mode_indicators = [
            "debug=true",
            "development_mode=true",
            "dev=true",
            "debug=1",
            "development=true",
            "trace=true",
            "trace=1",
            "debugger",
            "devtools"
        ]  
        for indicator in debug_mode_indicators:
            if indicator in response.text:
                print_result(f"Potential debug mode indicator detected: {indicator}", results_file)
                break

        # XXE Injection 
        potential_xxe_vulnerabilities = soup.find_all(lambda tag: (
            tag and (
                tag.name == "xml" or
                (tag.name == "img" and tag.has_attr("src") and tag["src"].lower().startswith("data:image/svg+xml")) or
                (tag.has_attr("src") and tag["src"].lower().endswith(".xml")) or
                (tag.has_attr("data") and tag["data"].lower().endswith(".xml"))
            )
        ))
        if potential_xxe_vulnerabilities:
            print_result("Potential XXE vulnerabilities found:", results_file)
            for tag in potential_xxe_vulnerabilities:
                print_result(tag.prettify(), results_file)
        else:
            print_result("No potential XXE vulnerabilities found.", results_file)  

        # XSSI
        potential_xssi_endpoints = [
            '/api/v1/user/profile',
            '/api/v1/products',
            '/api/v1/orders'
        ] 
        for endpoint in potential_xssi_endpoints:
            xssi_url = f"{url.rstrip('/')}{endpoint}"
            xssi_response = requests.get(xssi_url, headers=headers)  

            if xssi_response.status_code == 200:
                xssi_indicators = [
                    'while(1);',
                    'for(;;);',
                    'while(1) {}',
                    'for(;;) {}',
                    'throw 1;',
                    'throw 2;',
                    '<pre>)]}\'\n',
                    'while(1);</pre>',
                    'for(;;);</pre>',
                    'throw 1;</pre>',
                    'throw 2;</pre'
                ]

                for indicator in xssi_indicators:
                    if indicator in xssi_response.text:
                        print_result(f"Potential XSSI vulnerability detected at endpoint: {endpoint}", results_file)
                        break
                # Define the function to search for sensitive info in JavaScript code
        def search_sensitive_info_in_js(js_code, js_sensitive_info_keywords):
            found_info = []
            for keyword in js_sensitive_info_keywords:
                pattern = rf'(?i)(var\s+|const\s+|let\s+)?{keyword}\s*[:=]\s*[\'"]([^\'"]+)[\'"];?'
                matches = re.findall(pattern, js_code)
                found_info.extend(matches)
            return found_info
        # Extract and search JavaScript code from the HTML response
        js_code = '\n'.join([script.text for script in soup.find_all('script')])
        # Search for sensitive info in JavaScript code
        #sensitive_info_in_js = search_sensitive_info_in_js(js_code, js_sensitive_info_keywords)

        # Search for sensitive info in JavaScript code    
        js_code = response.text  # Assuming the JavaScript code is within the HTML response
        js_sensitive_info_keywords = [
        'api_key',
        'password',
        'session_token',
        'username',
        'email',
        'credit_card',
        'ssn',
        'social_security',
        'secret_key',
        'access_token',
        'private_key',
        'oauth_token',
        'auth_token',
        'jwt_token',
        'api_secret',
        'database_password',
        'aws_access_key',
        'aws_secret_key',
        'client_secret',
        'mysql_password',
        'postgresql_password',
        'mongodb_uri',
        'firebase_config',
        'azure_key',
        'google_cloud_key',
        'private_api_key',
        'private_api_token',
        'private_token',
        'bearer_token',
        'api_token',
        'encryption_key',
        'app_secret',
        'service_account_key',
        'app_id',
        'client_id',
        'client_secret',
        'consumer_key',
        'oauth_key',
        'oauth_secret',
        'security_key',
        'rsa_private_key',
        'rsa_public_key',
        'ssh_private_key',
        'ssh_public_key',
        'token_secret',
        'api_password',
        'cookie_secret',
        'api_key_id',
        'access_key_id',
        'client_id',
        'client_secret',
        'client_certificate',
        'root_certificate',
        'pem_file',
        'jks_file',
        'keystore_password',
        'truststore_password',
        'ssl_certificate',
        'ssl_private_key',
        'ssl_key_password',
        'hmac_key',
        'password_salt',
        'encryption_salt',
        'security_question',
        'security_answer',
        'two_factor_code',
        'biometric_data',
        'healthcare_data',
        'medical_record',
        'patient_id',
        'prescription',
        'credit_card_number',
        'cvv',
        'expiration_date',
        'billing_address',
        'passport_number',
        'driver_license',
        'social_insurance_number',
        'tax_identification_number',
        'employee_id',
        'bank_account',
        'routing_number',
        'credit_score',
        'financial_data',
        'investment_account',
        'mortgage_info',
        # Add more keywords or patterns as needed
    ]
    sensitive_info_in_js = search_sensitive_info_in_js(js_code, js_sensitive_info_keywords)

    if sensitive_info_in_js:
        #print("Potential sensitive information found in JavaScript code:", results_file)
        for info in sensitive_info_in_js:
            print(info)
    else:
        print("No potential sensitive information found in JavaScript code.")

        #Email Address Detected
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
        #email_matches = re.findall(email_pattern, response.text)
        potential_emails = re.findall(email_pattern, response.text)
        valid_emails = [email for email in potential_emails if not email.endswith('.png')]
        
        if potential_emails:
            print_result("Potential sensitive data exposed: Email Address")
            for email in potential_emails:
                print_result(email, results_file)
        else:
            print_result("No email addresses found.")

    if response.status_code != 200:

        print(f"Failed to retrieve the webpage. Status code: {response.status_code}") 

  
except requests.exceptions.RequestException as e:
    print(f"An error occurred while making the request: {e}")
    
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    if results_file:
        results_file.close()

save_results = input("Do you want to save the results to a file? (yes/no): ").strip().lower()

if save_results == 'yes':
    results_file = open(results_filename, 'w', encoding='utf-8')
    if results:
    #with open(results_filename, 'w', encoding='utf-8') as results_file:

        results_file = open(results_filename, 'w', encoding='utf-8')
        for result in results:
            results_file.write(result + '\n')
        results_file.close()
        print(f"Results saved in: {results_filename}")
    else:
       print("No results to save.")
else:
    print("Results not saved.")
