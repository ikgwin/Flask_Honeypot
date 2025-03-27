# v2.0
# Updated 24/03/2025


# *************************      IMPORTING MODULES     *************************

import os
import json
import logging
from pythonjsonlogger import jsonlogger
from functools import wraps
from flask import Flask, redirect, render_template, request, send_from_directory, Response, make_response
import re
import csv
from datetime import datetime

# *************************         LOGGER CONFIGS     ************************* 

# -------- Config stuff for the normal logger --------
log_file = 'Honeypot_Logs.log' # Sets the name of the log file where logs will be saved.
logger = logging.getLogger('Honeypot_Logger') # Createss a logger named 'Honeypot_Logger' to handle logging.
logger.setLevel(logging.DEBUG) # Thisll set the logging level to DEBUG, meaning it will capture all log messages at the DEBUG level or higher.
logger_fh = logging.FileHandler(log_file) # Creates a file handler to write logs to the specified log_file.
logger_fh.setLevel(logging.DEBUG) # Sets the log level for the file handler to DEBUG, so it writes all messages at DEBUG or higher.
logger_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s') # Defines the format for the log messages, including the timestamp, logger name, log level, and the actual message.
logger_fh.setFormatter(logger_formatter) # Applies the defined format to the file handler.
logger.addHandler(logger_fh) # Adds the file handler to the logger, enabling it to write logs to the file.

# -------- Config stuff for the JSON logger --------
# Comments basically the same as the config above, refeer to them
log_file_json = "Honeypot_logs_JSON.log"
json_logger = logging.getLogger('json_logger')
json_logger.setLevel(logging.DEBUG)
logfile_json_fh = logging.FileHandler(log_file_json) 
logfile_json_fh.setLevel(logging.DEBUG)
logfile_json_formatter = jsonlogger.JsonFormatter('%(asctime)s %(name)s %(levelname)s %(message)s %(ip)s %(cfip)s') 
logfile_json_fh.setFormatter(logfile_json_formatter) 
json_logger.addHandler(logfile_json_fh) 

# -------- Config stuff for the CSV logger --------
# Comments still basically the same as above
csv_file = "Honeypot_logs_CSV.csv"

# Initialise the time var
ct = datetime.now()
ct_str = str(ct)
ts = ct.timestamp()
ts_str = str(ts)

# *************************       LOGGING FUNCTIONS      *************************

# function to check if a string is empty or is only whitespaces
def is_empty_or_whitespace(str):
    return str.strip() == ""

# function to check if username is empty or is only whitespaces
def un_is_empty(username):
    return is_empty_or_whitespace(username)

# function to check if password is empty or is only whitespaces
def pw_is_empty(password):
    return is_empty_or_whitespace(password)

# log requests in JSON format, and append to "Honeypot_logs.log"
def log_requests(username, password):

    ''' Function that logs the request info to a file named "Honeypot_Logs.log" when its called '''

    # un checker
    if (username is None or un_is_empty(username)):
        username = "NULL_VAL"
    # pw checker
    if (password is None or pw_is_empty(password)):
        password = "NULL_VAL"

    if ('segoeui-semilight.ttf' in request.url 
        or 'segoeui-regular.ttf' in request.url 
        or "favicon.ico" in request.url): # If the font files are included in the request, do not log them
        return

    # Initialise ingested log data
    cfip = request.headers.get('CF-Connecting-IP')
    ingested_log_data = {
        "time_of_event": ct_str,
        "timestamp": ts_str,  
        "log_level": "INFO",        
        "event_type": "honeypot_access",
        "message": "Request Made",
        "http_method": request.method,
        "url": request.url,
        "headers": dict(request.headers),   
        "ip": request.remote_addr,
        "cfip": request.headers.get('CF-Connecting-IP'),
        "user_agent": request.headers.get('User-Agent', 'Unknown'),
    }

    # if UN and PW in function call, append it to log data
    if username != "NULL_VAL" or password != "NULL_VAL":
        ingested_log_data["message"] = "Authentication Request Made"
        ingested_log_data["auth_attempt"] = {"username": username, "password": password}

    # Log the event to the file
    logger.info(ingested_log_data)


# log requests in JSON format, and append to "Honeypot_logs_JSON.log"
def log_requests_in_JSON(username, password):
    
    ''' Function that logs the request info to a file named "Honeypot_Logs_JSON.log" when its called '''

    # un checker
    if (username is None or un_is_empty(username)):
        username = "NULL_VAL"
    # pw checker
    if (password is None or pw_is_empty(password)):
        password = "NULL_VAL"

    if ('segoeui-semilight.ttf' in request.url 
        or 'segoeui-regular.ttf' in request.url 
        or "favicon.ico" in request.url): # If the font files are included in the request, do not log them
        return

    # Initialise ingested log data
    cfip = request.headers.get('CF-Connecting-IP')
    ingested_log_data = {
        "time_of_event": ct_str,
        "timestamp": ts_str,
        "log_level": "INFO",
        "event_type": "honeypot_access",
        "message": "Request Made",
        "url": request.url,
        "headers": dict(request.headers),
        "ip": request.remote_addr,
        "user_agent": request.headers.get('User-Agent', 'Unknown'),
    }

    # if UN and PW in function call, append it to log data
    if username != "NULL_VAL" or password != "NULL_VAL":
        ingested_log_data["message"] = "Authentication Request Made"
        ingested_log_data["auth_attempt"] = {"username": username, "password": password}

    json_logger.info(ingested_log_data)

    # test shit:
    # json_entry = json.dumps(ingested_log_data)
    # json_logger.info(json_entry)
    # Log the event to the file
    # json_logger.info(ingested_log_data)

def log_requests_in_CSV(username, password):
    
    ''' This function handles the logging of events in CSV format to the file "Honeypot_logs_CSV.csv '''

    # un checker
    if (username is None or un_is_empty(username)):
        username = "NULL_VAL"
    # pw checker
    if (password is None or pw_is_empty(password)):
        password = "NULL_VAL"

    if ('segoeui-semilight.ttf' in request.url 
        or 'segoeui-regular.ttf' in request.url 
        or "favicon.ico" in request.url): # If the font files are included in the request, do not log them
        return

    # titles =[] -- was used to make the title of csv
    titles = ["time_of_event", "timestamp", "log_level", "event_type", "url", "headers.Host", "headers.User-Agent", "headers.Accept", 
                "headers.Accept-Language", "headers.Accept-Encoding", "headers.Content-Type", "headers.Content-Length", "headers.Origin", 
                "headers.Connection", "headers.Referer", "headers.Cookie", "headers.Upgrade-Insecure-Requests", "headers.Sec-Fetch-Dest", 
                "headers.Sec-Fetch-Mode", "headers.Sec-Fetch-Site", "headers.Sec-Fetch-User", "headers.Priority", "user_agent", 
                "auth_attempt.username", "auth_attempt.password"]
            
    values = []

    headers_dictionary = dict(request.headers)

    # Initialise ingested log data
    ingested_log_data = {
        "time_of_event": ct_str,
        "timestamp": ts_str,
        "log_level": "INFO",
        "event_type": "honeypot_access",
        "message": "Request Made",
        "url": request.url,
        "headers": headers_dictionary,
        "ip": request.remote_addr,
        "user_agent": request.headers.get('User-Agent', 'Unknown'),
        "username": username,
        "password": password
    }

    # log only the values that match the title
    for title in titles:
        if title.startswith("headers."):
            headers_match = re.search(r"headers\.(.+)", title)
            if headers_match:
                header_key = headers_match.group(1)

                if ( (ingested_log_data["headers"].get(header_key, "NULL_VAL")) is None
                    or (is_empty_or_whitespace(ingested_log_data["headers"].get(header_key, ""))) ):
                    values.append("NULL_VAL")
                else:
                    values.append(ingested_log_data["headers"].get(header_key, ""))

        elif title.startswith("auth_attempt."):
            auth_match = re.search(r"auth_attempt\.(.+)", title)
            if auth_match:
                auth_key = auth_match.group(1)

                if auth_key == "username":
                    values.append(ingested_log_data["username"])
                elif auth_key == "password":
                    values.append(ingested_log_data["password"])
                
        else:
            if ( (ingested_log_data.get(title, "NULL_VAL")) is None
                or (is_empty_or_whitespace(ingested_log_data.get(title, "NULL_VAL"))) ):
                values.append("NULL_VAL")
            else:
                values.append(ingested_log_data.get(title, "NULL_VAL"))

    # putting the title at the top of the CSV file once

    with open("Honeypot_logs_CSV.csv", mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(values)

    # test shit:
    # print("\n")
    # print(titles)
    # print("\n")
    # print(len(titles))
    # print("\n")
    # print(values)
    # print("\n")
    # print(len(values))


# *************************         EVENT HANDLERS / ROUTES        *************************

def create_app(test_config=None):

    app = Flask(__name__, instance_relative_config=True)

    # Handler for before every request
    @app.before_request
    def log_all_requests():
        ''' Function to simply called the log functions, and does so for every and all requests '''
        log_requests("NULL_VAL", "NULL_VAL") # Call the function that stores logs
        log_requests_in_JSON("NULL_VAL", "NULL_VAL")
        log_requests_in_CSV("NULL_VAL", "NULL_VAL")
        # log_requests_in_JSON_TEST("na", "na") -----------------------> commented out bcos test

    # Handler for 404 errors
    @app.errorhandler(404)
    def page_not_found(e):
        ''' Function to redirects the hackerman to the html file specified for 404 errors '''
        return render_template('404.html'), 404         # note that we set the 404 status explicitly

    # Handler for 403 errors : the authenticated hackerman does not have permissions to visit
    @app.errorhandler(403)
    def page_no_access(e):
        ''' Function to redirects the hackerman to the html file specified for 403 errors '''
        return render_template('403.html'), 403

    # Handler for 401 errors : the hackerman is not authenticated
    @app.errorhandler(401)
    def page_auth_required(e):
        ''' Function to redirects the hackerman to the html file specified for 401 errors''' 
        return render_template('401.html'), 401
    
    # Register error handlers for different HTTP error codes
    app.register_error_handler(404, page_not_found)  # Handles 404 errors (Page Not Found)
    app.register_error_handler(403, page_no_access)  # Handles 403 errors (Forbidden Access)
    app.register_error_handler(401, page_auth_required)  # Handles 401 errors (Authentication Required)
    
    # Configure the Flask app with a secret key for sessions or cookies
    app.config.from_mapping(
        SECRET_KEY=None,  # Sets a secret key used for signing cookies, sessions, etc
    )
    print(app.static_folder) # Print the static folder path of the Flask app 

    # Ensure the instance folder exists - used for configuration / data storage.
    try:
        os.makedirs(app.instance_path)  # Try to create the instance folder if it doesn't exist
    except OSError:
        pass  # If the folder already exists or there’s another OS error, do nothing

    # TBH idk wtf these next 5 are doing since they have no event decorator 
    def check_auth(username, password):
        logger.info(f"{request.base_url}|{username}:{password}")
        return False

    def authenticate():
        """Sends a 401 response that enables basic auth"""
        return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})

    def requires_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.authorization
            if not auth or not check_auth(auth.username, auth.password):
                return authenticate()
            return f(*args, **kwargs)
        return decorated

    def add_response_headers(headers={}):
        """This decorator adds the headers passed in to the response"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                resp = make_response(f(*args, **kwargs))
                h = resp.headers
                for header, value in headers.items():
                    h[header] = value
                return resp
            return decorated_function
        return decorator

    def changeheader(f):
        return add_response_headers({"Server": "Microsoft-IIS/7.5", 
            "X-Powered-By": "ASP.NET"})(f)


    # This absolute behemoth redirects the hackerman to the home page upon visiting any of the listed paths
    @app.route('/Abs/')
    @app.route('/aspnet_client/')
    @app.route('/Autodiscover/')
    @app.route('/AutoUpdate/')
    @app.route('/CertEnroll/')
    @app.route('/CertSrv/')
    @app.route('/Conf/')
    @app.route('/DeviceUpdateFiles_Ext/')
    @app.route('/DeviceUpdateFiles_Int/')
    @app.route('/ecp/')
    @app.route('/Etc/')
    @app.route('/EWS/')
    @app.route('/Exchweb/')
    @app.route('/GroupExpansion/')
    @app.route('/Microsoft-Server-ActiveSync/')
    @app.route('/OAB/')
    @app.route('/ocsp/')
    @app.route('/PhoneConferencing/')
    @app.route('/PowerShell/')
    @app.route('/Public/')
    @app.route('/RequestHandler/')
    @app.route('/RequestHandlerExt/')
    @app.route('/Rgs/')
    @app.route('/Rpc/')
    @app.route('/RpcWithCert/')
    @app.route('/UnifiedMessaging/')
    @changeheader
    @requires_auth
    def stub_redirect():
        return redirect('/')

    @app.route('/owa/auth/15.1.1466/themes/resources/segoeui-regular.ttf', methods=['GET'])
    @changeheader
    def font_segoeui_regular_ttf():
        ''' Font shit 1 ''' 
        return send_from_directory(app.static_folder, filename='segoeui-regular.ttf', conditional=True)
        
    @app.route('/owa/auth/15.1.1466/themes/resources/segoeui-semilight.ttf', methods=['GET'])
    @changeheader
    def font_segoeui_semilight_ttf():
        ''' Font shit 2 ''' 
        return send_from_directory(app.static_folder, filename='segoeui-semilight.ttf', conditional=True)

    @app.route('/owa/auth/15.1.1466/themes/resources/favicon.ico', methods=['GET'])
    @changeheader
    def favicon_ico():
        ''' Font shit 3 ''' 
        return send_from_directory(app.static_folder, filename='favicon.ico', conditional=True)

    # Checks for authentication 
    @app.route('/owa/auth.owa', methods=['GET', 'POST'])
    @changeheader
    def auth():
        
        ''' Function for auth checking logic n stuff '''

        ua = request.headers.get('User-Agent')
        ip = request.remote_addr
        if request.method == 'GET':
            return redirect('/owa/auth/logon.aspx?replaceCurrent=1&reason=3&url=', 302)
        else:
            passwordText = ""
            password = ""
            username = ""

            if "username" in request.form:
                username = request.form["username"]
            if "password" in request.form:
                password = request.form["password"]
            if "passwordText" in request.form:
                passwordText = request.form["passwordText"]

            log_requests(username, password)
            log_requests_in_JSON(username, password)
            log_requests_in_CSV(username, password)

            # log_requests_in_JSON_TEST(username, password) -----------------------> commented out bcos test
            return redirect('/owa/auth/logon.aspx?replaceCurrent=1&reason=2&url=', 302)

    # Hanlder for when hackerman goes to this login path
    @app.route('/owa/auth/logon.aspx', methods=['GET'])
    @changeheader
    def owa():
        ''' Redirects the hackerman to the login page '''
        return render_template("outlook_web.html")  

    # Handlers for the following pages
    @app.route('/')
    @app.route('/exchange/')
    @app.route('/webmail/')
    @app.route('/exchange')
    @app.route('/webmail')
    @changeheader
    def index():

        ''' Logs request when hackerman goes to one of those paths above and redirects 
            them to the login page '''

        log_requests("NULL_VAL", "NULL_VAL")
        log_requests_in_JSON("NULL_VAL", "NULL_VAL")
        log_requests_in_CSV("NULL_VAL", "NULL_VAL")
        # log_requests_in_JSON_TEST("na", "na") -----------------------> commented out bcos test
        return redirect('/owa/auth/logon.aspx?replaceCurrent=1&url=', 302)         

    return app

# Run it
if __name__ == "__main__":
    if __name__ == '__main__':
        print("\n\n\n\n")
        create_app().run(debug=False,port=5090, host="0.0.0.0")

