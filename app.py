import os
import shutil
import subprocess
import platform
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from utils import is_target_up, run_nmap_scan, parse_os, parse_nmap_services, search_exploits, run_vuln_scan, parse_vuln_scan, validate_hash, parse_hashcat_output, classify_cves_by_severity, set_cell_background
import hashlib
from datetime import datetime
import json
from docx import Document
from io import BytesIO
from docx.shared import Inches, RGBColor, Pt
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.enum.table import WD_TABLE_ALIGNMENT
from werkzeug.security import safe_join
from sqlalchemy.exc import SQLAlchemyError
from docx.enum.style import WD_STYLE_TYPE
from docx.oxml.shared import OxmlElement
from docx.oxml.ns import qn
from docx.oxml.shared import qn, OxmlElement




# Set constants
EXPLOIT_DB_PATH = "/usr/share/exploitdb/exploits/"
WORDLIST_PATH_GOBUSTER = "/usr/share/wordlists/dirb/big.txt"
NIKTO_OUTPUT_FILE = "nikto_output.txt"  # Output file for Nikto results
VIRUSTOTAL_API_KEY = "c65ad644ef9c7244822249f7a9d3ca8a75c4e1502ca2dbc6935334335f6bc2f9"
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/c65ad644ef9c7244822249f7a9d3ca8a75c4e1502ca2dbc6935334335f6bc2f9"
WORDLIST_PATH_HASHCAT="/usr/share/wordlists/seclists/Passwords/500-worst-passwords.txt"
# Global dictionary to store shell processes per user
shell_processes = {}

# Initialize Flask app and configure database
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.urandom(24)

# Add this security headers function
@app.after_request
def set_security_headers(response):
    """Set security headers on each response."""
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response

# Initialize the database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

#scanDB
class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target = db.Column(db.String(150), nullable=False)
    os_name = db.Column(db.String(150))
    services = db.Column(db.Text)  # Store as JSON
    exploits = db.Column(db.Text)  # Store as JSON
    cves = db.Column(db.Text)      # Store as JSON
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='scans')
    


# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Client_user table    
class ClientUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'), nullable=False)
    scan = db.relationship('ScanResult', backref='client_users')


# Create the database if it doesn't exist
with app.app_context():
    db.create_all()

# Login Manager setup
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Client login routes
@app.route("/client-login", methods=["GET", "POST"])
def client_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        client = ClientUser.query.filter_by(username=username).first()

        if client and check_password_hash(client.password, password):
            session['client_id'] = client.id
            session['client_scan_id'] = client.scan_id
            return redirect(url_for('client_scan_history'))
        else:
            return render_template("client_login.html", message="Invalid credentials")

    return render_template("client_login.html")

@app.route("/client-scan-history")
def client_scan_history():
    if 'client_id' not in session:
        return redirect(url_for('client_login'))
    
    scan_id = session['client_scan_id']
    client_id = session['client_id'] 
    scan = ScanResult.query.get_or_404(scan_id)

    scan = ScanResult.query.get_or_404(scan_id)
    client = ClientUser.query.get_or_404(client_id)

    session['client_username'] = client.username

    return render_template("scan_history.html", 
                         scans=[{
                             'id': scan.id,
                             'username': scan.user.username,
                             'target': scan.target,
                             'os_name': scan.os_name,
                             'timestamp': scan.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                             'services_count': len(json.loads(scan.services)) if scan.services else 0,
                             'exploits_count': len(json.loads(scan.exploits)) if scan.exploits else 0,
                             'cves_count': len(json.loads(scan.cves)) if scan.cves else 0
                         }], 
                         username=client.username,
                         is_client=True)

@app.route("/client-scan-details/<int:scan_id>")
def client_scan_details(scan_id):
    gobuster_results = []
    try:
        with open("gobuster_output.txt", "r") as file:
            output_lines = file.readlines()
        
        # Parse the Gobuster results
        for line in output_lines:
            if line.strip() and "Dirs" not in line:  # Skip header lines
                parts = line.strip().split()
                if len(parts) > 1:
                    # Extract the status code, remove ANSI escape sequences and the closing parenthesis ')'
                    status = re.sub(r'\x1b\[[0-9;]*m', '', parts[3])  # Remove ANSI codes
                    status = status.replace(')', '')  # Remove the closing parenthesis
                    gobuster_results.append({"path": parts[0], "status": status})
    except FileNotFoundError:
        gobuster_results = []    # 1. Validate session and authorization
    if 'client_id' not in session:
        return redirect(url_for('client_login'))

    client_id = session.get('client_id')
    assigned_scan_id = session.get('client_scan_id')

    # 2. Ensure client can access only their assigned scan
    if scan_id != assigned_scan_id:
        abort(403, description="Unauthorized access to this scan")

    try:
        # 3. Fetch scan directly
        scan = ScanResult.query.get_or_404(scan_id)

        # 4. Parse JSON data safely
        try:
            services = json.loads(scan.services or '[]')
            exploits = json.loads(scan.exploits or '{}')
            cves = json.loads(scan.cves or '[]')
        except (json.JSONDecodeError, TypeError):
            abort(500, description="Invalid scan data format")

        classified_cves = classify_cves_by_severity(cves)

        client_name = session.get('client_username', 'Client')

        return render_template(
            "client_scan_details.html",
            scan={
                'id': scan.id,
                'target': scan.target,
                'os_name': scan.os_name,
                'services': services,
                'exploits': exploits,
                'cves': cves,
                'timestamp': scan.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            },
            classified_cves=classified_cves,
            username=client_name,
            client_name=client_name,
            is_client=True, 
            gobuster_results=gobuster_results
        )

    except SQLAlchemyError:
        abort(500, description="Database error occurred")

# Admin routes
@app.route("/administration")
@login_required
def administration():
    scans = ScanResult.query.all()
    client_users = ClientUser.query.all()
    return render_template("administration.html", 
                         scans=scans, 
                         client_users=client_users,
                         username=current_user.username)
#client things
@app.route("/create-client-user", methods=["POST"])
@login_required
def create_client_user():
    username = request.form["username"]
    password = request.form["password"]
    scan_id = request.form["scan_id"]

    if ClientUser.query.filter_by(username=username).first():
        flash("Username already exists", "error")
        return redirect(url_for('administration'))

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_client = ClientUser(
        username=username,
        password=hashed_password,
        scan_id=scan_id
    )
    db.session.add(new_client)
    db.session.commit()

    flash("Client user created successfully", "success")
    return redirect(url_for('administration'))

@app.route("/client-logout")
def client_logout():
    session.pop('client_id', None)
    session.pop('client_scan_id', None)
    return redirect(url_for('client_login'))

@app.route("/delete-client-user/<int:client_id>", methods=["POST"])
@login_required
def delete_client_user(client_id):
    client = ClientUser.query.get_or_404(client_id)
    db.session.delete(client)
    db.session.commit()

    flash("Client user deleted successfully", "success")
    return redirect(url_for('administration'))

# Routes for User Authentication
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("index"))
        else:
            flash("Invalid credentials, please try again.", "error")

    return render_template("login.html")
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        username = secure_filename(username)

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for('administration'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists, please choose another.")
            return redirect(url_for('administration'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successfully completed!")
        return redirect(url_for("administration"))

    

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))

# Main Penetration Testing Tool Route
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        target = request.form.get("target")
        if not target:
            flash("Target is required.")
            return render_template("index.html")
        

        ip_pattern = r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$"

        if not re.match(ip_pattern, target) and not re.match(domain_pattern, target):
            flash("Please enter a valid IP Address or Domain!", "error")
            return render_template("index.html")

        if not is_target_up(target):
            return render_template("index.html", message=f"Target {target} is down.", target=target)

        nmap_output = run_nmap_scan(target)
        if not nmap_output:
            return render_template("index.html", message="Failed to get Nmap scan results.", target=target)

        os_name = parse_os(nmap_output)
        services = parse_nmap_services(nmap_output)

        vuln_scan_output = run_vuln_scan(target)
        cves = parse_vuln_scan(vuln_scan_output) if vuln_scan_output else []

        results = {}
        for port, service in services:
            exploits = search_exploits(service, os_name)
            if exploits:
                results[service] = exploits

        gobuster_results = run_gobuster(target)
        new_scan = ScanResult(
            user_id=current_user.id,
            target=target,
            os_name=os_name,
            services=json.dumps(services),
            exploits=json.dumps(results),  # results is the exploits dict
            cves=json.dumps(cves)
        )
        db.session.add(new_scan)
        db.session.commit()


        return render_template("index.html", 
                            message=None, 
                            target=target, 
                            os_name=os_name, 
                            services=services, 
                            exploits=results, 
                            gobuster_results=gobuster_results, 
                            cves=cves, 
                            username=current_user.username)

    return render_template("index.html", username=current_user.username)

# Route for Nikto command execution
import urllib.parse
import re
import subprocess
from flask import flash, render_template

@app.route("/nikto", methods=["GET", "POST"])
@login_required
def nikto():
    output_lines = []
    if request.method == "POST":
        command = request.form.get("command")
        if not command:
            flash("Nikto command is required.", "error")
            return render_template("nikto.html")

        # Decode any URL-encoded characters
        try:
            decoded_command = urllib.parse.unquote(command)
            if decoded_command != command:
                flash("URL encoded characters are not allowed", "error")
                return render_template("nikto.html")
            command = decoded_command
        except:
            flash("Invalid characters detected", "error")
            return render_template("nikto.html")

        # Check for newlines, carriage returns, or any escape sequences
        if re.search(r'[\r\n\t\v\f\0]', command):
            flash("Line breaks and control characters are not allowed", "error")
            return render_template("nikto.html")

        # only allow nikto with specific parameters
        valid_nikto_pattern = r"^nikto\s+(-[h|u|T|p|v|x|F]\s+[a-zA-Z0-9\.\-\_\/\:]+\s*)*$"
        disallowed_chars = r"[\|\&\;\`]"  

        if not re.match(valid_nikto_pattern, command) or re.search(disallowed_chars, command):
            flash("Invalid Nikto command! Please ensure only valid parameters are used.", "error")
            return render_template("nikto.html")

        # Additional check for dangerous patterns
        danger_patterns = [
            r'[\|\&\;\`\$\(\)\{\}\[\]\<\>]',  # Shell special characters
            r'touch|wget|curl|bash|sh|python|perl|ruby|nc|ncat|telnet',  # Command names
            r'\/dev\/|\/etc\/|\/tmp\/|\/proc\/',  # Sensitive directories
            r'%(0A|0D|00)'  # URL encoded newlines and null bytes
        ]

        for pattern in danger_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                flash("Potentially dangerous command detected", "error")
                return render_template("nikto.html")

        try:
            # Run the Nikto command safely using subprocess with shell=False
            result = subprocess.run(command, shell=True, capture_output=True, text=True)

            # Save the output to a file
            with open(NIKTO_OUTPUT_FILE, "w") as f:
                f.write(result.stdout)

            # Read the saved file to display the result
            with open(NIKTO_OUTPUT_FILE, "r") as file:
                output_lines = file.readlines()

            flash("Nikto command executed successfully, output saved.")
            return render_template("nikto.html", output=output_lines)

        except Exception as e:
            flash(f"Error executing Nikto: {e}", "error")
            return render_template("nikto.html")

    return render_template("nikto.html", output=output_lines)


# Route to view the Nikto output after execution
@app.route("/view_nikto_output", methods=["GET", "POST"])
@login_required
def view_nikto_output():
    output_lines = []
    with open(NIKTO_OUTPUT_FILE, "r") as file:
        output_lines = file.readlines()

    if request.method == "POST":
        grep_term = request.form.get("grep_term")
        if grep_term:
            output_lines = [line for line in output_lines if grep_term in line]

    return render_template("view_nikto_output.html", output=output_lines)

def run_gobuster(target):
    try:
        command = [
            "gobuster", "dir", "-u", f"http://{target}", "-w", WORDLIST_PATH_GOBUSTER, 
            "-t", "50", "-o", "gobuster_output.txt"
        ]
        subprocess.run(command, check=True)

        with open("gobuster_output.txt", "r") as file:
            output = file.readlines()

        directories = []
        for line in output:
            if line.strip() and "Dirs" not in line:
                parts = line.strip().split()
                if len(parts) > 1:
                    # Extract the status code and remove any ANSI escape sequences
                    status = re.sub(r'\x1b\[[0-9;]*m', '',  parts[3])  # Remove ANSI codes
                    status = status.replace(')', '')  # Remove the closing parenthesis
                    directories.append({"path": parts[0], "status": status})

        return directories
    except subprocess.CalledProcessError as e:
        print(f"Error running Gobuster: {e}")
        return []

# Exploit Execution Route
@app.route("/run_exploit", methods=["POST"])
@login_required
def run_exploit():
    target = request.form["target"]
    exploit_path = request.form["exploit_path"]

    try:
        # Start the shell process for interaction
        shell_processes[current_user.id] = subprocess.Popen(
            ["/bin/bash"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Execute the exploit
        execute_exploit(exploit_path, target)

        return jsonify({
            "message": f"Exploit {exploit_path} executed successfully!",
            "shell_url": url_for('shell_interaction')
        })

    except Exception as e:
        return jsonify({
            "error": f"Error executing exploit: {str(e)}"
        })


def execute_exploit(exploit_path, target):
    # Attempts to execute the selected exploit and start a shell session.
    global shell_processes  # Use the global shell_process dictionary
    # use exploit db to help us to find the exploits 
    full_exploit_path = os.path.join(EXPLOIT_DB_PATH, exploit_path)
    if not os.path.exists(full_exploit_path):
        return

    exploit_copy = f"./{os.path.basename(exploit_path)}"
    shutil.copy(full_exploit_path, exploit_copy)  # Copy exploit to local directory
    os.chmod(exploit_copy, 0o755)  # Ensure the file is executable

    if exploit_copy.endswith(".py"):
        command = ["python3", exploit_copy, target]
    elif exploit_copy.endswith(".pl"):
        command = ["perl", exploit_copy, target]
    elif exploit_copy.endswith(".sh"):
        command = ["bash", exploit_copy, target]
    elif exploit_copy.endswith(".c"):
        compile_cmd = ["gcc", exploit_copy, "-o", "compiled_exploit"]
        subprocess.run(compile_cmd, check=True)
        command = ["./compiled_exploit", target]
    else:
        return

    try:
        # Run the exploit
        subprocess.run(command, check=True)

        # Start a shell process after the exploit is executed
        shell_process = subprocess.Popen(
            ["/bin/bash"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        shell_processes[current_user.id] = shell_process  # Store the process by user
        print(f"Exploit {exploit_path} executed successfully, shell session started.")
    except subprocess.CalledProcessError:
        print(f"Error executing exploit {exploit_path}")
        return

# Shell Interaction Routes
@app.route('/shell-interaction-url')
@login_required
def shell_interaction():
    return render_template('shell_interaction.html')

@app.route('/send_command', methods=['POST'])
@login_required
def send_command():
    shell_process = shell_processes.get(current_user.id)
    if not shell_process:
        return jsonify({'error': 'Shell process not found'}), 400

    command = request.form['command']
    try:
        shell_process.stdin.write(command + "\n")
        shell_process.stdin.flush()

        output_lines = []
        while True:
            output = shell_process.stdout.readline()
            if not output:
                break
            output_lines.append(output.strip())

        return jsonify({'output': "\n".join(output_lines)}) if output_lines else jsonify({'error': 'No output received.'})
    except Exception as e:
        return jsonify({'error': f'Error executing command: {str(e)}'}), 500



@app.route("/virustotal", methods=["GET", "POST"])
@login_required
def virustotal():
    output_data = {}
    if request.method == "POST":
        # Get the user input
        user_input = request.form.get("input")
        if not user_input:
            flash("Input is required.", "error")
            return render_template("virustotal.html")

        # Validate input (accept only hash, IP, or URL)
        if not validate_input(user_input):
            flash("Invalid input! Only hash, IP, or URL are accepted.", "error")
            return render_template("virustotal.html")

        try:
            # Generate VirusTotal URL report based on input type (hash, URL, or IP)
            vt_url = get_virustotal_url_report(user_input)
            if vt_url:
                return render_template("virustotal.html", vt_url=vt_url)

            flash("Invalid format! Please provide a valid hash, IP, or URL.", "error")
            return render_template("virustotal.html")

        except Exception as e:
            flash(f"Error: {str(e)}", "error")
            return render_template("virustotal.html")
    
    return render_template("virustotal.html", output=output_data)


def validate_input(user_input):
    """
    Validates the user input to ensure it's a valid hash, IP, or URL format.
    """
    # Validate hash, IP, or URL
    return bool(
        re.match(r"^[a-fA-F0-9]{32}$", user_input) or
        re.match(r"^[a-fA-F0-9]{40}$", user_input) or
        re.match(r"^[a-fA-F0-9]{64}$", user_input) or
        re.match(r"^https?://", user_input) or
        re.match(r"^\d{1,3}(\.\d{1,3}){3}$", user_input)
    )


def get_virustotal_url_report(input_value):
    """
    Returns a direct URL for the VirusTotal report based on the input type (hash, URL, or IP).
    """
    if re.match(r"^[a-fA-F0-9]{32}$", input_value):  # MD5 Hash
        return f"https://www.virustotal.com/gui/file/{input_value}/detection"
    elif re.match(r"^[a-fA-F0-9]{40}$", input_value):  # SHA1 Hash
        return f"https://www.virustotal.com/gui/file/{input_value}/detection"
    elif re.match(r"^[a-fA-F0-9]{64}$", input_value):  # SHA256 Hash
        return f"https://www.virustotal.com/gui/file/{input_value}/detection"
    elif re.match(r"^https?://", input_value):  # URL
        # Hash the URL using SHA-256 before querying
        url_hash = hashlib.sha256(input_value.encode()).hexdigest()
        return f"https://www.virustotal.com/gui/url/{url_hash}/detection"
    elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", input_value):  # IP Address
        return f"https://www.virustotal.com/gui/ip-address/{input_value}/detection"
    else:
        return None
@app.route("/hashcat", methods=["GET", "POST"])
@login_required
def hashcat():
    output_lines = []  # To store the output lines
    wordlists = []
    cracked_pairs = []  # This will store the raw hash:password strings
    

    # List all wordlists in /usr/share/wordlists/seclists/Passwords
    wordlist_directory = "/home/kali/Desktop/GP2/2nd_drqasem_meeting/GP/Passwords"
    if os.path.exists(wordlist_directory):
        wordlists = [f for f in os.listdir(wordlist_directory) if os.path.isfile(os.path.join(wordlist_directory, f))]

    # Default Hashcat modes for algorithms
    hash_modes = {
        "0": "MD5",        # MD5
        "100": "SHA1",     # SHA1
        "1400": "SHA256"   # SHA256
    }

    if request.method == "POST":
        hash_value = request.form.get("hash")
        wordlist = request.form.get("wordlist", wordlists[0] if wordlists else "")  # Default to the first wordlist if available
        attack_mode = request.form.get("attack_mode", "0")  # Default attack mode is 0 (Straight)
        algorithm = request.form.get("algorithm", "0")  # Default is MD5

        if not hash_value:
            flash("Hash value is required.", "error")
            return render_template("hashcat.html", wordlists=wordlists)

        # Validate input hash
        if not validate_hash(hash_value):
            flash("Invalid hash format.", "error")
            return render_template("hashcat.html", wordlists=wordlists)

        # Get the selected Hashcat mode for the selected algorithm
        hash_mode = algorithm

        try:
            # Run Hashcat command with the selected hash mode
            hashcat_command = [
                "hashcat", "-m", hash_mode,  # Set hash mode dynamically
                "-a", attack_mode,  # Attack mode (0 for straight, 3 for brute-force, etc.)
                hash_value, os.path.join(wordlist_directory, wordlist)
            ]
            result = subprocess.run(hashcat_command, capture_output=True, text=True, check=True)

            # Parse the output
            cracked_pairs = parse_hashcat_output(result.stdout)


            # Check if Hashcat produced output
            if result.stdout:
                # Save the output to a file
                hashcat_output_file = "hashcat_output.txt"
                with open(hashcat_output_file, "w") as f:
                    f.write(result.stdout)
                
            

                # Read the saved file to display the result
                with open(hashcat_output_file, "r") as file:
                    output_lines = file.readlines()
                

                flash("Hashcat execution completed.", "success")
                
            else:
                flash("Hashcat did not produce any output. Please check the input or command.", "error")
            # Check if the hashes are in the potfile and show results
            if not result.stdout or "All hashes found as potfile" in result.stdout:
                # Use the --show flag to display cracked hashes from the potfile
                show_command = [
                    "hashcat", "--show", "-m", hash_mode, hash_value, os.path.join(wordlist_directory, wordlist)
                ]
                show_result = subprocess.run(show_command, capture_output=True, text=True, check=True)
                if show_result.stdout:
                    output_lines = show_result.stdout.splitlines()
                    flash("Hashcat found results in the potfile.", "info")

        except subprocess.CalledProcessError as e:
            flash(f"Error executing Hashcat: {e}", "error")

    return render_template("hashcat.html", output=output_lines, wordlists=wordlists)

@app.route("/scan-history")
@login_required
def scan_history():
    # Get all scans ordered by most recent
    all_scans = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    
    # Prepare data for template
    scans = []
    for scan in all_scans:
        scans.append({
            'id': scan.id,
            'username': scan.user.username,
            'target': scan.target,
            'os_name': scan.os_name,
            'timestamp': scan.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'services_count': len(json.loads(scan.services)) if scan.services else 0,
            'exploits_count': len(json.loads(scan.exploits)) if scan.exploits else 0,
            'cves_count': len(json.loads(scan.cves)) if scan.cves else 0
        })
    
    return render_template("scan_history.html", scans=scans, username=current_user.username)

# Add this route to view individual scan details
@app.route("/scan-details/<int:scan_id>")
@login_required
def scan_details(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    gobuster_results = []
    try:
        with open("gobuster_output.txt", "r") as file:
            output_lines = file.readlines()
        
        # Parse the Gobuster results
        for line in output_lines:
            if line.strip() and "Dirs" not in line:  # Skip header lines
                parts = line.strip().split()
                if len(parts) > 1:
                    # Extract the status code, remove ANSI escape sequences and the closing parenthesis ')'
                    status = re.sub(r'\x1b\[[0-9;]*m', '', parts[3])  # Remove ANSI codes
                    status = status.replace(')', '')  # Remove the closing parenthesis
                    gobuster_results.append({"path": parts[0], "status": status})
    except FileNotFoundError:
        gobuster_results = []    #Process data for charting and displaying
    services = json.loads(scan.services)
    cves = json.loads(scan.cves)

    # Classify CVEs based on their severity
    classified_cves = classify_cves_by_severity(cves)

    # Debug: Print out classified CVEs to ensure correct classification
    print("Classified CVEs: ", classified_cves)

    return render_template("scan_details.html", 
                         scan={
                             'id': scan.id,
                             'username': scan.user.username,
                             'target': scan.target,
                             'os_name': scan.os_name,
                             'services': services,
                             'exploits': json.loads(scan.exploits),
                             'cves': cves,
                             'timestamp': scan.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                         }, classified_cves=classified_cves, username=current_user.username, gobuster_results=gobuster_results)

# Make sure this route is within the app definition, below the other routes
@app.route("/download_report/<int:scan_id>")
@login_required
def download_report(scan_id):
    # Fetch the scan details from the database
    scan = ScanResult.query.get_or_404(scan_id)
    services = json.loads(scan.services)
    cves = json.loads(scan.cves)
    exploits = json.loads(scan.exploits)
    
    # Classify CVEs
    classified_cves = classify_cves_by_severity(cves)

    # Create a .docx document
    doc = Document()

    
    
    # Add Title and Executive Summary
    doc.add_heading('Pen-Test PRO Framework PT-Report', 0)

    # Add Confidentiality Notice and Disclaimer
    doc.add_heading('CONFIDENTIALITY NOTICE', level=1)
    doc.add_paragraph(
        "This report contains sensitive, privileged, and confidential information. "
        "Precautions should be taken to protect the confidentiality of the information in this "
        "document. Publication of this report may cause reputational damage to the client "
        "or facilitate attacks against the client. PT team shall not be held liable for special, "
        "incidental, collateral or consequential damages arising out of the use of this "
        "information.", style='Intense Quote'
    )
    
    doc.add_heading('DISCLAIMER', level=1)
    doc.add_paragraph(
        "Note that this assessment may not disclose all vulnerabilities that are present on "
        "the systems within the scope of the engagement. This report is a summary of the "
        "findings from a 'point-in-time' assessment made on the client's environment. Any "
        "changes made to the environment during the period of testing may affect the results "
        "of the assessment.", style='Intense Quote'
    )
    
    doc.add_page_break()

    doc.add_heading('TABLE OF CONTENTS', level=1)

    # Add paragraph style for TOC
    styles = doc.styles
    toc_style = styles.add_style('TOC_Entry', WD_STYLE_TYPE.PARAGRAPH)
    toc_style.font.size = Pt(12)  # Slightly larger than body text
    toc_style.font.name = 'Calibri'

    # Helper function to add TOC entries with hyperlinks
    def add_toc_entry(text, level=1, bookmark=None):
        p = doc.add_paragraph(style='TOC_Entry')
        p.paragraph_format.left_indent = Inches(0.25 * (level-1))
        
        if bookmark:
            # Create hyperlink to bookmark
            hyperlink = OxmlElement('w:hyperlink')
            hyperlink.set(qn('w:anchor'), bookmark)
            
            # Add the text run to the hyperlink
            run = p.add_run(text)
            hyperlink.append(run._r)
            p._p.append(hyperlink)
        else:
            p.add_run(text)
        return p

    # Helper function to add bookmarks to sections
    def add_bookmark(paragraph, bookmark_name):
        """Add start/end bookmark tags to a paragraph"""
        run = paragraph.add_run()
        start = OxmlElement('w:bookmarkStart')
        start.set(qn('w:id'), '0')
        start.set(qn('w:name'), bookmark_name)
        run._r.append(start)
        
        run = paragraph.add_run()
        end = OxmlElement('w:bookmarkEnd')
        end.set(qn('w:id'), '0')
        end.set(qn('w:name'), bookmark_name)
        run._r.append(end)

    # Add TOC entries with bookmarks - Corrected Version
    add_toc_entry("1. Executive Summary", 1, "exec_summary")
    add_toc_entry("   • Objective", 2, "objective")
    add_toc_entry("   • Scope", 2, "scope")

    add_toc_entry("2. Findings Summary", 1, "findings_summary")

    add_toc_entry("3. Vulnerability Assessment", 1, "vulnerability_assessment")

    add_toc_entry("4. Detailed Vulnerability Findings", 1, "detailed_findings")

    add_toc_entry("5. Discovered Exploits", 1, "discovered_exploits")

    add_toc_entry("6. Directory Brute-Force Results", 1, "gobuster_results")  # Fixed as subsection of 4

    add_toc_entry("7. Cyber Security Design Principles Evaluation", 1, "security_principles")
     
    add_toc_entry("8. CIAAAA Evaluation", 1, "ciaaaa_evaluation")

    add_toc_entry("9. Testing Methodology", 1, "testing_methodology")
    add_toc_entry("   • Reconnaissance", 2, "reconnaissance")
    add_toc_entry("   • Methodology", 2, "methodology_details")

    add_toc_entry("10. Conclusion", 1, "conclusion")
    doc.add_page_break()
        
    



     # Add Executive Summary section 
    exec_summary_para = doc.add_paragraph()
    add_bookmark(exec_summary_para, "exec_summary")
    doc.add_heading('1. Executive Summary', level=1)

    objective_para = doc.add_paragraph()
    add_bookmark(objective_para, "objective")
    doc.add_heading('a. Objective', level=2)
    doc.add_paragraph("The penetration test aimed to assess the security posture of the target environment by identifying vulnerabilities and potential exploits.")  # Add your objective text
    
    scope_para = doc.add_paragraph()
    add_bookmark(scope_para, "scope")
    doc.add_heading('b. Scope', level=2)
    
    # Add Scope description
    doc.add_paragraph("The test covered the following systems:")
    
    # Create the scope table
    scope_table = doc.add_table(rows=1, cols=2)
    scope_table.style = 'Table Grid'
    
    # Set table header
    hdr_cells = scope_table.rows[0].cells
    hdr_cells[0].text = 'IP-address'
    hdr_cells[1].text = 'Description'
    
    # Add target system row
    row_cells = scope_table.add_row().cells
    row_cells[0].text = scan.target  # This will use the scanned IP/domain
    row_cells[1].text = '-'

    doc.add_paragraph(f"Operating System: {scan.os_name}")
    doc.add_paragraph(f"Scan Date: {scan.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    
    

   # Findings Summary Section
    findings_para = doc.add_paragraph()
    add_bookmark(findings_para, "findings_summary")
    doc.add_heading('2. Findings Summary', level=1)

    # Create a table for Findings Summary
    findings_table = doc.add_table(rows=1, cols=4)
    findings_table.style = 'Table Grid'

    # Set column names for the table with colored backgrounds
    hdr_cells = findings_table.rows[0].cells

    # CRITICAL cell (Purple background, white text)
    critical_cell = hdr_cells[0]
    critical_cell.text = "CRITICAL"
    critical_cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)  # White text
    set_cell_background(critical_cell, "800080")  # Purple background

    # HIGH cell (Red background, white text)
    high_cell = hdr_cells[1]
    high_cell.text = "HIGH"
    high_cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)  # White text
    set_cell_background(high_cell, "FF0000")  # Red background

    # MEDIUM cell (Yellow background, black text)
    medium_cell = hdr_cells[2]
    medium_cell.text = "MEDIUM"
    medium_cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(0, 0, 0)  # Black text
    set_cell_background(medium_cell, "FFFF00")  # Yellow background

    # LOW cell (Green background, white text)
    low_cell = hdr_cells[3]
    low_cell.text = "LOW"
    low_cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)  # White text
    set_cell_background(low_cell, "00FF00")  # Green background

    #Add the severity counts from classified_cves (keep existing text colors)
    row_cells = findings_table.add_row().cells
    row_cells[0].text = str(len(classified_cves.get("Critical", [])))
    row_cells[1].text = str(len(classified_cves.get("High", [])))
    row_cells[2].text = str(len(classified_cves.get("Medium", [])))
    row_cells[3].text = str(len(classified_cves.get("Low", [])))

    # Add this right after your Findings Summary section
    vuln_para = doc.add_paragraph()
    add_bookmark(vuln_para, "vulnerability_assessment")
    doc.add_heading('3. Vulnerability Assessment', level=1)

    # Create a sorted list of vulnerabilities by severity
    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    sorted_cves = []

    for entry in cves:
        for cve in entry['cves']:
            cve_parts = cve.split()
            severity_score = float(cve_parts[1]) if len(cve_parts) > 1 else 0.0
            
            if severity_score >= 9.0:
                severity = "CRITICAL"
            elif severity_score >= 7.0:
                severity = "HIGH"
            elif severity_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            sorted_cves.append({
                'cve': f"CVE-{cve_parts[0]}" if len(cve_parts) > 0 else "Unknown",
                'service': entry['service'],
                'severity': severity,
                'score': severity_score
            })

    # Sort by severity (Critical first, Low last)
    sorted_cves.sort(key=lambda x: severity_order.index(x['severity']))

    # Create the assessment table
    assessment_table = doc.add_table(rows=1, cols=3)
    assessment_table.style = 'Table Grid'

    # Set column widths
    assessment_table.columns[0].width = Inches(3.5)  # Vulnerability
    assessment_table.columns[1].width = Inches(2.5)  # Targeted Host
    assessment_table.columns[2].width = Inches(1.5)  # Severity

    # Header row
    hdr_cells = assessment_table.rows[0].cells
    hdr_cells[0].text = 'Vulnerability'
    hdr_cells[1].text = 'Targeted Host'
    hdr_cells[2].text = 'Severity'

    # Add sorted vulnerabilities
    for vuln in sorted_cves:
        row_cells = assessment_table.add_row().cells
        row_cells[0].text = vuln['cve']
        row_cells[1].text = scan.target
        
        # Format severity cell
        severity_cell = row_cells[2]
        severity_cell.text = vuln['severity']
        
        # Set cell colors based on severity
        severity_colors = {
            'CRITICAL': ("800080", RGBColor(255, 255, 255)),  # Purple bg, white text
            'HIGH': ("FF0000", RGBColor(255, 255, 255)),      # Red bg, white text
            'MEDIUM': ("FFFF00", RGBColor(0, 0, 0)),          # Yellow bg, black text
            'LOW': ("00FF00", RGBColor(255, 255, 255))        # Green bg, white text
        }
        bg_color, text_color = severity_colors[vuln['severity']]
        set_cell_background(severity_cell, bg_color)
        severity_cell.paragraphs[0].runs[0].font.color.rgb = text_color


    detailed_para = doc.add_paragraph()
    add_bookmark(detailed_para, "detailed_findings")
    doc.add_heading('4. Detailed Vulnerability Findings', level=1)

    # Configure page layout
    section = doc.sections[0]
    section.page_width = Inches(8.5)  # Standard letter width
    section.page_height = Inches(11)  # Standard letter height
    section.left_margin = Inches(0.5)
    section.right_margin = Inches(0.5)


    #classify and sort vulnerabilities by severity
    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    sorted_vulnerabilities = []

    for entry in cves:
        for cve in entry['cves']:
            cve_parts = cve.split()
            cve_id = f"CVE-{cve_parts[0]}" if len(cve_parts) > 0 else "Unknown"
            severity_score = float(cve_parts[1]) if len(cve_parts) > 1 else 0.0
            
            if severity_score >= 9.0:
                severity = "CRITICAL"
            elif severity_score >= 7.0:
                severity = "HIGH"
            elif severity_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            sorted_vulnerabilities.append({
                'id': cve_id,
                'severity': severity,
                'score': severity_score,
                'service': entry['service']
            })

    # Sort vulnerabilities by severity (CRITICAL first, LOW last)
    sorted_vulnerabilities.sort(key=lambda x: severity_order.index(x['severity']))

    for entry in cves:
        for cve in entry['cves']:
            # Parse CVE details
            cve_parts = cve.split()
            cve_id = f"CVE-{cve_parts[0]}" if len(cve_parts) > 0 else "Unknown"
            severity_score = float(cve_parts[1]) if len(cve_parts) > 1 else 0.0
            
            # Determine severity level and color
            if severity_score >= 9.0:
                severity = "CRITICAL"
                color = "800080"  # Purple
            elif severity_score >= 7.0:
                severity = "HIGH"
                color = "FF0000"  # Red
            elif severity_score >= 4.0:
                severity = "MEDIUM"
                color = "FFFF00"  # Yellow
            else:
                severity = "LOW"
                color = "00FF00"  # Green

    # Create tables for each vulnerability
    for vuln in sorted_vulnerabilities:
        # Create table with appropriate width
        table = doc.add_table(rows=5, cols=2)
        table.style = 'Table Grid'
        table.alignment = WD_TABLE_ALIGNMENT.CENTER  # Center the table on page
        
        # Set table width to 90% of available space
        table.width = Inches(6.5)  # Adjusted for margins
        
        # Set column widths (30% for first column, 70% for second)
        for row in table.rows:
            row.cells[0].width = Inches(1.95)  # 30% of 6.5 inches
            row.cells[1].width = Inches(4.55)  # 70% of 6.5 inches
        
        # Header row with vulnerability ID and severity
        header_cells = table.rows[0].cells
        header_cells[0].text = vuln['id']
        header_cells[1].text = vuln['severity']
        
        # Set severity cell formatting
        severity_colors = {
            'CRITICAL': ("800080", RGBColor(255, 255, 255)),
            'HIGH': ("FF0000", RGBColor(255, 255, 255)),
            'MEDIUM': ("FFFF00", RGBColor(0, 0, 0)),
            'LOW': ("00FF00", RGBColor(255, 255, 255))
        }
        bg_color, text_color = severity_colors[vuln['severity']]
        set_cell_background(header_cells[1], bg_color)
        header_cells[1].paragraphs[0].runs[0].font.color.rgb = text_color
        
        # Description row
        desc_cells = table.rows[1].cells
        desc_cells[0].text = "Description"
        desc_cells[1].text = f"Vulnerability in {vuln['service']} service (CVSS: {vuln['score']:.1f}) - WRITE EXTRA INFROMATION HERE"
        
        # URLor IP row
        IP_cells = table.rows[2].cells
        IP_cells[0].text = "IP-address/URL"
        IP_cells[1].text = f"{scan.target}"
        
        # Recommendations row
        rec_cells = table.rows[3].cells
        rec_cells[0].text = "Recommendations"
        rec_cells[1].text = "-"
        
        # Evidence row
        evi_cells = table.rows[4].cells
        evi_cells[0].text = "Evidences"
        evi_cells[1].text = "-"
        
        # Add space after each table
        doc.add_paragraph("\n") 

    

    # Add space before next section
    doc.add_paragraph("\n")

        # Add this section after the Vulnerability Assessment section
    exploits_para = doc.add_paragraph()
    add_bookmark(exploits_para, "discovered_exploits")
    doc.add_heading('5. Discovered Exploits', level=1)

    if exploits:
        # Create exploits table
        exploits_table = doc.add_table(rows=1, cols=3)
        exploits_table.style = 'Table Grid'
        
        # Set column widths
        exploits_table.columns[0].width = Inches(1.5)  # Service
        exploits_table.columns[1].width = Inches(3.0)  # Exploit Title
        exploits_table.columns[2].width = Inches(2.0)  # Path
        
        # Header row
        header_cells = exploits_table.rows[0].cells
        header_cells[0].text = 'Service'
        header_cells[1].text = 'Exploit Title'
        header_cells[2].text = 'Path'
        
        # Add each exploit
        for service, exploit_list in exploits.items():
            for exploit in exploit_list:
                row_cells = exploits_table.add_row().cells
                row_cells[0].text = service
                row_cells[1].text = exploit.get('Title', 'N/A')
                
                # Format path to be more readable
                path = exploit.get('Path', '')
                if path.startswith(EXPLOIT_DB_PATH):
                    path = path[len(EXPLOIT_DB_PATH):]  # Remove base path
                row_cells[2].text = path
                
                # Highlight critical exploits
                if 'critical' in exploit.get('Title', '').lower():
                    for cell in row_cells:
                        set_cell_background(cell, "FFCCCB")  # Light red background
    else:
        doc.add_paragraph("No exploits were found during this assessment.", style='Intense Quote')

    doc.add_paragraph("\n")

    # Add Gobuster Results Section (before Discovered Exploits)
    gobuster_para = doc.add_paragraph()
    add_bookmark(gobuster_para, "gobuster_results")
    doc.add_heading('6 Directory Brute-Force Findings', level=1)
    doc.add_paragraph(
        "The following directories and files were discovered through brute-force scanning:",
        style='Intense Quote'
    )

    def sanitize_text(text):
        """Remove non-XML compatible characters from text"""
        # Remove ANSI escape sequences (used for color formatting in terminal)
        text = re.sub(r'\x1b\[[0-9;]*m', '', text)  # Remove ANSI escape codes
        
        # Remove any closing parenthesis ')' that might be attached to status codes
        text = text.replace(')', '')
        if not text:
            return ""
        # Remove NULL bytes and control characters
        text = "".join(char for char in text if ord(char) >= 32 or char in "\n\r\t")
        # Ensure text is properly encoded
        return text.encode('ascii', errors='ignore').decode('ascii')

    # Create table for Gobuster results
    gobuster_table = doc.add_table(rows=1, cols=3)
    gobuster_table.style = 'Table Grid'

    # Set column widths
    gobuster_table.columns[0].width = Inches(3.0)  # Path column
    gobuster_table.columns[1].width = Inches(1.5)  # Status column
    gobuster_table.columns[2].width = Inches(3.0)  # Full URL column

    # Header row
    hdr_cells = gobuster_table.rows[0].cells
    hdr_cells[0].text = 'Path'
    hdr_cells[1].text = 'Status'
    hdr_cells[2].text = 'Full URL'

    # Add Gobuster results to table
    try:
        with open("gobuster_output.txt", "r") as file:
            gobuster_results = file.readlines()
        
        for line in gobuster_results:
            if line.strip() and "Dirs" not in line:  # Skip header lines
                parts = line.strip().split()
                if len(parts) > 1:
                    path = sanitize_text(parts[0])
                    status = parts[3]  # Using parts[3] based on your output structure
                    status = sanitize_text(status)  # Clean any unwanted characters
                    
                    # Clean the status code, removing any ANSI escape sequences and the closing parenthesis ')'
                    status = re.sub(r'\x1b\[[0-9;]*[m|K]', '', status)  # Expanded regex to catch more sequences
                    status = status.replace(')', '')  # Remove the closing parenthesis
                    
                    # Add row to table
                    row_cells = gobuster_table.add_row().cells
                    row_cells[0].text = path
                    row_cells[1].text = status
                    
                    # Format status cell based on response code
                    if status.startswith('2'):
                        set_cell_background(row_cells[1], "00FF00")  # Green for 2xx
                    elif status.startswith('3'):
                        set_cell_background(row_cells[1], "FFFF00")  # Yellow for 3xx
                        row_cells[1].paragraphs[0].runs[0].font.color.rgb = RGBColor(0, 0, 0)  # Black text
                    elif status.startswith('4'):
                        set_cell_background(row_cells[1], "FFA500")  # Orange for 4xx
                    elif status.startswith('5'):
                        set_cell_background(row_cells[1], "FF0000")  # Red for 5xx
                    
                    # Add full URL
                    row_cells[2].text = sanitize_text(f"http://{scan.target}{path}")

    except FileNotFoundError:
        doc.add_paragraph("No directory brute-force results were found.", style='Intense Quote')
    except Exception as e:
        doc.add_paragraph(f"Error processing directory brute-force results: {str(e)}", style='Intense Quote')
    
    principles_para = doc.add_paragraph()
    add_bookmark(principles_para, "security_principles")
    doc.add_heading('7. Cyber Security Design Principles Evaluation ', level=1)
    # Add Cyber Security Design Principles Table
    principles = [
        "Least Common Mechanism", "Least Astonishment", "Least Privilege", "Separation of Privilege",
        "Isolation", "Encapsulation", "Open Design", "Economy of Mechanism", "Fail-safe defaults",
        "Complete Mediation", "Modularity", "Layering", "Psychological acceptability"
    ]

    

    table = doc.add_table(rows=1, cols=2)
    table.style = 'Table Grid'
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = 'Principle'
    hdr_cells[1].text = 'Score (out of 10)'


    for principle in principles:
        row = table.add_row().cells
        row[0].text = principle
        row[1].text = "N/A"  # Placeholder for evaluation score, can be adjusted
    
    # Add CIAAAA Evaluation Section (after Cyber Security Design Principles Evaluation)
    ciaaaa_para = doc.add_paragraph()
    add_bookmark(ciaaaa_para, "ciaaaa_evaluation")
    doc.add_heading('8. CIAAAA Evaluation', level=1)

    # Add Introduction text for CIAAAA Evaluation
    doc.add_paragraph(
        "This section provides the evaluation of the Confidentiality, Integrity, Availability, Accountability, Authorization, "
        "and Authentication principles applied in the system's security design.", style='Intense Quote'
    )

    # Create table for CIAAAA evaluation
    ciaaaa_table = doc.add_table(rows=1, cols=2)
    ciaaaa_table.style = 'Table Grid'

    # Set column widths
    ciaaaa_table.columns[0].width = Inches(3.0)  # Principle column
    ciaaaa_table.columns[1].width = Inches(3.5)  # Evaluation column

    # Header row
    hdr_cells = ciaaaa_table.rows[0].cells
    hdr_cells[0].text = 'Principle'
    hdr_cells[1].text = 'Evaluation'

    # List of CIAAAA principles with sample evaluations (you can update with actual evaluations)
    principles = [
        ("Confidentiality", "-"),
        ("Integrity", "-"),
        ("Availability", "-"),
        ("Accountability", "-"),
        ("Authorization", "-"),
        ("Authentication", "-")
    ]

    # Add the principles and their evaluations to the table
    for principle, evaluation in principles:
        row_cells = ciaaaa_table.add_row().cells
        row_cells[0].text = principle
        row_cells[1].text = evaluation
    
    # Add Testing Methodology section 
    methodology_para = doc.add_paragraph()
    add_bookmark(methodology_para, "testing_methodology")
    doc.add_heading('8. Testing Methodology', level=1)

    # Reconnaissance subsection
    recon_para = doc.add_paragraph()
    add_bookmark(recon_para, "reconnaissance")
    doc.add_heading('Reconnaissance', level=2)
    doc.add_paragraph("The reconnaissance phase involved the following activities:")
    recon_items = [
        "Network scanning using Nmap to identify open ports and services",
        "Service fingerprinting to determine versions and configurations",
        "Web application crawling to map the attack surface"
        "Vulnerability scanning using Nmap scripts and Vulners database"
    ]
    for item in recon_items:
        doc.add_paragraph(item, style='List Bullet')

    # Methodology subsection
    method_details_para = doc.add_paragraph()
    add_bookmark(method_details_para, "methodology_details")
    doc.add_heading('Methodology', level=2)
    doc.add_paragraph("The penetration testing methodology followed the NIST Testing Guide and uses ()-BOX methodology framework and included these phases:")
    methodology_steps = [
        "Planning and reconnaissance to identify the attack surface",
        "Vulnerability scanning and analysis",
        "Exploitation of identified vulnerabilities (where safe and authorized)",
        "Post-exploitation analysis to determine potential impact",
        "Reporting and remediation recommendations"
    ]
    for step in methodology_steps:
        doc.add_paragraph(step, style='List Bullet')

    doc.add_paragraph("\nTools used during the assessment:", style='Intense Quote')

    # Properly structured tools list with exactly 2 elements per tuple
    tools_used = [
        ("Nmap", "Network scanning and service enumeration"),
        ("Searchsploit", "Exploit database searching"),
        ("useexploit","run exploits manually via linux commands"),
        ("Nikto", "Web server vulnerability scanning"),
        ("Metasploit Framework", "Exploit development and testing"),
        ("Gobuster", "Directory and file brute-forcing"),
        ("Hashcat", "Password hash cracking"),
    ]

    try:
        tools_table = doc.add_table(rows=1, cols=2)
        tools_table.style = 'Table Grid'
        hdr = tools_table.rows[0].cells
        hdr[0].text = 'Tool'
        hdr[1].text = 'Purpose'
        
        for tool_info in tools_used:
            if len(tool_info) == 2:  # Ensure exactly 2 items
                row = tools_table.add_row().cells
                row[0].text = tool_info[0]
                row[1].text = tool_info[1]
            else:
                print(f"Skipping malformed tool entry: {tool_info}")
                
    except Exception as e:
        print(f"Error creating tools table: {str(e)}")
        # Fallback to bullet list if table creation fails
        doc.add_paragraph("Primary tools used:", style='Heading 3')
        for tool in tools_used:
            doc.add_paragraph(f"{tool[0]}: {tool[1]}", style='List Bullet')

    # Add Conclusion section
    doc.add_page_break()
    conclusion_para = doc.add_paragraph()
    add_bookmark(conclusion_para, "conclusion")
    doc.add_heading('9. Conclusion', level=1)
    doc.add_paragraph("The penetration test revealed several security vulnerabilities that could potentially compromise the target system. The most critical findings include:", style='Intense Quote')

    # Summary of critical findings
    critical_findings = [
        f"{len(classified_cves['Critical'])} Critical vulnerabilities requiring immediate attention",
        f"{len(classified_cves['High'])} High risk vulnerabilities that should be patched promptly",
        f"{len(exploits)} exploitable services with publicly available exploits",
        f"{len(services)} services identified with potential security issues"
    ]
    for finding in critical_findings:
        doc.add_paragraph(finding, style='List Bullet')

    doc.add_paragraph("\nRecommendations for immediate action:", style='Heading 3')
    recommendations = [
        "Prioritize patching Critical and High severity vulnerabilities immediately",
        "Implement input validation and output encoding for all web applications",
        "Harden system configurations following CIS benchmarks",
        "Establish a regular patch management cycle",
        "Conduct quarterly security assessments and penetration tests",
        "Provide security awareness training for all technical staff",
        "Implement Web Application Firewall (WAF) protection"
    ]
    for rec in recommendations:
        doc.add_paragraph(rec, style='List Bullet')

    doc.add_paragraph("\nNext steps:", style='Heading 3')
    next_steps = [
        "Review all findings with the security team",
        "Develop remediation timeline based on risk priorities",
        "Schedule retesting after remediation",
        "Consider implementing continuous security monitoring"
    ]
    for step in next_steps:
        doc.add_paragraph(step, style='List Bullet')

    doc.add_paragraph("\nThis concludes the penetration test report. For any clarification or additional information, please contact the security team.", style='Intense Quote')


    # Save to in-memory file
    report_stream = BytesIO()
    doc.save(report_stream)
    report_stream.seek(0)

    # Send file for download
    return send_file(report_stream, as_attachment=True, download_name=f"scan_report_{scan_id}.docx", mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False, threaded=True)
