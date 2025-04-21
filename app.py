import os
import re
import ssl
import csv
import time
import uuid
import gridfs
import secrets
import mimetypes
import dns.resolver
from bs4 import BeautifulSoup
from datetime import datetime
from dotenv import load_dotenv
from pymongo import MongoClient
from flask_ckeditor import CKEditor
from urllib.parse import quote_plus
from flask_mail import Mail, Message
from email.mime.image import MIMEImage
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, flash, jsonify, send_from_directory



# Load environment variables
load_dotenv()
ssl_context = ssl.create_default_context()

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
ckeditor = CKEditor(app)


# Config from .env
SENDER_EMAIL = os.getenv("EMAIL_SENDER")
SENDER_USERNAME = os.getenv("EMAIL_USERNAME")
SENDER_PASSWORD = os.getenv("EMAIL_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
WAIT_TIME = int(os.getenv("WAIT_TIME", 300))
SENDER_NAME = os.getenv("EMAIL_NAME")

app.config.update(
    MAIL_SERVER=SMTP_SERVER,
    MAIL_PORT=SMTP_PORT,
    MAIL_USERNAME=SENDER_USERNAME,
    MAIL_PASSWORD=SENDER_PASSWORD,
    MAIL_USE_TLS=True,
    MAIL_DEFAULT_SENDER=SENDER_EMAIL,
    UPLOAD_FOLDER='uploads',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    CKEDITOR_SERVE_LOCAL=True,
    CKEDITOR_HEIGHT=400
)


uri = "mongodb+srv://Rajkachhadiya:<db_password>@cluster0.jmquj1y.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

MONGO_USER = os.getenv("MONGO_USER")
MONGO_PASS = quote_plus(os.getenv("MONGO_PASS"))  # encode special chars like @ or $
MONGO_CLUSTER = os.getenv("MONGO_CLUSTER")
MONGO_DBNAME = os.getenv("MONGO_DBNAME")
MONGO_APPNAME = os.getenv("MONGO_APPNAME", "MyApp")

mongo_uri = f"mongodb+srv://{MONGO_USER}:{MONGO_PASS}@{MONGO_CLUSTER}/?retryWrites=true&w=majority&appName={MONGO_APPNAME}"
client = MongoClient(mongo_uri)
db = client[MONGO_DBNAME]
fs = gridfs.GridFS(db)

db = client["Cluster0"]            # you can change the DB name if you like
fs = gridfs.GridFS(db)              # GridFS handles large files

@app.route("/files")
def list_files():
    return "<br>".join([file.filename for file in fs.find()])

@app.route("/api/mongo-status")
def mongo_status():
    try:
        db.list_collection_names()  # simple check
        return jsonify({"status": "connected"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/test-mongo")
def test_mongo():
    try:
        db.list_collection_names()  # simple check
        return "✅ MongoDB is connected!"
    except Exception as e:
        return f"❌ MongoDB error: {e}"


mail = Mail(app)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'zip', 'avif', 'ico', 'heic', 'webp', 'txt', 'xlsx', 'csv', 'pptx'}

INVALID_MAILS_PATH = "Invalid_mails.csv"
REPORTS_DIR = "reports"
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
report_filename = os.path.join(REPORTS_DIR, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def strip_tags(html):
    return BeautifulSoup(html, "html.parser").get_text()

def remove_tracking_pixels(html):
    soup = BeautifulSoup(html, 'html.parser')
    for img in soup.find_all('img'):
        if 'display:none' in str(img).lower() or '1px' in str(img).lower():
            img.decompose()
    return str(soup)

def is_valid_format(email):
    pattern = r'^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def has_valid_domain(email):
    try:
        domain = email.split('@')[-1]
        answers = dns.resolver.resolve(domain, 'MX')
        return len(answers) > 0
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.NoNameservers:
        return False
    except Exception:
        return False

def is_valid_email(email):
    if not is_valid_format(email):
        return False, "Invalid format"
    if not has_valid_domain(email):
        return False, "Invalid domain"
    return True, ""

def load_invalid_emails():
    if not os.path.exists(INVALID_MAILS_PATH):
        return set()
    with open(INVALID_MAILS_PATH, 'r', encoding='utf-8') as f:
        return set(line.split(',')[1].strip() for line in f if line.strip() and not line.startswith("Date-Time"))

def save_invalid_email(email, reason):
    existing = load_invalid_emails()
    if email in existing:
        return
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    write_header = not os.path.exists(INVALID_MAILS_PATH) or os.stat(INVALID_MAILS_PATH).st_size == 0
    with open(INVALID_MAILS_PATH, 'a', encoding='utf-8') as f:
        if write_header:
            f.write("Date-Time,To,Status,Failed Reason,Time Taken\n")
        f.write(f"{now},{email},Failed,{reason},0\n")

def remove_invalid_email(email):
    if not os.path.exists(INVALID_MAILS_PATH):
        return
    with open(INVALID_MAILS_PATH, 'r', encoding='utf-8') as f:
        lines = [line for line in f if email not in line]
    with open(INVALID_MAILS_PATH, 'w', encoding='utf-8') as f:
        f.writelines(lines)

def save_report(timestamp, sender, to, cc, subject, html_message, status, reason, taken):
    write_header = not os.path.exists(report_filename) or os.stat(report_filename).st_size == 0
    with open(report_filename, 'a', encoding='utf-8') as f:
        if write_header:
            f.write("Date-Time,Send mail address,To,cc,subject,message,status,failed reason,time taken\n")
        message_preview = strip_tags(html_message).replace('\n', ' ').strip().replace(',', ';')[:200]
        f.write(f"{timestamp},{sender},{to or ''},{cc or ''},{subject or ''},{message_preview},{status},{reason},{taken:.2f}s\n")

def get_emails_from_csv(path):
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        return [(row[0].strip(), row[1].strip() if len(row) > 1 else None) for row in reader if row]


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        form_subject = request.form['subject'].strip()
        raw_html = request.form['ckeditor']
        message = remove_tracking_pixels(raw_html)
        from_email = request.form.get('from_email', SENDER_EMAIL)
        from_display = (SENDER_NAME, from_email) # For user name show

        cc_raw = request.form.get('cc_emails', '')
        cc_emails = [c.strip() for c in cc_raw.split(',') if c.strip()]
        wait_input = int(request.form.get('wait_time', 0))
        wait_time = WAIT_TIME if wait_input == 0 else wait_input

        uploaded_file = request.files.get('recipients')
        attachments = request.files.getlist('file')

        emails_data = []
        if uploaded_file and uploaded_file.filename.endswith('.csv'):
            uploaded_file.save("emails.csv")
            emails_data = get_emails_from_csv("emails.csv")
        else:
            inline_emails = request.form['emails']
            emails_data = [(e.strip(), form_subject) for e in inline_emails.split(',') if e.strip()]

        invalid_emails = load_invalid_emails()
        batch_counter = 0

        with mail.connect() as conn:
            for i, (to_email, subj) in enumerate(emails_data):
                start = time.time()
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                final_subject = subj or form_subject or ''
                valid_to = []
                invalid_to = []
                valid_cc = []
                invalid_cc = []

                # Validate TO
                if to_email:
                    if to_email in invalid_emails:
                        invalid_to.append((to_email, 'Previously invalid'))
                    else:
                        valid, reason = is_valid_email(to_email)
                        if valid:
                            valid_to.append(to_email)
                            remove_invalid_email(to_email)
                        else:
                            save_invalid_email(to_email, reason)
                            invalid_to.append((to_email, reason))

                # Validate CC
                for cc in cc_emails:
                    if cc in invalid_emails:
                        invalid_cc.append((cc, 'Previously invalid'))
                    else:
                        valid, reason = is_valid_email(cc)
                        if valid:
                            valid_cc.append(cc)
                            remove_invalid_email(cc)
                        else:
                            save_invalid_email(cc, reason)
                            invalid_cc.append((cc, reason))

                # Send if valid TO or CC
                if valid_to or valid_cc:
                    try:
                        msg = Message(
                            subject=final_subject,
                            recipients=valid_to or [],
                            cc=valid_cc or [],
                            sender=from_display
                        )

                        # Inline images
                        image_cid_map = {}
                        img_tags = re.findall(r'<img[^>]+src="(/uploads/[^">]+)"', message)
                        for idx, img_src in enumerate(img_tags):
                            full_path = os.path.join(os.getcwd(), img_src.lstrip('/'))
                            if os.path.exists(full_path):
                                cid = f"img{idx}@mail"
                                image_cid_map[img_src] = cid
                                with open(full_path, 'rb') as f:
                                    mime_img = MIMEImage(f.read())
                                    mime_img.add_header('Content-ID', f'<{cid}>')
                                    mime_img.add_header('Content-Disposition', 'inline', filename=os.path.basename(full_path))
                                    msg.attach(mime_img)
                        for src, cid in image_cid_map.items():
                            message = message.replace(f'src="{src}"', f'src="cid:{cid}"')

                        msg.body = strip_tags(message)
                        msg.html = message

                        uploaded_to_mongo = []

                        for file in attachments:
                            if allowed_file(file.filename):
                                filename = secure_filename(file.filename)
                                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                                file.save(filepath)

                                if not fs.exists({"filename": filename}):
                                    with open(filepath, 'rb') as f:
                                        fs.put(f, filename=filename)
                                    uploaded_to_mongo.append(filename)

                                with open(filepath, 'rb') as f:
                                    data = f.read()
                                    mime_type = mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
                                    msg.attach(filename, mime_type, data)

                        conn.send(msg)
                        taken = time.time() - start
                        flash(f"✅ Sent to: {', '.join(valid_to + valid_cc)}", 'success')

                        if uploaded_to_mongo:
                            flash(f"MONGO_UPLOAD::{','.join(uploaded_to_mongo)}", "mongo_status")

                        for vt in valid_to:
                            save_report(timestamp, from_email, vt, '', final_subject, message, 'Success', '', taken)
                        for vc in valid_cc:
                            save_report(timestamp, from_email, '', vc, final_subject, message, 'Success', '', taken)

                    except Exception as e:
                        taken = time.time() - start
                        flash(f"⚠️ Failed to send: {e}", 'danger')
                        for vt in valid_to:
                            save_invalid_email(vt, str(e))
                            save_report(timestamp, from_email, vt, '', final_subject, message, 'Failed', str(e), taken)
                        for vc in valid_cc:
                            save_invalid_email(vc, str(e))
                            save_report(timestamp, from_email, '', vc, final_subject, message, 'Failed', str(e), taken)

                # Log invalid TOs
                for it, reason in invalid_to:
                    flash(f"❌ TO invalid: {it} - {reason}", 'danger')
                    save_report(timestamp, from_email, it, '', final_subject, message, 'Failed', reason, 0)

                # Log invalid CCs
                for ic, reason in invalid_cc:
                    flash(f"❌ CC invalid: {ic} - {reason}", 'danger')
                    save_report(timestamp, from_email, '', ic, final_subject, message, 'Failed', reason, 0)

                batch_counter += 1
                if batch_counter % 15 == 0 and len(emails_data) > 15:
                    flash("⌛ Waiting before next batch...", 'info')
                    time.sleep(wait_time)

        flash("🎉 Processing Complete", 'success')
        return redirect('/')

    return render_template('index.html', sender_email=SENDER_EMAIL, wait_time=WAIT_TIME)


@app.route('/upload-image', methods=['POST'])
def upload_image():
    incoming_file = request.files.get('file') or request.files.get('upload')
    if not incoming_file:
        return jsonify({'error': 'No file uploaded'}), 200
    if not allowed_file(incoming_file.filename):
        return jsonify({'error': 'Invalid file type'}), 400
    fname = f"{uuid.uuid4().hex}_{secure_filename(incoming_file.filename)}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], fname)
    incoming_file.save(filepath)
    return jsonify({'fileName': fname, 'url': f'/uploads/{fname}'})

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
