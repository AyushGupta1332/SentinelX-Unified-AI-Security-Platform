from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash, g, send_file
from flask_socketio import SocketIO
from flask_cors import CORS
import threading
import time
import pandas as pd
import numpy as np
import pickle
from collections import deque
import os
import subprocess
import warnings
from pathlib import Path
import re
import json
import logging
import sqlite3
import io
import base64
from datetime import datetime
from urllib.parse import urlparse
warnings.filterwarnings('ignore')

# Phishing Detection imports
try:
    import yara
    import tldextract
    from langdetect import detect
    from bs4 import BeautifulSoup
    from PIL import Image
    import PyPDF2
    from docx import Document
    from body_classifier import predict_body_label
    from google_auth_oauthlib.flow import Flow
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build
    from google.auth.transport.requests import Request
    import requests as http_requests  # renamed to avoid conflict
    PHISHING_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some phishing detection dependencies not available: {e}")
    PHISHING_AVAILABLE = False

app = Flask(__name__, template_folder='template', static_folder='static')
app.config['SECRET_KEY'] = 'your-secret-key-here'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables - Anomaly Detection
monitoring_active = False
traffic_gen_process = None
monitor_thread = None
prediction_queue = deque(maxlen=100)
stats = {
    'total_samples': 0,
    'normal_count': 0,
    'anomaly_count': 0,
    'accuracy': 0.0
}

# Track last processed row count
last_processed_rows = 0

# Global variables - Data Classification
scanning_active = False
scan_thread = None
classification_results = []
classification_stats = {
    'total_files': 0,
    'sensitive_count': 0,
    'non_sensitive_count': 0
}

# ========== PHISHING DETECTION CONFIGURATION ==========
# YARA configuration
app.config['YARA_RULES_DIR'] = os.path.join(os.path.dirname(__file__), 'awesome-yara', 'rules')
app.config['TEMP_DIR'] = os.path.join(os.getcwd(), 'temp')
app.config['PHISHING_DB'] = os.path.join(os.path.dirname(__file__), 'phishing_emails.db')

# Load trusted domains
TRUSTED_CSV_PATH = os.path.join(os.path.dirname(__file__), "top-1m.csv")
trusted_set = set()

PUBLIC_EMAIL_PROVIDERS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com',
    'aol.com', 'icloud.com', 'mail.com', 'protonmail.com', 'yandex.com'
}

# Load trusted domains from CSV
if PHISHING_AVAILABLE:
    try:
        df = pd.read_csv(TRUSTED_CSV_PATH, header=None)
        trusted_set = set(str(x).strip().lower() for x in df[0].dropna() 
                         if str(x).strip().lower() not in PUBLIC_EMAIL_PROVIDERS)
        logger.info(f"Loaded {len(trusted_set)} trusted entries from {TRUSTED_CSV_PATH}")
    except Exception as e:
        logger.warning(f"Could not load trusted domains: {e}")
        trusted_set = set()

# YARA rules initialization
yara_rules = None

def initialize_yara_rules():
    global yara_rules
    if not PHISHING_AVAILABLE:
        return
    rules_dir = app.config['YARA_RULES_DIR']
    if not os.path.exists(rules_dir):
        logger.warning(f"YARA rules directory not found: {rules_dir}")
        yara_rules = None
        return
    try:
        rule_files = []
        for root, dirs, files in os.walk(rules_dir):
            for file in files:
                if file.endswith(('.yar', '.yara')):
                    rule_path = os.path.join(root, file)
                    try:
                        with open(rule_path, 'r') as f:
                            content = f.read()
                            yara.compile(source=content)
                        rule_files.append((os.path.splitext(os.path.basename(file))[0], rule_path))
                    except Exception as e:
                        continue
        if rule_files:
            yara_rules = yara.compile(filepaths={rule_name: rule_path for rule_name, rule_path in rule_files})
            logger.info(f"YARA rules loaded: {len(rule_files)} rule files")
    except Exception as e:
        logger.warning(f"Error loading YARA rules: {e}")
        yara_rules = None

# Initialize phishing database
def init_phishing_db():
    conn = sqlite3.connect(app.config['PHISHING_DB'])
    conn.execute('''
        CREATE TABLE IF NOT EXISTS Email (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT,
            sender TEXT,
            receiver TEXT,
            subject TEXT,
            body TEXT,
            category TEXT,
            confidence_score REAL,
            needs_review INTEGER DEFAULT 0,
            explanation TEXT,
            features TEXT,
            urls TEXT,
            provider TEXT,
            user_email TEXT,
            received_date INTEGER,
            has_feedback INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS Attachment (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            data BLOB,
            email_id INTEGER,
            sensitivity TEXT,
            content_type TEXT,
            yara_result TEXT,
            FOREIGN KEY (email_id) REFERENCES Email(id)
        )
    ''')
    conn.commit()
    conn.close()

# ========== SINGLE DATABASE FOR ALL USERS ==========
FEEDBACK_DB_PATH = os.path.join(os.path.dirname(__file__), 'feedback.db')

def get_phishing_db_connection():
    """Get a connection to the main phishing emails database"""
    conn = sqlite3.connect(app.config['PHISHING_DB'])
    conn.row_factory = sqlite3.Row
    return conn

# Initialize feedback database
def init_feedback_db():
    """Initialize the unified feedback database"""
    conn = sqlite3.connect(FEEDBACK_DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS Feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id INTEGER,
            user_email TEXT,
            provider TEXT,
            original_category TEXT,
            corrected_category TEXT,
            feedback_reason TEXT,
            email_subject TEXT,
            email_sender TEXT,
            email_body_preview TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    logger.info(f"Initialized feedback database: {FEEDBACK_DB_PATH}")

# Initialize databases on startup
init_feedback_db()

if PHISHING_AVAILABLE:
    init_phishing_db()
    initialize_yara_rules()

# ========== GOOGLE & OUTLOOK API CONFIGURATION ==========
# Google Gmail API credentials from environment variables
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI', 'http://127.0.0.1:5000/phishing/callback')
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Outlook API credentials from environment variables
OUTLOOK_CLIENT_ID = os.environ.get('OUTLOOK_CLIENT_ID')
OUTLOOK_CLIENT_SECRET = os.environ.get('OUTLOOK_CLIENT_SECRET')
OUTLOOK_REDIRECT_URI = os.environ.get('OUTLOOK_REDIRECT_URI', 'http://localhost:5000/phishing/callback_outlook')
OUTLOOK_SCOPES = ['https://graph.microsoft.com/Mail.Read']

def get_google_client_config():
    """Build Google OAuth client config dynamically from environment variables"""
    return {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [GOOGLE_REDIRECT_URI]
        }
    }

def build_gmail_service(credentials):
    """Build Gmail API service"""
    return build('gmail', 'v1', credentials=credentials)

def clean_preview_text(html_content, max_length=200):
    """Clean HTML content for preview"""
    if not html_content:
        return ""
    soup = BeautifulSoup(html_content, 'html.parser')
    for tag in soup.find_all(True):
        tag.unwrap()
    text = soup.get_text(separator=' ', strip=True)
    text = ' '.join(text.split())
    if len(text) > max_length:
        text = text[:max_length] + "..."
    return text

def extract_text_from_pdf(pdf_data):
    """Extract text from PDF data."""
    text = ''
    reader = PyPDF2.PdfReader(io.BytesIO(pdf_data))
    for page in reader.pages:
        page_text = page.extract_text()
        if page_text:
            text += page_text + '\n'
    return text

def extract_text_from_docx(docx_data):
    """Extract text from DOCX data."""
    doc = Document(io.BytesIO(docx_data))
    return "\n".join([para.text for para in doc.paragraphs])

def classify_text_attachment(text):
    """Classify text content as sensitive or non-sensitive."""
    try:
        if not text or text.strip() == '':
            return 'non-sensitive'
        # Use document classifier if available
        try:
            from phishing_document_classifier import classify_text_content
            return classify_text_content(text)
        except:
            return 'non-sensitive'
    except Exception as e:
        logger.error(f"Error classifying text attachment: {e}")
        return 'non-sensitive'

def classify_image_attachment(image_data):
    """Classify image content as sensitive or non-sensitive using CNN."""
    try:
        if not PHISHING_AVAILABLE:
            return 'non-sensitive'
        image = Image.open(io.BytesIO(image_data))
        if image.mode == 'RGBA':
            image = image.convert('RGB')
        image = image.resize((148, 148))
        image_array = np.array(image) / 255.0
        image_array = np.expand_dims(image_array, axis=0)
        # Load image model
        image_model_path = os.path.join(os.path.dirname(__file__), 'image_model.h5')
        if os.path.exists(image_model_path):
            import tensorflow as tf
            image_model = tf.keras.models.load_model(image_model_path)
            prediction = image_model.predict(image_array)
            sensitivity = 'sensitive' if prediction[0] > 0.5 else 'non-sensitive'
            return sensitivity
        return 'non-sensitive'
    except Exception as e:
        logger.error(f"Error classifying image attachment: {e}")
        return 'non-sensitive'

def process_gmail_message(service, message_id):
    """Process a Gmail message and extract data for classification."""
    try:
        msg = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        headers = {h['name']: h['value'] for h in msg['payload']['headers']}
        sender = headers.get('From', 'Unknown Sender')
        if not re.search(r'[\w\.-]+@[\w\.-]+\.\w+', sender):
            sender = 'unknown@unknown.com'
        receiver = headers.get('To', 'Unknown Receiver')
        subject = headers.get('Subject', 'No Subject')

        attachments = []
        body = ""
        html_content = None
        plain_content = None

        # Process message parts
        parts_to_process = [msg['payload']]
        while parts_to_process:
            part = parts_to_process.pop(0)
            mime_type = part.get('mimeType', '')

            if 'parts' in part:
                parts_to_process = part['parts'] + parts_to_process
                continue

            if mime_type == 'text/html':
                if 'data' in part['body']:
                    html_content = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
            elif mime_type == 'text/plain':
                if 'data' in part['body'] and not html_content:
                    plain_content = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')

            # Attachments
            if part.get('filename'):
                if part['body'].get('attachmentId'):
                    att_id = part['body']['attachmentId']
                    att = service.users().messages().attachments().get(
                        userId='me', messageId=message_id, id=att_id
                    ).execute()
                    data = base64.urlsafe_b64decode(att['data'])
                    file_type = part.get('mimeType')
                    sensitivity = 'non-sensitive'
                    if file_type and file_type.startswith('image/'):
                        sensitivity = classify_image_attachment(data)
                    elif file_type == 'application/pdf':
                        text = extract_text_from_pdf(data)
                        sensitivity = classify_text_attachment(text)
                    elif file_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                        text = extract_text_from_docx(data)
                        sensitivity = classify_text_attachment(text)
                    elif file_type == 'text/plain':
                        text = data.decode('utf-8', errors='ignore')
                        sensitivity = classify_text_attachment(text)

                    attachments.append({
                        'filename': part['filename'],
                        'data': data,
                        'sensitivity': sensitivity,
                        'content_type': file_type
                    })

        # Fallback for simple emails
        if not (html_content or plain_content) and msg['payload'].get('body', {}).get('data'):
            body_data = msg['payload']['body']['data']
            plain_content = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')

        # Clean body
        if html_content:
            soup = BeautifulSoup(html_content, 'html.parser')
            for tag in soup.find_all(['script', 'style', 'link', 'meta']):
                tag.decompose()
            body = soup.get_text(separator=' ', strip=True)
        elif plain_content:
            body = plain_content
        body = ' '.join(body.split())
        if body.startswith(subject):
            body = body[len(subject):].strip()

        urls = extract_and_classify_urls(subject, body)
        category, confidence, explanation, needs_review, features = classify_email(message_id, sender, subject, body, attachments)

        return {
            'message_id': message_id,
            'sender': sender,
            'receiver': receiver,
            'subject': subject,
            'body': body,
            'category': category,
            'confidence_score': confidence,
            'explanation': explanation,
            'needs_review': needs_review,
            'features': features,
            'attachments': attachments,
            'urls': urls
        }
    except Exception as e:
        logger.error(f"Error processing Gmail message {message_id}: {str(e)}")
        return None

def process_outlook_email(email):
    """Process an Outlook email and extract data for classification."""
    try:
        sender = email['from']['emailAddress']['address'] if 'from' in email and 'emailAddress' in email['from'] else 'Unknown Sender'
        if not re.search(r'[\w\.-]+@[\w\.-]+\.\w+', sender):
            sender = 'unknown@unknown.com'
        receiver = email['toRecipients'][0]['emailAddress']['address'] if 'toRecipients' in email and email['toRecipients'] else 'Unknown Receiver'
        subject = email.get('subject', 'No Subject')
        body = email.get('body', {}).get('content', '')

        soup = BeautifulSoup(body, 'html.parser')
        for tag in soup.find_all(['style', 'script']):
            tag.decompose()
        body = soup.get_text(separator=' ', strip=True)
        body = ' '.join(body.split())
        if body.startswith(subject):
            body = body[len(subject):].strip()

        urls = extract_and_classify_urls(subject, body)

        # Process attachments
        attachments = []
        if 'attachments' in email:
            for attachment in email['attachments']:
                att_data = base64.b64decode(attachment.get('contentBytes', ''))
                content_type = attachment.get('contentType', '')
                sensitivity = 'non-sensitive'
                if content_type.startswith('image/'):
                    sensitivity = classify_image_attachment(att_data)
                elif content_type == 'application/pdf':
                    text = extract_text_from_pdf(att_data)
                    sensitivity = classify_text_attachment(text)
                elif content_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                    text = extract_text_from_docx(att_data)
                    sensitivity = classify_text_attachment(text)
                elif content_type == 'text/plain':
                    text = att_data.decode('utf-8', errors='ignore')
                    sensitivity = classify_text_attachment(text)
                
                attachments.append({
                    'filename': attachment.get('name', 'unknown'),
                    'data': att_data,
                    'sensitivity': sensitivity,
                    'content_type': content_type
                })

        category, confidence, explanation, needs_review, features = classify_email(email['id'], sender, subject, body, attachments)

        return {
            'message_id': email['id'],
            'sender': sender,
            'receiver': receiver,
            'subject': subject,
            'body': body,
            'category': category,
            'confidence_score': confidence,
            'explanation': explanation,
            'needs_review': needs_review,
            'features': features,
            'attachments': attachments,
            'urls': urls
        }
    except Exception as e:
        logger.error(f"Error processing Outlook email: {str(e)}")
        return None

def fetch_and_process_gmail_emails(service, user_email, num_emails):
    """Fetch emails from Gmail and process them."""
    try:
        results = service.users().messages().list(
            userId='me',
            labelIds=['INBOX'],
            maxResults=num_emails
        ).execute()
        messages = results.get('messages', [])
        
        logger.info(f"Fetching {len(messages)} emails for {user_email}")
        
        # Use single phishing database
        conn = get_phishing_db_connection()
        
        for msg in messages:
            try:
                message_id = msg['id']
                
                # Check if already processed for this user
                cursor = conn.execute('SELECT id FROM Email WHERE message_id = ? AND user_email = ?', (message_id, user_email))
                if cursor.fetchone():
                    continue
                    continue
                
                # Get full message
                msg_full = service.users().messages().get(userId='me', id=message_id, format='full').execute()
                received_date = int(msg_full.get('internalDate', 0))
                
                # Process the message
                email_data = process_gmail_message(service, message_id)
                if email_data is None:
                    continue
                
                # Store in single phishing database with user info
                conn.execute('''
                    INSERT INTO Email (message_id, sender, receiver, subject, body, category, 
                                      confidence_score, needs_review, explanation, features, urls, 
                                      provider, user_email, received_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    email_data['message_id'],
                    email_data['sender'],
                    email_data['receiver'],
                    email_data['subject'],
                    email_data['body'],
                    email_data['category'],
                    email_data['confidence_score'],
                    1 if email_data['needs_review'] else 0,
                    json.dumps(email_data.get('explanation', [])),
                    json.dumps(email_data.get('features', {})),
                    json.dumps(email_data.get('urls', [])),
                    'gmail',
                    user_email,
                    received_date
                ))
                
                # Store attachments
                email_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
                for att in email_data.get('attachments', []):
                    conn.execute('''
                        INSERT INTO Attachment (filename, data, email_id, sensitivity, content_type)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (att['filename'], att['data'], email_id, att['sensitivity'], att['content_type']))
                
                conn.commit()
                logger.info(f"Processed Gmail email for {user_email}: {email_data['subject'][:50]}")
                
            except Exception as e:
                logger.error(f"Error processing email {msg.get('id')}: {e}")
                continue
        
        conn.close()
        logger.info(f"Finished processing {len(messages)} emails")
        
    except Exception as e:
        logger.error(f"Error fetching Gmail emails: {e}")

def fetch_and_process_outlook_emails(access_token, user_email, num_emails):
    """Fetch emails from Outlook and process them."""
    try:
        headers = {'Authorization': f'Bearer {access_token}'}
        response = http_requests.get(
            'https://graph.microsoft.com/v1.0/me/mailfolders/inbox/messages',
            headers=headers,
            params={'$top': num_emails, '$orderby': 'receivedDateTime desc', '$expand': 'attachments'}
        )
        
        if response.status_code != 200:
            logger.error(f"Failed to fetch Outlook emails: {response.text}")
            return
        
        messages = response.json().get('value', [])
        logger.info(f"Fetching {len(messages)} Outlook emails for {user_email}")
        
        # Use single phishing database
        conn = get_phishing_db_connection()
        
        for email in messages:
            try:
                message_id = email['id']
                
                # Check if already processed for this user
                cursor = conn.execute('SELECT id FROM Email WHERE message_id = ? AND user_email = ?', (message_id, user_email))
                if cursor.fetchone():
                    continue
                
                # Parse date
                received_date_str = email.get('receivedDateTime', '1970-01-01T00:00:00Z')
                try:
                    received_date_dt = datetime.strptime(received_date_str.replace('Z', ''), '%Y-%m-%dT%H:%M:%S')
                    received_date = int(received_date_dt.timestamp() * 1000)
                except:
                    received_date = 0
                
                # Process the email
                email_data = process_outlook_email(email)
                if email_data is None:
                    continue
                
                # Store in phishing database with provider and user_email
                conn.execute('''
                    INSERT OR IGNORE INTO Email (message_id, sender, receiver, subject, body, category, 
                                      confidence_score, needs_review, explanation, features, urls, 
                                      provider, user_email, received_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    email_data['message_id'],
                    email_data['sender'],
                    email_data['receiver'],
                    email_data['subject'],
                    email_data['body'],
                    email_data['category'],
                    email_data['confidence_score'],
                    1 if email_data['needs_review'] else 0,
                    json.dumps(email_data.get('explanation', [])),
                    json.dumps(email_data.get('features', {})),
                    json.dumps(email_data.get('urls', [])),
                    'outlook',
                    user_email,
                    received_date
                ))
                
                # Store attachments
                email_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
                for att in email_data.get('attachments', []):
                    conn.execute('''
                        INSERT INTO Attachment (filename, data, email_id, sensitivity, content_type)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (att['filename'], att['data'], email_id, att['sensitivity'], att['content_type']))
                
                conn.commit()
                logger.info(f"Processed Outlook email: {email_data['subject'][:50]}")
                
            except Exception as e:
                logger.error(f"Error processing Outlook email {email.get('id')}: {e}")
                continue
        
        conn.close()
        logger.info(f"Finished processing {len(messages)} Outlook emails")
        
    except Exception as e:
        logger.error(f"Error fetching Outlook emails: {e}")

# Load MLP model and preprocessors
def load_mlp_model():
    try:
        print("Loading MLP model and preprocessors...")
        
        # Use absolute paths based on script location
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        model_path = os.path.join(base_dir, 'mlp_ids_model.pkl')
        scaler_path = os.path.join(base_dir, 'scaler.pkl')
        encoders_path = os.path.join(base_dir, 'label_encoders.pkl')
        features_path = os.path.join(base_dir, 'feature_info.pkl')
        
        print(f"  Loading model from: {model_path}")
        
        if not os.path.exists(model_path):
            print(f"  ERROR: Model file not found at {model_path}")
            return None, None, None, None
        
        with open(model_path, 'rb') as f:
            mlp_model = pickle.load(f)
        
        with open(scaler_path, 'rb') as f:
            mlp_scaler = pickle.load(f)
        
        with open(encoders_path, 'rb') as f:
            mlp_label_encoders = pickle.load(f)
        
        with open(features_path, 'rb') as f:
            mlp_feature_info = pickle.load(f)
        
        print("✓ MLP model loaded successfully!")
        return mlp_model, mlp_scaler, mlp_label_encoders, mlp_feature_info
    except Exception as e:
        print(f"Error loading MLP model: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None, None

mlp_model, mlp_scaler, mlp_label_encoders, mlp_feature_info = load_mlp_model()

# Prediction function for MLP model
def predict_samples(df):
    global stats
    
    if mlp_model is None:
        print("MLP Model not loaded!")
        return []
    
    try:
        # Remove target columns if present
        X_test = df.drop(['label', 'anomaly'], axis=1, errors='ignore')
        
        # Encode categorical features
        X_test_encoded = X_test.copy()
        categorical_cols = mlp_feature_info['categorical_cols']
        
        for col in categorical_cols:
            if col in X_test_encoded.columns:
                le = mlp_label_encoders[col]
                # Handle unseen categories
                X_test_encoded[col] = X_test_encoded[col].astype(str).apply(
                    lambda x: le.transform([x])[0] if x in le.classes_ else -1
                )
        
        # Scale features
        X_test_scaled = mlp_scaler.transform(X_test_encoded)
        
        # Predict
        y_pred = mlp_model.predict(X_test_scaled)
        y_pred_proba = mlp_model.predict_proba(X_test_scaled)[:, 1]
        
        results = []
        for i, pred in enumerate(y_pred):
            # Get confidence (probability of predicted class)
            confidence = y_pred_proba[i] if pred == 1 else (1 - y_pred_proba[i])
            
            result = {
                'prediction': 'Normal' if pred == 0 else 'Anomaly',
                'confidence': float(confidence * 100),
                'timestamp': time.strftime('%H:%M:%S')
            }
            results.append(result)
            
            # Update stats
            stats['total_samples'] += 1
            if pred == 0:
                stats['normal_count'] += 1
            else:
                stats['anomaly_count'] += 1
        
        return results
    except Exception as e:
        print(f"Prediction error: {e}")
        import traceback
        traceback.print_exc()
        return []

# Monitor thread function
def monitor_and_predict():
    global monitoring_active, prediction_queue, last_processed_rows
    
    csv_files = []
    
    while monitoring_active:
        try:
            # Find latest CSV file from monitor
            csv_files = [f for f in os.listdir('.') if f.startswith('normal_windows_') and f.endswith('.csv')]
            
            if csv_files:
                latest_csv = max(csv_files, key=os.path.getctime)
                
                # Read the entire CSV
                df = pd.read_csv(latest_csv)
                current_rows = len(df)
                
                # Process only NEW rows since last check
                if current_rows > last_processed_rows:
                    print(f"[DEBUG] Total rows in CSV: {current_rows}, Last processed: {last_processed_rows}")
                    
                    # Get new rows
                    new_df = df.iloc[last_processed_rows:current_rows]
                    print(f"[DEBUG] Processing {len(new_df)} new samples...")
                    
                    if len(new_df) > 0:
                        # Process in batches of 10 to avoid overwhelming the UI
                        batch_size = 10
                        for i in range(0, len(new_df), batch_size):
                            batch = new_df.iloc[i:i+batch_size]
                            predictions = predict_samples(batch)
                            
                            for pred in predictions:
                                prediction_queue.append(pred)
                                socketio.emit('new_prediction', pred)
                            
                            # Emit stats update after each batch
                            socketio.emit('stats_update', stats)
                            print(f"[DEBUG] Stats - Total: {stats['total_samples']}, Normal: {stats['normal_count']}, Anomaly: {stats['anomaly_count']}")
                    
                    # Update last processed row count
                    last_processed_rows = current_rows
            
            time.sleep(2)  # Check every 2 seconds
            
        except Exception as e:
            print(f"Monitor error: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(2)

# Routes
@app.route('/')
def index():
    """Landing page"""
    return render_template('index.html')

@app.route('/anomaly-detection')
def anomaly_detection():
    """Anomaly detection dashboard"""
    return render_template('anomaly_detection.html')

@app.route('/data-classification')
def data_classification():
    """Data classification scanner"""
    return render_template('data_classification.html')

@app.route('/api/start', methods=['POST'])
def start_monitoring():
    global monitoring_active, traffic_gen_process, monitor_thread, last_processed_rows
    
    if not monitoring_active:
        monitoring_active = True
        
        # Reset stats and tracking
        stats['total_samples'] = 0
        stats['normal_count'] = 0
        stats['anomaly_count'] = 0
        last_processed_rows = 0
        
        # Start traffic generator
        try:
            traffic_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'traffic.py')
            traffic_gen_process = subprocess.Popen(['python', traffic_script], cwd=os.path.dirname(os.path.abspath(__file__)))
            time.sleep(2)  # Give it time to start
            print("[INFO] Traffic generator started")
        except Exception as e:
            print(f"Traffic generator error: {e}")
        
        # Start monitor in background thread
        try:
            monitor_thread = threading.Thread(target=run_monitor, daemon=True)
            monitor_thread.start()
            print("[INFO] Monitor thread started")
        except Exception as e:
            print(f"Monitor start error: {e}")
        
        # Start prediction thread
        pred_thread = threading.Thread(target=monitor_and_predict, daemon=True)
        pred_thread.start()
        print("[INFO] Prediction thread started")
        
        return jsonify({'status': 'started', 'message': 'Monitoring started successfully'})
    
    return jsonify({'status': 'already_running', 'message': 'Monitoring is already active'})

@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    global monitoring_active, traffic_gen_process
    
    monitoring_active = False
    
    # Stop traffic generator
    if traffic_gen_process:
        try:
            print("[INFO] Stopping traffic generator...")
            traffic_gen_process.terminate()
            
            # Wait a bit for graceful shutdown
            try:
                traffic_gen_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                # If it doesn't stop gracefully, force kill it
                print("[INFO] Traffic generator not responding, forcing kill...")
                traffic_gen_process.kill()
            
            traffic_gen_process = None
            print("[INFO] Traffic generator stopped successfully")
        except Exception as e:
            print(f"[ERROR] Error stopping traffic generator: {e}")
            traffic_gen_process = None
    
    return jsonify({'status': 'stopped', 'message': 'Monitoring stopped'})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify(stats)

@app.route('/api/recent', methods=['GET'])
def get_recent_predictions():
    return jsonify(list(prediction_queue))

# ========== DATA CLASSIFICATION API ENDPOINTS ==========

@app.route('/api/classify/start', methods=['POST'])
def start_classification():
    global scanning_active, scan_thread, classification_results, classification_stats
    
    if scanning_active:
        return jsonify({'status': 'already_running', 'message': 'Scan is already running'})
    
    data = request.json
    directory = data.get('directory', '').strip()
    
    # Normalize path separators
    directory = os.path.normpath(directory)
    
    print(f"\n[API] Classification scan requested for: {directory}")
    
    if not directory:
        print("[API] ERROR: No directory provided")
        return jsonify({'status': 'error', 'message': 'No directory path provided'})
    
    if not os.path.exists(directory):
        print(f"[API] ERROR: Directory does not exist: {directory}")
        return jsonify({'status': 'error', 'message': f'Directory does not exist: {directory}'})
    
    if not os.path.isdir(directory):
        print(f"[API] ERROR: Path is not a directory: {directory}")
        return jsonify({'status': 'error', 'message': f'Path is not a directory: {directory}'})
    
    # Reset stats and results
    print("[API] Resetting stats and starting scan thread...")
    scanning_active = True
    classification_results = []
    classification_stats = {
        'total_files': 0,
        'sensitive_count': 0,
        'non_sensitive_count': 0
    }
    
    # Start scanning thread
    scan_thread = threading.Thread(target=run_classification_scan, args=(directory,), daemon=True)
    scan_thread.start()
    print("[API] Scan thread started successfully")
    
    return jsonify({'status': 'started', 'message': 'Scan started successfully'})

@app.route('/api/classify/stop', methods=['POST'])
def stop_classification():
    global scanning_active
    scanning_active = False
    return jsonify({'status': 'stopped', 'message': 'Scan stopped'})

@app.route('/api/classify/stats', methods=['GET'])
def get_classification_stats():
    return jsonify(classification_stats)

@app.route('/api/classify/results', methods=['GET'])
def get_classification_results():
    return jsonify(classification_results)

def run_classification_scan(directory):
    """Run classification scan in background thread"""
    global scanning_active, classification_results, classification_stats
    
    try:
        print(f"\n[CLASSIFICATION] Starting scan of directory: {directory}")
        
        # Emit loading message
        socketio.emit('scan_progress', {
            'current': 0,
            'total': 0,
            'percentage': 0,
            'message': 'Loading RoBERTa model... (this may take 30-60 seconds on first run)'
        })
        
        # Import classifier
        print("[CLASSIFICATION] Importing classifier module...")
        from data_classifier import get_classifier
        
        # Get classifier instance (this will load the model - takes time!)
        print("[CLASSIFICATION] Initializing classifier (loading RoBERTa model)...")
        classifier = get_classifier()
        print("[CLASSIFICATION] Classifier ready!")
        
        # Define allowed extensions
        allowed_extensions = {'.txt', '.docx', '.pdf', '.csv', '.xlsx', '.xls'}
        
        # Get all files
        print(f"[CLASSIFICATION] Scanning directory for files...")
        directory_path = Path(directory)
        
        if not directory_path.exists():
            print(f"[CLASSIFICATION] ERROR: Directory does not exist: {directory}")
            socketio.emit('scan_error', {'error': f'Directory does not exist: {directory}'})
            scanning_active = False
            return
        
        all_files = []
        for ext in allowed_extensions:
            all_files.extend(directory_path.glob(f'*{ext}'))
        
        total_files = len(all_files)
        print(f"[CLASSIFICATION] Found {total_files} files to process")
        
        if total_files == 0:
            print(f"[CLASSIFICATION] No supported files found in directory")
            socketio.emit('scan_complete', {
                'total': 0,
                'sensitive': 0,
                'non_sensitive': 0,
                'message': 'No supported files found'
            })
            scanning_active = False
            return
        
        # Emit initial progress
        socketio.emit('scan_progress', {
            'current': 0,
            'total': total_files,
            'percentage': 0,
            'message': f'Starting scan of {total_files} files...'
        })
        
        # Process each file
        for idx, file_path in enumerate(all_files):
            if not scanning_active:
                print("[CLASSIFICATION] Scan stopped by user")
                break
            
            try:
                print(f"[CLASSIFICATION] Processing file {idx + 1}/{total_files}: {file_path.name}")
                
                # Wrap classification in try-except to prevent any single file from crashing the scan
                try:
                    # Classify file
                    result = classifier.classify_file(file_path)
                    
                    # Update stats
                    classification_stats['total_files'] += 1
                    if result['classification'] == 'Sensitive':
                        classification_stats['sensitive_count'] += 1
                    else:
                        classification_stats['non_sensitive_count'] += 1
                    
                    # Add to results
                    classification_results.append(result)
                    
                    # Emit result
                    socketio.emit('classification_result', result)
                    
                    print(f"[CLASSIFICATION] ✓ {file_path.name}: {result['classification']} ({result['confidence']:.1f}%)")
                    
                except Exception as file_error:
                    # Handle errors for individual files without crashing
                    print(f"[CLASSIFICATION] ✗ Error classifying {file_path.name}: {file_error}")
                    
                    # Create error result
                    error_result = {
                        'filename': file_path.name,
                        'path': str(file_path),
                        'classification': 'Error',
                        'confidence': 0.0,
                        'file_size': 0,
                        'file_type': file_path.suffix,
                        'error': str(file_error)
                    }
                    
                    classification_results.append(error_result)
                    socketio.emit('classification_result', error_result)
                
                # Emit progress regardless of success/failure
                socketio.emit('scan_progress', {
                    'current': idx + 1,
                    'total': total_files,
                    'percentage': ((idx + 1) / total_files) * 100,
                    'message': f'Processing {idx + 1}/{total_files} files...'
                })
                
            except Exception as e:
                print(f"[CLASSIFICATION] Unexpected error on file {file_path}: {e}")
                import traceback
                traceback.print_exc()
                # Continue to next file
                continue
        
        # Emit completion
        print(f"[CLASSIFICATION] Scan complete! Processed {classification_stats['total_files']} files")
        socketio.emit('scan_complete', {
            'total': classification_stats['total_files'],
            'sensitive': classification_stats['sensitive_count'],
            'non_sensitive': classification_stats['non_sensitive_count']
        })
        
        scanning_active = False
        
    except Exception as e:
        print(f"[CLASSIFICATION] FATAL ERROR in scan: {e}")
        import traceback
        traceback.print_exc()
        scanning_active = False
        socketio.emit('scan_error', {'error': str(e)})

# ========== PHISHING DETECTION ROUTES ==========

@app.route('/phishing-detection')
def phishing_detection():
    """Phishing detection dashboard"""
    return render_template('phishing_detection.html')

# Phishing helper functions
def extract_and_classify_urls(subject, body):
    """Extract URLs from email and classify them as Safe or Potentially Phishing"""
    if not PHISHING_AVAILABLE:
        return []
    try:
        soup = BeautifulSoup(body or '', 'html.parser')
        plain_text_body = soup.get_text(separator=' ', strip=True)
        text = f"{subject or ''} {plain_text_body}"
        
        url_pattern = re.compile(
            r'(https?://[\w\.-]+\.\w+[\w\.:/?=&%-]*|www\.[\w\.-]+\.\w+[\w\.:/?=&%-]*)',
            re.IGNORECASE
        )
        urls = url_pattern.findall(text)
        url_list = []
        
        for url in urls:
            if url.lower().startswith('www.'):
                normalized_url = 'http://' + url
            else:
                normalized_url = url
            if normalized_url not in url_list:
                url_list.append(normalized_url)
        
        url_info = []
        for url in url_list:
            try:
                parsed = urlparse(url)
                hostname = parsed.hostname
                if not hostname:
                    continue
                hostname = hostname.lower()
                ext = tldextract.extract(hostname)
                normalized_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else hostname
                
                if normalized_domain in trusted_set:
                    status = "Safe"
                else:
                    status = "Potentially Phishing"
                
                url_info.append({
                    "url": url,
                    "domain": normalized_domain,
                    "status": status
                })
            except Exception:
                continue
        
        return url_info
    except Exception as e:
        logger.error(f"Error extracting URLs: {e}")
        return []

def scan_attachment_with_yara(attachment_data, filename):
    """Scan attachment with YARA rules"""
    if not PHISHING_AVAILABLE or yara_rules is None:
        return {'status': 'skipped', 'message': 'YARA scanning not available'}
    
    try:
        temp_dir = app.config['TEMP_DIR']
        os.makedirs(temp_dir, exist_ok=True)
        temp_file_path = os.path.join(temp_dir, f"temp_{filename}")
        
        with open(temp_file_path, 'wb') as f:
            f.write(attachment_data)
        
        matches = yara_rules.match(temp_file_path)
        os.remove(temp_file_path)
        
        if matches:
            match_details = [f"{match.rule}" for match in matches]
            return {
                'status': 'unsafe',
                'message': f"Malicious patterns detected: {', '.join(match_details)}",
                'details': match_details
            }
        else:
            return {
                'status': 'safe',
                'message': "No malicious patterns detected"
            }
    except Exception as e:
        logger.error(f"YARA scan error: {e}")
        return {'status': 'error', 'message': str(e)}

def is_trusted_email_or_domain(email):
    """Check if email or domain is in trusted set"""
    if not email or not PHISHING_AVAILABLE:
        return False
    
    email = email.strip().lower()
    
    if email in trusted_set:
        return True
    
    match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', email)
    if not match:
        return False
    
    domain_raw = match.group(1).lower()
    ext = tldextract.extract(domain_raw)
    normalized_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    
    if normalized_domain in PUBLIC_EMAIL_PROVIDERS:
        return False
    
    return normalized_domain in trusted_set

def extract_domain(sender):
    """Extract domain from sender email"""
    if not isinstance(sender, str):
        return ""
    sender = sender.strip()
    domain_match = re.search(r'@([\w\.-]+\.\w+)', sender)
    if domain_match:
        return domain_match.group(1).lower()
    return ""

def classify_email(email_id, sender_email, subject, content, attachments=None):
    """Classify email using multi-layered approach"""
    if not PHISHING_AVAILABLE:
        return "Unknown", 0.0, [], True, {}
    
    try:
        SAFE_THRESHOLD = 0.90
        PHISHING_THRESHOLD = 0.35
        
        # Check whitelist
        if is_trusted_email_or_domain(sender_email):
            return "Safe", 100.0, [], False, {}
        
        # Language detection
        text_for_language = f"{subject or ''} {content or ''}".strip()
        if not text_for_language:
            return "Unknown", 0.0, [], True, {}
        
        try:
            detected_lang = detect(text_for_language)
            if detected_lang != 'en':
                return "Unknown", 50.0, [], True, {}
        except:
            pass
        
        # Initialize factors
        factors = {
            'ai_model_prediction': 0.0,
            'url_analysis': 0.0,
            'attachment_analysis': 0.0,
            'content_analysis': 0.0,
            'sender_trust': 0.0
        }
        
        # AI body classifier
        try:
            label, conf, probs = predict_body_label(text_for_language)
            if isinstance(probs, dict) and 'Phishing' in probs:
                phish_prob = float(probs['Phishing'])
            else:
                phish_prob = float(conf) if label.lower() == 'phishing' else float(1.0 - conf)
            factors['ai_model_prediction'] = max(0.0, min(1.0, phish_prob))
        except Exception as e:
            logger.error(f"Body classifier error: {e}")
        
        # URL analysis
        urls = extract_and_classify_urls(subject, content)
        if any(u['status'] == 'Potentially Phishing' for u in urls):
            factors['url_analysis'] = 0.7
        
        # Attachment analysis
        if attachments:
            for att in attachments:
                if len(att) >= 2:
                    yara_result = scan_attachment_with_yara(att[1], att[0])
                    if yara_result.get('status') == 'unsafe':
                        factors['attachment_analysis'] = 1.0
                        break
        
        # Content heuristics
        content_lower = (content or '').lower()
        suspicious_keywords = ['urgent', 'verify', 'security alert', 'password', 'click here', 'suspended', 'confirm']
        if any(kw in content_lower for kw in suspicious_keywords):
            factors['content_analysis'] = 0.4
        
        # Sender trust
        suspicious_tlds = ['.xyz', '.biz', '.info', '.top', '.loan', '.click']
        normalized_domain = extract_domain(sender_email)
        if any(normalized_domain.endswith(tld) for tld in suspicious_tlds):
            factors['sender_trust'] = 0.5
        
        # Weighted score
        weights = {
            'ai_model_prediction': 0.40,
            'url_analysis': 0.25,
            'attachment_analysis': 0.15,
            'content_analysis': 0.10,
            'sender_trust': 0.10
        }
        
        weighted_score = sum(factors.get(k, 0.0) * w for k, w in weights.items())
        model_confidence = max(0.0, min(1.0, weighted_score))
        
        # Apply thresholds
        needs_review = False
        if model_confidence >= SAFE_THRESHOLD:
            category = "Safe"
        elif model_confidence >= PHISHING_THRESHOLD:
            category = "Phishing"
        else:
            category = "Safe"
            needs_review = True
        
        confidence = round(model_confidence * 100, 2)
        
        # Build explanation
        mapping = {
            'ai_model_prediction': 'AI Body Analysis',
            'url_analysis': 'URL Analysis',
            'attachment_analysis': 'Attachment Analysis',
            'content_analysis': 'Content Analysis',
            'sender_trust': 'Sender Trust'
        }
        explanation = [(mapping[k], v) for k, v in factors.items() if k in mapping and v > 0]
        
        return category, confidence, explanation, needs_review, factors
        
    except Exception as e:
        logger.error(f"Classification error: {e}")
        return "Unknown", 0.0, [], True, {}

@app.route('/api/phishing/analyze', methods=['POST'])
def analyze_email_manual():
    """Analyze email content manually"""
    if not PHISHING_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'Phishing detection not available'})
    
    try:
        data = request.json
        subject = data.get('subject', '')
        sender = data.get('sender', '')
        body = data.get('body', '')
        
        if not body.strip():
            return jsonify({'status': 'error', 'message': 'Email body is required'})
        
        category, confidence, explanation, needs_review, factors = classify_email(
            'manual', sender, subject, body
        )
        
        urls = extract_and_classify_urls(subject, body)
        
        return jsonify({
            'status': 'success',
            'result': {
                'category': category,
                'confidence': confidence,
                'explanation': explanation,
                'needs_review': needs_review,
                'factors': factors,
                'urls': urls
            }
        })
    except Exception as e:
        logger.error(f"Manual analysis error: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/phishing/set-email-count')
def set_phishing_email_count():
    """Set email count and redirect to OAuth"""
    count = request.args.get('count', 10, type=int)
    provider = request.args.get('provider', 'gmail')
    session['phishing_email_count'] = count
    
    if provider == 'gmail':
        return redirect(url_for('phishing_authorize_gmail'))
    else:
        return redirect(url_for('phishing_authorize_outlook'))

@app.route('/phishing/authorize_gmail')
def phishing_authorize_gmail():
    """Redirect to Gmail OAuth"""
    if not PHISHING_AVAILABLE:
        flash('Phishing detection is not available', 'error')
        return redirect(url_for('phishing_detection'))
    
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash('Gmail API credentials not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables.', 'error')
        return redirect(url_for('phishing_detection'))
    
    try:
        # Use the redirect URI from environment variable to match Google Cloud Console config
        redirect_uri = GOOGLE_REDIRECT_URI
        flow = Flow.from_client_config(
            get_google_client_config(),
            scopes=GMAIL_SCOPES,
            redirect_uri=redirect_uri
        )
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        session['oauth_state'] = state
        return redirect(authorization_url)
    except Exception as e:
        logger.error(f"Gmail OAuth error: {e}")
        flash(f'Error initiating Gmail authorization: {str(e)}', 'error')
        return redirect(url_for('phishing_detection'))

@app.route('/callback')
@app.route('/phishing/callback')
def phishing_gmail_callback():
    """Handle Gmail OAuth callback"""
    if not PHISHING_AVAILABLE:
        flash('Phishing detection is not available', 'error')
        return redirect(url_for('phishing_detection'))
    
    try:
        num_emails = session.get('phishing_email_count', 10)
        
        # Use the redirect URI from environment variable to match Google Cloud Console config
        redirect_uri = GOOGLE_REDIRECT_URI
        flow = Flow.from_client_config(
            get_google_client_config(),
            scopes=GMAIL_SCOPES,
            state=session.get('oauth_state'),
            redirect_uri=redirect_uri
        )
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        service = build_gmail_service(credentials)
        
        # Get user email
        try:
            profile = service.users().getProfile(userId='me').execute()
            user_email = profile.get('emailAddress', 'unknown_user')
            session['phishing_user_email'] = user_email
            session['phishing_provider'] = 'gmail'
            logger.info(f"Gmail user authenticated: {user_email}")
        except Exception as e:
            logger.error(f"Error fetching user email: {e}")
            user_email = 'unknown_user'
            session['phishing_user_email'] = user_email
            session['phishing_provider'] = 'gmail'
        
        # Fetch and process emails
        flash(f'Successfully connected! Fetching {num_emails} emails...', 'success')
        fetch_and_process_gmail_emails(service, user_email, num_emails)
        
        return redirect(url_for('phishing_dashboard'))
    except Exception as e:
        logger.error(f"Gmail callback error: {e}")
        flash(f'Error during Gmail authorization: {str(e)}', 'error')
        return redirect(url_for('phishing_detection'))

@app.route('/phishing/authorize_outlook')
def phishing_authorize_outlook():
    """Redirect to Outlook OAuth"""
    if not PHISHING_AVAILABLE:
        flash('Phishing detection is not available', 'error')
        return redirect(url_for('phishing_detection'))
    
    if not OUTLOOK_CLIENT_ID or not OUTLOOK_CLIENT_SECRET:
        flash('Outlook API credentials not configured. Please set OUTLOOK_CLIENT_ID and OUTLOOK_CLIENT_SECRET environment variables.', 'error')
        return redirect(url_for('phishing_detection'))
    
    try:
        auth_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?"
        params = {
            'client_id': OUTLOOK_CLIENT_ID,
            'response_type': 'code',
            'redirect_uri': OUTLOOK_REDIRECT_URI,
            'response_mode': 'query',
            'scope': ' '.join(OUTLOOK_SCOPES),
            'state': os.urandom(16).hex()
        }
        session['outlook_state'] = params['state']
        return redirect(auth_url + '&'.join([f"{k}={v}" for k, v in params.items()]))
    except Exception as e:
        logger.error(f"Outlook OAuth error: {e}")
        flash(f'Error initiating Outlook authorization: {str(e)}', 'error')
        return redirect(url_for('phishing_detection'))

@app.route('/callback_outlook')
@app.route('/phishing/callback_outlook')
def phishing_outlook_callback():
    """Handle Outlook OAuth callback"""
    if not PHISHING_AVAILABLE:
        flash('Phishing detection is not available', 'error')
        return redirect(url_for('phishing_detection'))
    
    try:
        code = request.args.get('code')
        if not code:
            flash('Authorization failed - no code received', 'error')
            return redirect(url_for('phishing_detection'))
        
        num_emails = session.get('phishing_email_count', 10)
        
        # Exchange code for token
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': OUTLOOK_REDIRECT_URI,
            'client_id': OUTLOOK_CLIENT_ID,
            'client_secret': OUTLOOK_CLIENT_SECRET
        }
        
        token_response = http_requests.post(
            'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            data=data
        )
        
        if token_response.status_code != 200:
            error_data = token_response.json()
            flash(f'Token error: {error_data.get("error_description", "Unknown error")}', 'error')
            return redirect(url_for('phishing_detection'))
        
        access_token = token_response.json().get('access_token')
        
        # Get user info
        headers = {'Authorization': f'Bearer {access_token}'}
        user_response = http_requests.get('https://graph.microsoft.com/v1.0/me', headers=headers)
        if user_response.status_code == 200:
            user_email = user_response.json().get('userPrincipalName', 'unknown_user')
            session['phishing_user_email'] = user_email
            session['phishing_provider'] = 'outlook'
            logger.info(f"Outlook user authenticated: {user_email}")
        else:
            user_email = 'unknown_user'
            session['phishing_user_email'] = user_email
            session['phishing_provider'] = 'outlook'
        
        # Fetch and process emails
        flash(f'Successfully connected! Fetching {num_emails} emails...', 'success')
        fetch_and_process_outlook_emails(access_token, user_email, num_emails)
        
        return redirect(url_for('phishing_dashboard'))
    except Exception as e:
        logger.error(f"Outlook callback error: {e}")
        flash(f'Error during Outlook authorization: {str(e)}', 'error')
        return redirect(url_for('phishing_detection'))

@app.route('/phishing/dashboard')
def phishing_dashboard():
    """Display phishing detection dashboard with analyzed emails"""
    user_email = session.get('phishing_user_email', 'unknown_user')
    provider = session.get('phishing_provider', 'gmail')
    
    try:
        # Use single phishing database
        conn = get_phishing_db_connection()
        cursor = conn.cursor()
        
        # Get emails for this specific user
        cursor.execute('''
            SELECT * FROM Email 
            WHERE user_email = ?
            ORDER BY created_at DESC
        ''', (user_email,))
        emails = [dict(row) for row in cursor.fetchall()]
        
        # Get stats for this user
        cursor.execute("SELECT COUNT(*) as count FROM Email WHERE user_email = ?", (user_email,))
        total = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM Email WHERE category = 'Safe' AND user_email = ?", (user_email,))
        safe = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM Email WHERE category = 'Phishing' AND user_email = ?", (user_email,))
        phishing = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM Email WHERE needs_review = 1 AND user_email = ?", (user_email,))
        review = cursor.fetchone()['count']
        
        conn.close()
        
        return render_template('phishing_dashboard.html',
                              emails=emails,
                              stats={'total': total, 'safe': safe, 'phishing': phishing, 'review': review},
                              user_email=user_email,
                              provider=provider)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('phishing_detection'))

@app.route('/api/phishing/stats')
def get_phishing_stats():
    """Get phishing detection statistics"""
    try:
        conn = sqlite3.connect(app.config['PHISHING_DB'])
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) as total FROM Email')
        total = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(*) as safe FROM Email WHERE category = 'Safe'")
        safe = cursor.fetchone()['safe']
        
        cursor.execute("SELECT COUNT(*) as phishing FROM Email WHERE category = 'Phishing'")
        phishing = cursor.fetchone()['phishing']
        
        cursor.execute("SELECT COUNT(*) as review FROM Email WHERE needs_review = 1")
        review = cursor.fetchone()['review']
        
        conn.close()
        
        return jsonify({
            'total': total,
            'safe': safe,
            'phishing': phishing,
            'needs_review': review
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/phishing/email/<int:email_id>')
def phishing_email_details(email_id):
    """View email details"""
    user_email = session.get('phishing_user_email', 'unknown_user')
    provider = session.get('phishing_provider', 'gmail')
    
    try:
        # Use single phishing database
        conn = get_phishing_db_connection()
        cursor = conn.cursor()
        
        # Get email for this user
        cursor.execute('SELECT * FROM Email WHERE id = ? AND user_email = ?', (email_id, user_email))
        email_row = cursor.fetchone()
        
        if not email_row:
            flash('Email not found!', 'error')
            return redirect(url_for('phishing_detection'))
        
        email = dict(email_row)
        
        # Parse JSON fields
        try:
            email['explanation'] = json.loads(email['explanation']) if email.get('explanation') else []
            email['features'] = json.loads(email['features']) if email.get('features') else {}
            email['urls'] = json.loads(email['urls']) if email.get('urls') else []
        except:
            email['explanation'] = []
            email['features'] = {}
            email['urls'] = []
        
        # Get attachments
        cursor.execute('SELECT * FROM Attachment WHERE email_id = ?', (email_id,))
        attachments = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return render_template('email_details.html',
                              email=email,
                              attachments=attachments,
                              modified_body=email.get('body', ''),
                              provider=provider)
    except Exception as e:
        logger.error(f"Error loading email details: {e}")
        flash('Error loading email details', 'error')
        return redirect(url_for('phishing_detection'))

@app.route('/phishing/feedback/<int:email_id>', methods=['POST'])
def submit_phishing_feedback(email_id):
    """Submit feedback for email classification - stores in unified feedback database"""
    user_email = session.get('phishing_user_email', 'unknown_user')
    provider = session.get('phishing_provider', 'gmail')
    
    try:
        correct_category = request.form.get('correct_category')
        feedback_reason = request.form.get('feedback_reason', '')
        
        if correct_category not in ['Safe', 'Phishing']:
            flash('Invalid category selected', 'error')
            return redirect(url_for('phishing_email_details', email_id=email_id))
        
        # Get email info from phishing database
        user_conn = get_phishing_db_connection()
        cursor = user_conn.cursor()
        cursor.execute('SELECT * FROM Email WHERE id = ? AND user_email = ?', (email_id, user_email))
        email_row = cursor.fetchone()
        
        if not email_row:
            flash('Email not found', 'error')
            return redirect(url_for('phishing_dashboard'))
        
        email = dict(email_row)
        original_category = email.get('category', 'Unknown')
        
        # Store feedback in unified feedback database
        feedback_conn = sqlite3.connect(FEEDBACK_DB_PATH)
        feedback_conn.execute('''
            INSERT INTO Feedback (email_id, user_email, provider, original_category, 
                                 corrected_category, feedback_reason, email_subject, 
                                 email_sender, email_body_preview)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            email_id,
            user_email,
            provider,
            original_category,
            correct_category,
            feedback_reason,
            email.get('subject', ''),
            email.get('sender', ''),
            email.get('body', '')[:500] if email.get('body') else ''
        ))
        feedback_conn.commit()
        feedback_conn.close()
        
        # Update the email category in user-specific database
        user_conn.execute('''
            UPDATE Email SET category = ? WHERE id = ?
        ''', (correct_category, email_id))
        user_conn.commit()
        user_conn.close()
        
        flash('Feedback submitted successfully! Thank you for helping improve our detection.', 'success')
        return redirect(url_for('phishing_email_details', email_id=email_id))
    except Exception as e:
        logger.error(f"Error submitting feedback: {e}")
        flash('Error submitting feedback', 'error')
        return redirect(url_for('phishing_email_details', email_id=email_id))

@app.route('/phishing/attachment/<int:attachment_id>/download')
def download_attachment(attachment_id):
    """Download an email attachment"""
    user_email = session.get('phishing_user_email', 'unknown_user')
    provider = session.get('phishing_provider', 'gmail')
    
    try:
        # Use single phishing database
        conn = get_phishing_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM Attachment WHERE id = ?', (attachment_id,))
        attachment = cursor.fetchone()
        conn.close()
        
        if not attachment:
            flash('Attachment not found', 'error')
            return redirect(url_for('phishing_dashboard'))
        
        # Create file-like object from binary data
        file_data = io.BytesIO(attachment['data'])
        
        # Determine mimetype
        content_type = attachment['content_type'] or 'application/octet-stream'
        
        return send_file(
            file_data,
            mimetype=content_type,
            as_attachment=True,
            download_name=attachment['filename']
        )
    except Exception as e:
        logger.error(f"Error downloading attachment: {e}")
        flash('Error downloading attachment', 'error')
        return redirect(url_for('phishing_dashboard'))

@app.route('/phishing/attachment/<int:attachment_id>/scan')
def scan_attachment(attachment_id):
    """Scan an attachment with YARA rules"""
    user_email = session.get('phishing_user_email', 'unknown_user')
    provider = session.get('phishing_provider', 'gmail')
    
    try:
        # Use single phishing database
        conn = get_phishing_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM Attachment WHERE id = ?', (attachment_id,))
        attachment = cursor.fetchone()
        
        if not attachment:
            return jsonify({'status': 'error', 'message': 'Attachment not found'})
        
        # Scan with YARA if available
        scan_result = {'status': 'clean', 'matches': []}
        if yara_rules and attachment['data']:
            try:
                matches = yara_rules.match(data=attachment['data'])
                if matches:
                    scan_result = {
                        'status': 'malicious',
                        'matches': [str(m) for m in matches]
                    }
            except Exception as e:
                logger.error(f"YARA scan error: {e}")
        
        # Update database with scan result
        cursor.execute('''
            UPDATE Attachment SET yara_result = ? WHERE id = ?
        ''', (json.dumps(scan_result), attachment_id))
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'success', 'result': scan_result})
    except Exception as e:
        logger.error(f"Error scanning attachment: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/phishing/emails')
def get_phishing_emails():
    """Get list of analyzed emails"""
    try:
        conn = sqlite3.connect(app.config['PHISHING_DB'])
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM Email ORDER BY created_at DESC LIMIT 100')
        emails = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({'status': 'success', 'emails': emails})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/phishing/feedback')
def get_all_feedback():
    """Get all feedback from unified feedback database"""
    try:
        conn = sqlite3.connect(FEEDBACK_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM Feedback ORDER BY created_at DESC')
        feedback_list = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({'status': 'success', 'feedback': feedback_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/phishing/user-databases')
def get_user_databases():
    """Get list of all users from the single phishing database"""
    try:
        conn = get_phishing_db_connection()
        cursor = conn.cursor()
        
        # Get distinct users with their email counts
        cursor.execute('''
            SELECT provider, user_email, COUNT(*) as email_count 
            FROM Email 
            WHERE user_email IS NOT NULL 
            GROUP BY provider, user_email
        ''')
        
        users = []
        for row in cursor.fetchall():
            users.append({
                'provider': row['provider'],
                'user_email': row['user_email'],
                'email_count': row['email_count']
            })
        
        conn.close()
        
        return jsonify({'status': 'success', 'users': users})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# Helper function to run monitor
def run_monitor():
    from monitor import NormalCapture
    try:
        capture = NormalCapture(samples=1000000)
        capture.run()
    except Exception as e:
        print(f"Capture error: {e}")

# SocketIO events
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    socketio.emit('initial_data', {
        'stats': stats,
        'recent_predictions': list(prediction_queue),
        'monitoring_active': monitoring_active
    })


@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    print("=" * 60)
    print(" DLP PLATFORM - Integrated Security Dashboard")
    print("=" * 60)
    print()
    print("Server starting on http://localhost:5000")
    print()
    print("Integrated Systems:")
    print("  1. Anomaly Detection (MLP Model)")
    print("  2. Data Classification (RoBERTa Model)")
    print("  3. Phishing Detection (RoBERTa + YARA)")
    print()
    
    # Pre-load the data classifier to avoid restart issues
    print("Pre-loading Data Classification Model...")
    try:
        from data_classifier import get_classifier
        _ = get_classifier()  # Initialize classifier once
        print("✓ Data Classification Model loaded!")
    except Exception as e:
        print(f"⚠ Warning: Could not pre-load classifier: {e}")
        print("  Classification will load on first scan")
    
    # Pre-load the phishing classifier
    if PHISHING_AVAILABLE:
        print("Pre-loading Phishing Detection Model...")
        try:
            from body_classifier import predict_body_label
            _ = predict_body_label("Test email content")
            print("✓ Phishing Detection Model loaded!")
        except Exception as e:
            print(f"⚠ Warning: Could not pre-load phishing classifier: {e}")
    else:
        print("⚠ Phishing Detection not available (missing dependencies)")
    
    print()
    print("Required Files:")
    print("  Anomaly Detection:")
    print("    - mlp_ids_model.pkl")
    print("    - scaler.pkl")
    print("    - label_encoders.pkl")
    print("    - feature_info.pkl")
    print("  Data Classification:")
    print("    - data_classifier.py")
    print("    - RoBERTa model (configured in data_classifier.py)")
    print("  Phishing Detection:")
    print("    - body_classifier.py")
    print("    - roberta_lora_phishing_detector.pt")
    print("    - top-1m.csv (trusted domains)")
    print("    - awesome-yara/rules/ (YARA rules)")
    print()
    print("=" * 60)
    
    # Run with reloader disabled to prevent crashes during classification
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)

