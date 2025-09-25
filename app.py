from flask import Flask, request, jsonify
import base64
import json
import email
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import logging
from datetime import datetime
import os
import requests
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

def decode_pubsub_message(message_data):
    """
    Decode the Pub/Sub message data from base64
    """
    try:
        logger.info(f"Raw message_data received: {message_data[:100]}...")  # Log first 100 chars
        # Decode base64 message
        decoded_data = base64.b64decode(message_data).decode('utf-8')
        logger.info(f"Decoded message: {decoded_data[:200]}...")  # Log first 200 chars
        return decoded_data
    except Exception as e:
        logger.error(f"Error decoding Pub/Sub message: {str(e)}")
        logger.error(f"Message data that failed: {message_data}")
        return None

def get_gmail_message_ids_from_history(email_address, history_id, access_token):
    """
    Get message IDs from Gmail history using the Gmail API
    """
    try:
        url = f"https://gmail.googleapis.com/gmail/v1/users/me/history"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        params = {
            'startHistoryId': history_id
        }
        
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code == 200:
            history_data = response.json()
            message_ids = []
            
            if 'history' in history_data:
                for history_item in history_data['history']:
                    if 'messagesAdded' in history_item:
                        for message in history_item['messagesAdded']:
                            message_ids.append(message['message']['id'])
            
            return message_ids
        else:
            logger.error(f"Failed to get history: {response.status_code} - {response.text}")
            return []
            
    except Exception as e:
        logger.error(f"Error getting message IDs from history: {str(e)}")
        return []

def fetch_gmail_message(message_id, access_token):
    """
    Fetch email message from Gmail API using message ID
    """
    try:
        url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        params = {
            'format': 'full'
        }
        
        logger.info(f"Fetching Gmail message: {message_id}")
        logger.info(f"Using access token: {access_token[:20]}..." if access_token else "No access token provided")
        logger.info(f"Request URL: {url}")
        
        response = requests.get(url, headers=headers, params=params)
        
        logger.info(f"Gmail API Response Status: {response.status_code}")
        
        if response.status_code == 200:
            logger.info("Successfully fetched Gmail message")
            return response.json()
        elif response.status_code == 401:
            logger.error("Gmail API Authentication failed - Invalid or expired access token")
            logger.error(f"Response: {response.text}")
            return None
        elif response.status_code == 403:
            logger.error("Gmail API Access forbidden - Check API permissions and scopes")
            logger.error(f"Response: {response.text}")
            return None
        elif response.status_code == 404:
            logger.error(f"Gmail message {message_id} not found")
            logger.error(f"Response: {response.text}")
            return None
        else:
            logger.error(f"Gmail API Error: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"Error fetching Gmail message: {str(e)}")
        return None

def parse_gmail_message(gmail_message):
    """
    Parse Gmail API message response into our required format
    """
    try:
        if not gmail_message:
            return None
            
        payload = gmail_message.get('payload', {})
        headers = payload.get('headers', [])
        
        # Extract headers
        subject = ""
        from_addr = ""
        date_str = ""
        
        for header in headers:
            name = header.get('name', '').lower()
            value = header.get('value', '')
            
            if name == 'subject':
                subject = value
            elif name == 'from':
                from_addr = value
            elif name == 'date':
                date_str = value
        
        # Parse date
        try:
            if date_str:
                parsed_date = email.utils.parsedate_to_datetime(date_str)
                formatted_date = parsed_date.strftime('%Y-%m-%d %H:%M:%S')
            else:
                formatted_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        except:
            formatted_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Extract body and attachments
        body = ""
        attachments = []
        
        def extract_parts(part):
            nonlocal body, attachments
            
            if 'parts' in part:
                for subpart in part['parts']:
                    extract_parts(subpart)
            else:
                mime_type = part.get('mimeType', '')
                
                if mime_type == 'text/plain' and not body:
                    body_data = part.get('body', {}).get('data', '')
                    if body_data:
                        body = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
                elif mime_type == 'text/html' and not body:
                    body_data = part.get('body', {}).get('data', '')
                    if body_data:
                        body = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
                elif part.get('filename'):
                    # Handle attachments
                    filename = part.get('filename', '')
                    attachment_data = part.get('body', {}).get('data', '')
                    if attachment_data:
                        attachments.append({
                            "filename": filename,
                            "mime_type": mime_type,
                            "data": attachment_data  # Already base64 encoded
                        })
        
        extract_parts(payload)
        
        # Structure the response
        email_data = {
            "subject": subject or "No Subject",
            "from": from_addr or "unknown@example.com",
            "date": formatted_date,
            "body": body.strip() or "No body content",
            "attachments": attachments
        }
        
        logger.info(f"Parsed Gmail message: Subject='{subject}', From='{from_addr}'")
        return email_data
        
    except Exception as e:
        logger.error(f"Error parsing Gmail message: {str(e)}")
        return None

def handle_gmail_notification(notification_data):
    """
    Handle Gmail push notification and fetch actual email content
    """
    try:
        email_address = notification_data.get('emailAddress', 'unknown@gmail.com')
        history_id = notification_data.get('historyId', 0)
        
        logger.info(f"Processing Gmail notification for {email_address}, historyId: {history_id}")
        
        # Get access token from environment variable
        access_token = os.environ.get('GMAIL_ACCESS_TOKEN')
        
        if not access_token:
            logger.error("GMAIL_ACCESS_TOKEN not found in environment variables")
            return {
                "subject": "Gmail API Error",
                "from": email_address,
                "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "body": "Gmail access token not configured. Please set GMAIL_ACCESS_TOKEN environment variable.",
                "attachments": [],
                "error": "missing_access_token"
            }
        
        # For now, we'll use a mock message ID since we don't have the actual message ID
        # In a real implementation, you would get message IDs from the history
        message_ids = get_gmail_message_ids_from_history(email_address, history_id, access_token)
        
        if not message_ids:
            # If no message IDs from history, create a mock response
            return {
                "subject": f"Gmail Notification - History ID {history_id}",
                "from": email_address,
                "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "body": f"Gmail push notification received for {email_address}. History ID: {history_id}. No new messages found in history.",
                "attachments": [],
                "notification_data": {
                    "emailAddress": email_address,
                    "historyId": history_id,
                    "type": "gmail_push_notification"
                }
            }
        
        # Fetch the first message (you might want to fetch all messages)
        message_id = message_ids[0]
        gmail_message = fetch_gmail_message(message_id, access_token)
        
        if gmail_message:
            return parse_gmail_message(gmail_message)
        else:
            return {
                "subject": "Gmail API Error",
                "from": email_address,
                "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "body": f"Failed to fetch message {message_id} from Gmail API",
                "attachments": [],
                "error": "fetch_failed"
            }
        
    except Exception as e:
        logger.error(f"Error handling Gmail notification: {str(e)}")
        return None

def parse_email_message(raw_email):
    """
    Parse raw email message and extract structured data
    """
    try:
        logger.info(f"Parsing email message. Length: {len(raw_email)}")
        logger.info(f"Raw email preview: {raw_email[:300]}...")
        
        # Handle different input formats
        if not raw_email or not raw_email.strip():
            logger.error("Empty or whitespace-only email message received")
            return None
            
        # Try to parse as JSON first (in case it's Gmail notification or structured data)
        try:
            json_data = json.loads(raw_email)
            if isinstance(json_data, dict):
                # Check if it's a Gmail push notification
                if 'emailAddress' in json_data and 'historyId' in json_data:
                    logger.info("Received Gmail push notification")
                    return handle_gmail_notification(json_data)
                # Check if it's already structured email data
                elif 'subject' in json_data:
                    logger.info("Email data is already in JSON format")
                    return json_data
        except json.JSONDecodeError:
            pass  # Not JSON, continue with email parsing
        
        # Parse the email message
        msg = email.message_from_string(raw_email)
        
        # Extract basic email information with fallbacks
        subject = msg.get('Subject', '').strip()
        from_addr = msg.get('From', '').strip()
        date_str = msg.get('Date', '').strip()
        
        # If standard headers are empty, try alternative parsing
        if not subject and not from_addr:
            logger.info("Standard email headers not found, trying alternative parsing...")
            
            # Try to extract from raw text
            lines = raw_email.split('\n')
            for line in lines:
                line = line.strip()
                if line.lower().startswith('subject:'):
                    subject = line[8:].strip()
                elif line.lower().startswith('from:'):
                    from_addr = line[5:].strip()
                elif line.lower().startswith('date:'):
                    date_str = line[5:].strip()
        
        logger.info(f"Extracted - Subject: '{subject}', From: '{from_addr}', Date: '{date_str}'")
        
        # Parse date to standard format
        try:
            if date_str:
                parsed_date = email.utils.parsedate_to_datetime(date_str)
                formatted_date = parsed_date.strftime('%Y-%m-%d %H:%M:%S')
            else:
                formatted_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        except:
            formatted_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Extract email body
        body = ""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                # Extract body text
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = payload.decode('utf-8', errors='ignore')
                    except Exception as e:
                        logger.error(f"Error extracting plain text body: {e}")
                        body = part.get_payload()
                elif content_type == "text/html" and "attachment" not in content_disposition and not body:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = payload.decode('utf-8', errors='ignore')
                    except Exception as e:
                        logger.error(f"Error extracting HTML body: {e}")
                        body = part.get_payload()
                
                # Extract attachments
                elif "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        attachment_data = part.get_payload(decode=True)
                        if attachment_data:
                            # Encode attachment data to base64
                            encoded_data = base64.b64encode(attachment_data).decode('utf-8')
                            attachments.append({
                                "filename": filename,
                                "mime_type": content_type,
                                "data": encoded_data
                            })
        else:
            # Single part message
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode('utf-8', errors='ignore')
                else:
                    body = msg.get_payload()
            except Exception as e:
                logger.error(f"Error extracting single part body: {e}")
                body = str(msg.get_payload())
        
        # If body is still empty, try to extract from raw email
        if not body.strip():
            logger.info("Body extraction failed, trying to extract from raw email...")
            lines = raw_email.split('\n')
            body_started = False
            body_lines = []
            
            for line in lines:
                if body_started:
                    body_lines.append(line)
                elif line.strip() == "":  # Empty line indicates start of body
                    body_started = True
            
            if body_lines:
                body = '\n'.join(body_lines).strip()
        
        # If we still don't have basic email data, create a fallback response
        if not subject and not from_addr and not body.strip():
            logger.warning("No email data could be extracted, creating fallback response")
            email_data = {
                "subject": "No Subject",
                "from": "unknown@example.com",
                "date": formatted_date,
                "body": raw_email[:500] if raw_email else "No content available",
                "attachments": []
            }
        else:
            # Structure the response
            email_data = {
                "subject": subject or "No Subject",
                "from": from_addr or "unknown@example.com", 
                "date": formatted_date,
                "body": body.strip() or "No body content",
                "attachments": attachments
            }
        
        logger.info(f"Final email_data: {email_data}")
        print("email_data : ", email_data)
        return email_data
        
    except Exception as e:
        logger.error(f"Error parsing email message: {str(e)}")
        return None

@app.route('/', methods=['GET'])
def health_check():
    """
    Health check endpoint
    """
    return jsonify({
        "status": "healthy",
        "message": "Dummy Email API is running",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/pubsub/email', methods=['POST'])
def receive_pubsub_email():
    """
    Endpoint to receive Pub/Sub messages and fetch actual Gmail messages
    """
    try:
        # Get the request data
        request_data = request.get_json()
        logger.info(f"Received Pub/Sub request: {json.dumps(request_data, indent=2)}")
        
        if not request_data:
            logger.error("No JSON data received")
            return jsonify({"error": "No JSON data received"}), 400
        
        # Extract message data from Pub/Sub format
        message = request_data.get('message', {})
        message_data = message.get('data')
        
        logger.info(f"Extracted message data: {message_data}")
        
        if not message_data:
            logger.error("No message data found in request")
            return jsonify({"error": "No message data found"}), 400
        
        # Decode the Pub/Sub message
        decoded_message = decode_pubsub_message(message_data)
        
        if not decoded_message:
            return jsonify({"error": "Failed to decode message"}), 400
        
        # Check if it's a Gmail notification
        try:
            notification_data = json.loads(decoded_message)
            if isinstance(notification_data, dict) and 'emailAddress' in notification_data and 'historyId' in notification_data:
                logger.info("Detected Gmail push notification - fetching actual email messages")
                
                # Get access token
                access_token = os.environ.get('GMAIL_ACCESS_TOKEN')
                
                if not access_token:
                    logger.error("Gmail access token not configured")
                    return jsonify({
                        "status": "error",
                        "message": "Gmail access token not configured. Please set GMAIL_ACCESS_TOKEN environment variable."
                    }), 400
                
                email_address = notification_data.get('emailAddress')
                history_id = notification_data.get('historyId')
                
                logger.info(f"Processing Gmail notification for {email_address}, historyId: {history_id}")
                
                # Get message IDs from history
                message_ids = get_gmail_message_ids_from_history(email_address, history_id, access_token)
                
                if message_ids:
                    # Process all messages (or just the first one)
                    all_emails = []
                    
                    for message_id in message_ids[:5]:  # Limit to first 5 messages
                        logger.info(f"Fetching Gmail message: {message_id}")
                        
                        # Fetch the Gmail message
                        gmail_message = fetch_gmail_message(message_id, access_token)
                        
                        if gmail_message:
                            # Parse the message
                            email_data = parse_gmail_message(gmail_message)
                            
                            if email_data:
                                all_emails.append(email_data)
                                
                                # Log the actual email content
                                logger.info("="*80)
                                logger.info("GMAIL MESSAGE CONTENT:")
                                logger.info(f"Message ID: {message_id}")
                                logger.info(f"Subject: {email_data['subject']}")
                                logger.info(f"From: {email_data['from']}")
                                logger.info(f"Date: {email_data['date']}")
                                logger.info(f"Body: {email_data['body'][:500]}...")  # First 500 chars
                                logger.info(f"Attachments: {len(email_data['attachments'])} files")
                                logger.info("="*80)
                    
                    if all_emails:
                        # Return the first email (or all emails)
                        return jsonify({
                            "status": "success",
                            "message": f"Successfully fetched {len(all_emails)} Gmail messages",
                            "data": all_emails[0] if len(all_emails) == 1 else all_emails,
                            "total_messages": len(all_emails)
                        }), 200
                    else:
                        logger.warning("No emails could be fetched from Gmail API")
                        return jsonify({
                            "status": "warning",
                            "message": "Gmail notification received but no messages could be fetched",
                            "notification_data": notification_data
                        }), 200
                else:
                    logger.info("No new messages found in Gmail history")
                    return jsonify({
                        "status": "info",
                        "message": "Gmail notification received but no new messages found",
                        "notification_data": notification_data
                    }), 200
            else:
                # Not a Gmail notification, parse as regular email
                logger.info("Processing as regular email message")
                email_data = parse_email_message(decoded_message)
                
                if not email_data:
                    return jsonify({"error": "Failed to parse email message"}), 400
                
                # Log the processed email
                logger.info(f"Processed email: Subject='{email_data['subject']}', From='{email_data['from']}'")
                
                return jsonify({
                    "status": "success",
                    "message": "Email processed successfully",
                    "data": email_data
                }), 200
                
        except json.JSONDecodeError:
            # Not JSON, parse as regular email
            logger.info("Processing as regular email message")
            email_data = parse_email_message(decoded_message)
            
            if not email_data:
                return jsonify({"error": "Failed to parse email message"}), 400
            
            # Log the processed email
            logger.info(f"Processed email: Subject='{email_data['subject']}', From='{email_data['from']}'")
            
            return jsonify({
                "status": "success",
                "message": "Email processed successfully",
                "data": email_data
            }), 200
        
    except Exception as e:
        logger.error(f"Error processing Pub/Sub message: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500

@app.route('/test/email', methods=['POST'])
def test_email_parsing():
    """
    Test endpoint to directly test email parsing with raw email data
    """
    try:
        request_data = request.get_json()
        
        if not request_data or 'raw_email' not in request_data:
            return jsonify({"error": "Please provide 'raw_email' in request body"}), 400
        
        raw_email = request_data['raw_email']
        
        # Parse the email message
        email_data = parse_email_message(raw_email)
        
        if not email_data:
            return jsonify({"error": "Failed to parse email message"}), 400
        
        return jsonify({
            "status": "success",
            "message": "Email parsed successfully",
            "data": email_data
        }), 200
        
    except Exception as e:
        logger.error(f"Error in test endpoint: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500

@app.route('/gmail/message/<message_id>', methods=['GET'])
def fetch_gmail_message_endpoint(message_id):
    """
    Endpoint to directly fetch a Gmail message by message ID
    """
    try:
        # Get access token from environment variable
        access_token = os.environ.get('GMAIL_ACCESS_TOKEN')
        
        if not access_token:
            return jsonify({
                "status": "error",
                "message": "Gmail access token not configured. Please set GMAIL_ACCESS_TOKEN environment variable."
            }), 400
        
        # Fetch the Gmail message
        gmail_message = fetch_gmail_message(message_id, access_token)
        
        if not gmail_message:
            return jsonify({
                "status": "error",
                "message": f"Failed to fetch message {message_id} from Gmail API"
            }), 404
        
        # Parse the message
        email_data = parse_gmail_message(gmail_message)
        
        if not email_data:
            return jsonify({
                "status": "error",
                "message": "Failed to parse Gmail message"
            }), 500
        
        return jsonify({
            "status": "success",
            "message": "Gmail message fetched successfully",
            "data": email_data
        }), 200
        
    except Exception as e:
        logger.error(f"Error in Gmail message endpoint: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500

@app.route('/gmail/test', methods=['POST'])
def test_gmail_api():
    """
    Test endpoint to verify Gmail API access
    """
    try:
        request_data = request.get_json()
        
        if not request_data or 'message_id' not in request_data:
            return jsonify({"error": "Please provide 'message_id' in request body"}), 400
        
        message_id = request_data['message_id']
        access_token = os.environ.get('GMAIL_ACCESS_TOKEN')
        
        if not access_token:
            return jsonify({
                "status": "error",
                "message": "Gmail access token not configured"
            }), 400
        
        # Test Gmail API access
        gmail_message = fetch_gmail_message(message_id, access_token)
        
        if gmail_message:
            email_data = parse_gmail_message(gmail_message)
            return jsonify({
                "status": "success",
                "message": "Gmail API test successful",
                "data": email_data
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to fetch message from Gmail API"
            }), 404
        
    except Exception as e:
        logger.error(f"Error in Gmail test endpoint: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500

@app.route('/gmail/validate-token', methods=['GET'])
def validate_gmail_token():
    """
    Validate Gmail access token by making a simple API call
    """
    try:
        access_token = os.environ.get('GMAIL_ACCESS_TOKEN')
        
        if not access_token:
            return jsonify({
                "status": "error",
                "message": "Gmail access token not configured"
            }), 400
        
        # Test token with a simple profile request
        url = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        logger.info("Testing Gmail access token...")
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            profile_data = response.json()
            return jsonify({
                "status": "success",
                "message": "Gmail access token is valid",
                "profile": {
                    "emailAddress": profile_data.get('emailAddress'),
                    "messagesTotal": profile_data.get('messagesTotal'),
                    "threadsTotal": profile_data.get('threadsTotal')
                }
            }), 200
        elif response.status_code == 401:
            return jsonify({
                "status": "error",
                "message": "Invalid or expired access token",
                "details": response.text
            }), 401
        else:
            return jsonify({
                "status": "error",
                "message": f"Gmail API Error: {response.status_code}",
                "details": response.text
            }), response.status_code
        
    except Exception as e:
        logger.error(f"Error validating Gmail token: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
