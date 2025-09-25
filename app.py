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
            
        # Try to parse as JSON first (in case it's already structured)
        try:
            json_data = json.loads(raw_email)
            if isinstance(json_data, dict) and 'subject' in json_data:
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
    Endpoint to receive Pub/Sub messages containing email data
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
        
        # Parse the email message
        email_data = parse_email_message(decoded_message)
        
        if not email_data:
            return jsonify({"error": "Failed to parse email message"}), 400
        
        # Log the processed email
        logger.info(f"Processed email: Subject='{email_data['subject']}', From='{email_data['from']}'")
        
        # Return the structured email data
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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
