# Dummy Email API for Pub/Sub

A Flask-based API that receives Google Cloud Pub/Sub messages containing email data and decodes them into a structured JSON format.

## Features

- Receives Pub/Sub messages with email data
- Decodes base64-encoded email messages
- Parses email content including subject, sender, date, body, and attachments
- Returns structured JSON response in the specified format
- Includes health check endpoint
- Test endpoint for direct email parsing

## API Endpoints

### 1. Health Check
```
GET /
```
Returns the API status and timestamp.

### 2. Pub/Sub Email Endpoint
```
POST /pubsub/email
```
Receives Pub/Sub messages containing email data.

**Expected Pub/Sub Message Format:**
```json
{
  "message": {
    "data": "base64-encoded-email-content",
    "messageId": "message-id",
    "publishTime": "2023-01-01T00:00:00.000Z"
  }
}
```

**Response Format:**
```json
{
  "status": "success",
  "message": "Email processed successfully",
  "data": {
    "subject": "Invoice August",
    "from": "accounts@example.com",
    "date": "2025-08-28 10:00:00",
    "body": "Please find attached invoice.",
    "attachments": [
      {
        "filename": "invoice.pdf",
        "mime_type": "application/pdf",
        "data": "JVBERi0xLjQKJcfs..."
      }
    ]
  }
}
```

### 3. Test Endpoint
```
POST /test/email
```
Test endpoint for direct email parsing without Pub/Sub wrapper.

**Request Format:**
```json
{
  "raw_email": "raw email message string"
}
```

## Local Development

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

The API will be available at `http://localhost:5000`

## Deployment to Render

1. Connect your GitHub repository to Render
2. Create a new Web Service
3. Use the following settings:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
   - **Environment:** Python 3

## Testing

You can test the API using curl:

```bash
# Health check
curl http://localhost:5000/

# Test email parsing
curl -X POST http://localhost:5000/test/email \
  -H "Content-Type: application/json" \
  -d '{
    "raw_email": "Subject: Test Email\nFrom: test@example.com\nDate: Wed, 25 Sep 2024 10:00:00 +0000\n\nThis is a test email body."
  }'
```

## Environment Variables

- `PORT`: Port number for the application (default: 5000)

## Logging

The application includes comprehensive logging for debugging and monitoring:
- Request processing
- Email parsing results
- Error handling

## Error Handling

The API includes robust error handling for:
- Invalid JSON requests
- Missing message data
- Base64 decoding failures
- Email parsing errors
- Internal server errors
