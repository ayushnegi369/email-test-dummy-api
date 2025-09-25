import base64
import json
import requests

# Gmail notification data (like what you received)
gmail_notification = {
    "emailAddress": "ayushnegi369@gmail.com",
    "historyId": 2894979
}

# Encode it to base64 (as Pub/Sub would do)
encoded_notification = base64.b64encode(json.dumps(gmail_notification).encode('utf-8')).decode('utf-8')

# Create Pub/Sub message format
pubsub_message = {
    "message": {
        "data": encoded_notification,
        "messageId": "16486118175062014",
        "publishTime": "2025-09-25T05:00:35.352Z"
    },
    "subscription": "projects/t2b-gmail-email-service/subscriptions/gmail-notification-sub"
}

print("Testing Gmail notification handling...")
print("Encoded data:", encoded_notification)
print("Decoded data:", json.dumps(gmail_notification, indent=2))

# Test the API
try:
    response = requests.post(
        'http://localhost:8080/pubsub/email',
        json=pubsub_message,
        headers={'Content-Type': 'application/json'}
    )
    
    print("\nStatus Code:", response.status_code)
    print("Response:", json.dumps(response.json(), indent=2))
except Exception as e:
    print(f"Error testing API: {e}")
