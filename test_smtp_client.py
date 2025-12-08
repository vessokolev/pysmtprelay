#!/usr/bin/env python3
"""
Test script to send MIME message via SMTP to the server.
"""
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import argparse

def send_via_smtps(host, port, username, password, to_email, subject, body):
    """Send email via SMTPS (port 465)."""
    print(f"Connecting to {host}:{port} via SMTPS...")
    
    # Create SSL context that doesn't verify certificate
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Connect via SMTPS with timeout
    server = smtplib.SMTP_SSL(host, port, context=context, timeout=10)
    try:
        print("Connected. Authenticating...")
        server.login(username, password)
        print("Authenticated. Sending message...")
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = username
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        # Send message
        server.send_message(msg)
        print(f"Message sent successfully to {to_email}")
    finally:
        server.quit()

def send_via_starttls(host, port, username, password, to_email, subject, body):
    """Send email via STARTTLS (port 587)."""
    print(f"Connecting to {host}:{port} via STARTTLS...")
    
    # Create SSL context that doesn't verify certificate
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Connect and use STARTTLS with timeout
    server = smtplib.SMTP(host, port, timeout=10)
    try:
        print("Connected. Starting TLS...")
        server.starttls(context=context)
        print("TLS started. Authenticating...")
        server.login(username, password)
        print("Authenticated. Sending message...")
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = username
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        # Send message
        server.send_message(msg)
        print(f"Message sent successfully to {to_email}")
    finally:
        server.quit()

def main():
    parser = argparse.ArgumentParser(description='Test SMTP client')
    parser.add_argument('--host', default='127.0.0.1', help='SMTP server host')
    parser.add_argument('--port', type=int, default=8587, help='SMTP server port (default 8587 for STARTTLS, 8465 for SMTPS)')
    parser.add_argument('--username', default='testuser', help='Username for authentication')
    parser.add_argument('--password', default='testpass123', help='Password for authentication')
    parser.add_argument('--to', default='test@example.org', help='Recipient email address')
    parser.add_argument('--subject', default='Test Message', help='Email subject')
    parser.add_argument('--body', default='This is a test message sent via SMTP.', help='Email body')
    
    args = parser.parse_args()
    
    # Use SMTPS for port 465 or 8465 (our custom SMTPS port)
    if args.port == 465 or args.port == 8465:
        send_via_smtps(args.host, args.port, args.username, args.password, 
                      args.to, args.subject, args.body)
    else:
        send_via_starttls(args.host, args.port, args.username, args.password, 
                         args.to, args.subject, args.body)

if __name__ == "__main__":
    main()

