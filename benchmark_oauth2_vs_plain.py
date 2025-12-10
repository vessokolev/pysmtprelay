#!/usr/bin/env python3
"""
Benchmark OAuth2 vs PLAIN authentication to measure performance impact.
"""
import smtplib
import ssl
import time
import argparse
import concurrent.futures
import json
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from oauth2_mock_provider import get_token_for_user

def send_message_plain(host, port, username, password, to_email, context, msg_id, use_smtps=True):
    """Send message using PLAIN authentication."""
    try:
        if use_smtps:
            server = smtplib.SMTP_SSL(host, port, context=context, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls(context=context)
        
        server.login(username, password)
        
        msg = MIMEMultipart()
        msg['From'] = username
        msg['To'] = to_email
        msg['Subject'] = f"PLAIN Test [{msg_id}]"
        msg.attach(MIMEText(f"PLAIN auth test message {msg_id}", 'plain'))
        
        server.send_message(msg)
        server.quit()
        return True, None
    except Exception as e:
        return False, str(e)

def send_message_oauth2(host, port, email, access_token, to_email, context, msg_id, use_smtps=True):
    """Send message using OAuth2 authentication."""
    try:
        if use_smtps:
            server = smtplib.SMTP_SSL(host, port, context=context, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls(context=context)
        
        server.ehlo()
        
        # XOAUTH2 authentication
        oauth2_data = {
            "user": email,
            "authMethod": "XOAUTH2",
            "authToken": access_token
        }
        oauth2_string = json.dumps(oauth2_data)
        oauth2_encoded = base64.b64encode(oauth2_string.encode('utf-8')).decode('utf-8')
        
        code, response = server.docmd("AUTH", f"XOAUTH2 {oauth2_encoded}")
        if code != 235:
            if code == 334:
                code2, response2 = server.docmd("")
                if code2 != 235:
                    server.quit()
                    return False, f"OAuth2 auth failed: {code2} {response2}"
            else:
                server.quit()
                return False, f"OAuth2 auth failed: {code} {response}"
        
        msg = MIMEMultipart()
        msg['From'] = email
        msg['To'] = to_email
        msg['Subject'] = f"OAuth2 Test [{msg_id}]"
        msg.attach(MIMEText(f"OAuth2 auth test message {msg_id}", 'plain'))
        
        server.send_message(msg)
        server.quit()
        return True, None
    except Exception as e:
        return False, str(e)

def benchmark_auth_method(host, port, protocol, auth_method, username_or_email, password_or_token,
                         to_email, num_messages, num_workers, warmup=3):
    """Benchmark a specific authentication method."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    use_smtps = (protocol == 'smtps')
    
    # Warmup
    for i in range(warmup):
        try:
            if auth_method == 'plain':
                send_message_plain(host, port, username_or_email, password_or_token, to_email, context, i, use_smtps)
            else:
                send_message_oauth2(host, port, username_or_email, password_or_token, to_email, context, i, use_smtps)
        except:
            pass
    
    # Benchmark
    start_time = time.time()
    successful = 0
    failed = 0
    errors = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        if auth_method == 'plain':
            futures = [
                executor.submit(send_message_plain, host, port, username_or_email, password_or_token,
                              to_email, context, i+1, use_smtps)
                for i in range(num_messages)
            ]
        else:
            futures = [
                executor.submit(send_message_oauth2, host, port, username_or_email, password_or_token,
                              to_email, context, i+1, use_smtps)
                for i in range(num_messages)
            ]
        
        for future in concurrent.futures.as_completed(futures):
            success, error = future.result()
            if success:
                successful += 1
            else:
                failed += 1
                if error:
                    errors.append(error)
            if (successful + failed) % 20 == 0:
                elapsed = time.time() - start_time
                rate = (successful + failed) / elapsed if elapsed > 0 else 0
                print(f"  Progress: {successful + failed}/{num_messages} ({rate:.1f} msg/s)", end='\r')
    
    end_time = time.time()
    total_time = end_time - start_time
    messages_per_second = successful / total_time if total_time > 0 else 0
    
    return {
        'auth_method': auth_method,
        'successful': successful,
        'failed': failed,
        'total_time': total_time,
        'messages_per_second': messages_per_second,
        'errors': errors[:5]  # First 5 errors
    }

def main():
    parser = argparse.ArgumentParser(description='Benchmark OAuth2 vs PLAIN authentication')
    parser.add_argument('--host', default='127.0.0.1', help='SMTP server host')
    parser.add_argument('--port', type=int, default=8465, help='SMTP server port')
    parser.add_argument('--protocol', choices=['smtps', 'starttls'], default='smtps')
    parser.add_argument('--username', default='testuser', help='Username for PLAIN auth')
    parser.add_argument('--password', default='testpass123', help='Password for PLAIN auth')
    parser.add_argument('--email', default='testuser@example.com', help='Email for OAuth2')
    parser.add_argument('--to', default='test@example.org', help='Recipient')
    parser.add_argument('--messages', type=int, default=200, help='Messages per test')
    parser.add_argument('--workers', type=int, default=12, help='Concurrent workers')
    parser.add_argument('--warmup', type=int, default=3, help='Warmup messages')
    
    args = parser.parse_args()
    
    print(f"\n{'='*70}")
    print("OAuth2 vs PLAIN Authentication Performance Comparison")
    print(f"{'='*70}")
    print(f"Protocol: {args.protocol.upper()}")
    print(f"Workers: {args.workers}")
    print(f"Messages per test: {args.messages}")
    print(f"{'='*70}\n")
    
    # Get OAuth2 token
    print("Generating OAuth2 token...")
    oauth2_token = get_token_for_user(args.email)
    if not oauth2_token:
        print(f"Error: Could not generate OAuth2 token for {args.email}")
        return
    
    # Benchmark PLAIN
    print(f"\n{'='*70}")
    print("Testing PLAIN Authentication")
    print(f"{'='*70}")
    plain_result = benchmark_auth_method(
        args.host, args.port, args.protocol, 'plain',
        args.username, args.password, args.to,
        args.messages, args.workers, args.warmup
    )
    
    # Benchmark OAuth2
    print(f"\n{'='*70}")
    print("Testing OAuth2 Authentication")
    print(f"{'='*70}")
    oauth2_result = benchmark_auth_method(
        args.host, args.port, args.protocol, 'oauth2',
        args.email, oauth2_token, args.to,
        args.messages, args.workers, args.warmup
    )
    
    # Compare results
    print(f"\n{'='*70}")
    print("Performance Comparison")
    print(f"{'='*70}")
    print(f"{'Method':<15} {'Msg/s':<12} {'Success':<10} {'Failed':<10} {'Time (s)':<12}")
    print(f"{'-'*70}")
    
    for result in [plain_result, oauth2_result]:
        print(f"{result['auth_method'].upper():<15} "
              f"{result['messages_per_second']:<12.2f} "
              f"{result['successful']:<10} "
              f"{result['failed']:<10} "
              f"{result['total_time']:<12.2f}")
    
    # Calculate difference
    diff = oauth2_result['messages_per_second'] - plain_result['messages_per_second']
    diff_pct = (diff / plain_result['messages_per_second'] * 100) if plain_result['messages_per_second'] > 0 else 0
    
    print(f"{'='*70}")
    print(f"\nPerformance Impact:")
    print(f"  OAuth2 vs PLAIN: {diff:+.2f} msg/s ({diff_pct:+.1f}%)")
    
    if diff < 0:
        print(f"  [WARN]  OAuth2 is {abs(diff_pct):.1f}% slower than PLAIN")
    elif diff > 0:
        print(f"  [OK] OAuth2 is {diff_pct:.1f}% faster than PLAIN")
    else:
        print(f"  -> OAuth2 and PLAIN have similar performance")
    
    if oauth2_result['errors']:
        print(f"\nOAuth2 Errors (first 5):")
        for error in oauth2_result['errors']:
            print(f"  - {error}")
    
    print(f"{'='*70}\n")

if __name__ == "__main__":
    main()

