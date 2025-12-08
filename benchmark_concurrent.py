#!/usr/bin/env python3
"""
Concurrent benchmark script to test SMTP server with multiple simultaneous connections.
This simulates real-world load with concurrent clients.
"""
import smtplib
import ssl
import time
import argparse
import concurrent.futures
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_message_smtps(host, port, username, password, to_email, subject, body, context, msg_id):
    """Send a single message via SMTPS."""
    try:
        server = smtplib.SMTP_SSL(host, port, context=context, timeout=10)
        server.login(username, password)
        msg = MIMEMultipart()
        msg['From'] = username
        msg['To'] = to_email
        msg['Subject'] = f"{subject} [{msg_id}]"
        msg.attach(MIMEText(f"{body} Message ID: {msg_id}", 'plain'))
        server.send_message(msg)
        server.quit()
        return True, msg_id, None
    except Exception as e:
        return False, msg_id, str(e)

def send_message_starttls(host, port, username, password, to_email, subject, body, context, msg_id):
    """Send a single message via STARTTLS."""
    try:
        server = smtplib.SMTP(host, port, timeout=10)
        server.starttls(context=context)
        server.login(username, password)
        msg = MIMEMultipart()
        msg['From'] = username
        msg['To'] = to_email
        msg['Subject'] = f"{subject} [{msg_id}]"
        msg.attach(MIMEText(f"{body} Message ID: {msg_id}", 'plain'))
        server.send_message(msg)
        server.quit()
        return True, msg_id, None
    except Exception as e:
        return False, msg_id, str(e)

def benchmark_concurrent(host, port, protocol, username, password, to_email, 
                        num_messages, num_workers):
    """Benchmark SMTP server with concurrent connections."""
    print(f"\n{'='*60}")
    print(f"Concurrent Benchmark: {protocol.upper()} on {host}:{port}")
    print(f"{'='*60}")
    print(f"Protocol: {protocol}")
    print(f"Total messages: {num_messages}")
    print(f"Concurrent workers: {num_workers}")
    
    # Create SSL context
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Select function based on protocol
    if protocol == 'smtps':
        send_func = send_message_smtps
    elif protocol == 'starttls':
        send_func = send_message_starttls
    else:
        raise ValueError(f"Unknown protocol: {protocol}")
    
    # Prepare arguments for each message
    subject = "Concurrent Test"
    body = "Concurrent benchmark message"
    
    # Run concurrent benchmark
    print(f"\nStarting concurrent benchmark with {num_workers} workers...")
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        # Submit all tasks
        futures = [
            executor.submit(send_func, host, port, username, password, to_email,
                          subject, body, context, i+1)
            for i in range(num_messages)
        ]
        
        # Collect results
        successful = 0
        failed = 0
        errors = []
        
        for future in concurrent.futures.as_completed(futures):
            success, msg_id, error = future.result()
            if success:
                successful += 1
            else:
                failed += 1
                errors.append((msg_id, error))
            if (successful + failed) % 10 == 0:
                elapsed = time.time() - start_time
                rate = (successful + failed) / elapsed if elapsed > 0 else 0
                print(f"  Progress: {successful + failed}/{num_messages} messages "
                      f"({rate:.2f} msg/s, {successful} success, {failed} failed)", end='\r')
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Calculate statistics
    messages_per_second = successful / total_time if total_time > 0 else 0
    
    # Print results
    print(f"\n{'='*60}")
    print("Concurrent Benchmark Results:")
    print(f"{'='*60}")
    print(f"Protocol:           {protocol.upper()}")
    print(f"Concurrent workers: {num_workers}")
    print(f"Total messages:     {num_messages}")
    print(f"Successful:         {successful}")
    print(f"Failed:             {failed}")
    print(f"Total time:         {total_time:.2f} seconds")
    print(f"Messages/second:    {messages_per_second:.2f} msg/s")
    if errors and len(errors) <= 5:
        print(f"\nErrors (first 5):")
        for msg_id, error in errors[:5]:
            print(f"  Message {msg_id}: {error}")
    print(f"{'='*60}\n")
    
    return {
        'protocol': protocol,
        'workers': num_workers,
        'total_messages': num_messages,
        'successful': successful,
        'failed': failed,
        'total_time': total_time,
        'messages_per_second': messages_per_second
    }

def main():
    parser = argparse.ArgumentParser(description='Concurrent SMTP server benchmark')
    parser.add_argument('--host', default='127.0.0.1', help='SMTP server host')
    parser.add_argument('--port-smtps', type=int, default=8465, help='SMTPS port')
    parser.add_argument('--port-starttls', type=int, default=8587, help='STARTTLS port')
    parser.add_argument('--username', default='testuser', help='Username')
    parser.add_argument('--password', default='testpass123', help='Password')
    parser.add_argument('--to', default='test@example.org', help='Recipient')
    parser.add_argument('--messages', type=int, default=100, help='Total messages')
    parser.add_argument('--workers', type=int, default=4, help='Concurrent workers')
    parser.add_argument('--protocol', choices=['smtps', 'starttls', 'both'], default='smtps',
                       help='Protocol to test')
    
    args = parser.parse_args()
    
    results = []
    
    if args.protocol in ('smtps', 'both'):
        result = benchmark_concurrent(args.host, args.port_smtps, 'smtps', args.username,
                                     args.password, args.to, args.messages, args.workers)
        results.append(result)
    
    if args.protocol in ('starttls', 'both'):
        result = benchmark_concurrent(args.host, args.port_starttls, 'starttls', args.username,
                                     args.password, args.to, args.messages, args.workers)
        results.append(result)
    
    # Summary
    if results:
        print(f"\n{'='*60}")
        print("Summary:")
        print(f"{'='*60}")
        for r in results:
            print(f"{r['protocol'].upper():12} ({r['workers']} workers): "
                  f"{r['messages_per_second']:7.2f} msg/s")
        print(f"{'='*60}\n")

if __name__ == "__main__":
    main()

