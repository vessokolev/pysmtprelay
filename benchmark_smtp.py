#!/usr/bin/env python3
"""
Benchmark script to measure SMTP server throughput (messages per second).
Tests both SMTPS and STARTTLS protocols.
"""
import smtplib
import ssl
import time
import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_message_smtps(host, port, username, password, to_email, subject, body, context):
    """Send a single message via SMTPS."""
    server = smtplib.SMTP_SSL(host, port, context=context, timeout=10)
    try:
        server.login(username, password)
        msg = MIMEMultipart()
        msg['From'] = username
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        server.send_message(msg)
    finally:
        server.quit()

def send_message_starttls(host, port, username, password, to_email, subject, body, context):
    """Send a single message via STARTTLS."""
    server = smtplib.SMTP(host, port, timeout=10)
    try:
        server.starttls(context=context)
        server.login(username, password)
        msg = MIMEMultipart()
        msg['From'] = username
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        server.send_message(msg)
    finally:
        server.quit()

def benchmark(host, port, protocol, username, password, to_email, num_messages, warmup=5):
    """Benchmark SMTP server throughput."""
    print(f"\n{'='*60}")
    print(f"Benchmarking {protocol} on {host}:{port}")
    print(f"{'='*60}")
    print(f"Protocol: {protocol}")
    print(f"Messages to send: {num_messages}")
    print(f"Warmup messages: {warmup}")
    
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
    
    # Warmup phase
    print(f"\nWarming up ({warmup} messages)...")
    for i in range(warmup):
        try:
            send_func(host, port, username, password, to_email, 
                     f"Warmup {i+1}", f"Warmup message {i+1}", context)
        except Exception as e:
            print(f"Warning: Warmup message {i+1} failed: {e}")
    
    print("Warmup complete. Starting benchmark...")
    
    # Actual benchmark
    start_time = time.time()
    successful = 0
    failed = 0
    
    for i in range(num_messages):
        try:
            send_func(host, port, username, password, to_email,
                     f"Benchmark {i+1}", f"Benchmark message {i+1}", context)
            successful += 1
            if (i + 1) % 10 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                print(f"  Progress: {i+1}/{num_messages} messages ({rate:.2f} msg/s)", end='\r')
        except Exception as e:
            failed += 1
            print(f"\n  Error on message {i+1}: {e}")
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Calculate statistics
    messages_per_second = successful / total_time if total_time > 0 else 0
    avg_time_per_message = total_time / successful if successful > 0 else 0
    
    # Print results
    print(f"\n{'='*60}")
    print("Benchmark Results:")
    print(f"{'='*60}")
    print(f"Protocol:           {protocol.upper()}")
    print(f"Total messages:     {num_messages}")
    print(f"Successful:         {successful}")
    print(f"Failed:             {failed}")
    print(f"Total time:         {total_time:.2f} seconds")
    print(f"Messages/second:    {messages_per_second:.2f} msg/s")
    print(f"Avg time/message:   {avg_time_per_message*1000:.2f} ms")
    print(f"{'='*60}\n")
    
    return {
        'protocol': protocol,
        'total_messages': num_messages,
        'successful': successful,
        'failed': failed,
        'total_time': total_time,
        'messages_per_second': messages_per_second,
        'avg_time_per_message': avg_time_per_message
    }

def main():
    parser = argparse.ArgumentParser(description='Benchmark SMTP server throughput')
    parser.add_argument('--host', default='127.0.0.1', help='SMTP server host')
    parser.add_argument('--port-smtps', type=int, default=8465, help='SMTPS port')
    parser.add_argument('--port-starttls', type=int, default=8587, help='STARTTLS port')
    parser.add_argument('--username', default='testuser', help='Username for authentication')
    parser.add_argument('--password', default='testpass123', help='Password for authentication')
    parser.add_argument('--to', default='test@example.org', help='Recipient email address')
    parser.add_argument('--messages', type=int, default=100, help='Number of messages to send')
    parser.add_argument('--warmup', type=int, default=5, help='Number of warmup messages')
    parser.add_argument('--protocol', choices=['smtps', 'starttls', 'both'], default='both',
                       help='Protocol to test (smtps, starttls, or both)')
    
    args = parser.parse_args()
    
    results = []
    
    if args.protocol in ('smtps', 'both'):
        result = benchmark(args.host, args.port_smtps, 'smtps', args.username, args.password,
                          args.to, args.messages, args.warmup)
        results.append(result)
    
    if args.protocol in ('starttls', 'both'):
        result = benchmark(args.host, args.port_starttls, 'starttls', args.username, args.password,
                          args.to, args.messages, args.warmup)
        results.append(result)
    
    # Summary comparison
    if len(results) == 2:
        print(f"\n{'='*60}")
        print("Performance Comparison:")
        print(f"{'='*60}")
        for r in results:
            print(f"{r['protocol'].upper():12}: {r['messages_per_second']:7.2f} msg/s "
                  f"({r['avg_time_per_message']*1000:6.2f} ms/msg)")
        print(f"{'='*60}\n")

if __name__ == "__main__":
    main()

