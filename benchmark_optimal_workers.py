#!/usr/bin/env python3
"""
Find optimal number of concurrent workers for maximum SMTP throughput.
Tests various worker counts to find the peak performance point.
"""
import smtplib
import ssl
import time
import argparse
import concurrent.futures
import multiprocessing
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_message(host, port, protocol, username, password, to_email, context, msg_id):
    """Send a single message."""
    try:
        if protocol == 'smtps':
            server = smtplib.SMTP_SSL(host, port, context=context, timeout=10)
        else:  # starttls
            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls(context=context)
        
        server.login(username, password)
        msg = MIMEMultipart()
        msg['From'] = username
        msg['To'] = to_email
        msg['Subject'] = f"Test [{msg_id}]"
        msg.attach(MIMEText(f"Test message {msg_id}", 'plain'))
        server.send_message(msg)
        server.quit()
        return True, None
    except Exception as e:
        return False, str(e)

def benchmark_workers(host, port, protocol, username, password, to_email, 
                      num_messages, num_workers, warmup=5):
    """Benchmark with specific number of workers."""
    # Create SSL context
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Warmup
    for i in range(warmup):
        try:
            send_message(host, port, protocol, username, password, to_email, context, i)
        except:
            pass
    
    # Actual benchmark
    start_time = time.time()
    successful = 0
    failed = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [
            executor.submit(send_message, host, port, protocol, username, password,
                          to_email, context, i+1)
            for i in range(num_messages)
        ]
        
        for future in concurrent.futures.as_completed(futures):
            success, error = future.result()
            if success:
                successful += 1
            else:
                failed += 1
    
    end_time = time.time()
    total_time = end_time - start_time
    messages_per_second = successful / total_time if total_time > 0 else 0
    
    return {
        'workers': num_workers,
        'successful': successful,
        'failed': failed,
        'total_time': total_time,
        'messages_per_second': messages_per_second
    }

def find_optimal_workers(host, port, protocol, username, password, to_email,
                         num_messages, max_workers, cpu_count):
    """Test different worker counts to find optimal."""
    print(f"\n{'='*70}")
    print(f"Finding Optimal Worker Count for {protocol.upper()}")
    print(f"{'='*70}")
    print(f"CPU threads available: {cpu_count}")
    print(f"Messages per test: {num_messages}")
    print(f"Testing worker counts from 1 to {max_workers}")
    print(f"{'='*70}\n")
    
    # Test different worker counts
    # Test: 1, 2, 4, 6, 8, 10, 12 (CPU count), 16, 20, 24
    test_counts = [1, 2, 4, 6, 8, 10, cpu_count, cpu_count + 4, cpu_count + 8, cpu_count + 12]
    test_counts = [w for w in test_counts if w <= max_workers]
    test_counts = sorted(list(set(test_counts)))  # Remove duplicates and sort
    
    results = []
    
    for workers in test_counts:
        print(f"Testing with {workers:2d} workers... ", end='', flush=True)
        result = benchmark_workers(host, port, protocol, username, password, to_email,
                                 num_messages, workers)
        results.append(result)
        print(f"{result['messages_per_second']:6.2f} msg/s "
              f"({result['successful']}/{num_messages} success)")
    
    return results

def analyze_results(results):
    """Analyze results to find optimal worker count."""
    print(f"\n{'='*70}")
    print("Results Analysis")
    print(f"{'='*70}")
    print(f"{'Workers':<10} {'Msg/s':<12} {'Success':<10} {'Improvement':<12}")
    print(f"{'-'*70}")
    
    baseline = results[0]['messages_per_second'] if results else 0
    best_result = max(results, key=lambda x: x['messages_per_second'])
    best_workers = best_result['workers']
    best_throughput = best_result['messages_per_second']
    
    for r in results:
        improvement = ((r['messages_per_second'] - baseline) / baseline * 100) if baseline > 0 else 0
        marker = " <-- BEST" if r['workers'] == best_workers else ""
        print(f"{r['workers']:<10} {r['messages_per_second']:<12.2f} "
              f"{r['successful']:<10} {improvement:>+10.1f}%{marker}")
    
    print(f"{'='*70}")
    print(f"\nOptimal worker count: {best_workers}")
    print(f"Peak throughput: {best_throughput:.2f} messages/second")
    print(f"Improvement over baseline: {((best_throughput - baseline) / baseline * 100):.1f}%")
    
    # Find where performance plateaus (within 5% of peak)
    plateau_threshold = best_throughput * 0.95
    plateau_workers = [r['workers'] for r in results 
                       if r['messages_per_second'] >= plateau_threshold]
    if plateau_workers:
        print(f"Performance plateau range: {min(plateau_workers)}-{max(plateau_workers)} workers")
    
    # Check if we're CPU-bound
    if best_workers >= len(results) * 0.8:  # If best is near the end
        print(f"\nNote: Peak performance at {best_workers} workers suggests we may not be CPU-bound.")
        print("Consider testing with even more workers or checking I/O bottlenecks.")
    elif best_workers <= 4:
        print(f"\nNote: Peak performance at {best_workers} workers suggests CPU-bound operation.")
    
    return best_workers, best_throughput

def main():
    parser = argparse.ArgumentParser(description='Find optimal worker count for SMTP server')
    parser.add_argument('--host', default='127.0.0.1', help='SMTP server host')
    parser.add_argument('--port-smtps', type=int, default=8465, help='SMTPS port')
    parser.add_argument('--port-starttls', type=int, default=8587, help='STARTTLS port')
    parser.add_argument('--username', default='testuser', help='Username')
    parser.add_argument('--password', default='testpass123', help='Password')
    parser.add_argument('--to', default='test@example.org', help='Recipient')
    parser.add_argument('--messages', type=int, default=100, help='Messages per test')
    parser.add_argument('--max-workers', type=int, default=32, help='Maximum workers to test')
    parser.add_argument('--protocol', choices=['smtps', 'starttls', 'both'], default='smtps',
                       help='Protocol to test')
    
    args = parser.parse_args()
    
    cpu_count = multiprocessing.cpu_count()
    print(f"System has {cpu_count} CPU threads")
    
    all_results = {}
    
    if args.protocol in ('smtps', 'both'):
        results = find_optimal_workers(args.host, args.port_smtps, 'smtps', args.username,
                                      args.password, args.to, args.messages, args.max_workers,
                                      cpu_count)
        best_workers, best_throughput = analyze_results(results)
        all_results['smtps'] = (best_workers, best_throughput, results)
    
    if args.protocol in ('starttls', 'both'):
        results = find_optimal_workers(args.host, args.port_starttls, 'starttls', args.username,
                                      args.password, args.to, args.messages, args.max_workers,
                                      cpu_count)
        best_workers, best_throughput = analyze_results(results)
        all_results['starttls'] = (best_workers, best_throughput, results)
    
    # Summary
    if len(all_results) > 1:
        print(f"\n{'='*70}")
        print("Summary")
        print(f"{'='*70}")
        for protocol, (workers, throughput, _) in all_results.items():
            print(f"{protocol.upper():12}: Optimal {workers:2d} workers, "
                  f"{throughput:6.2f} msg/s")
        print(f"{'='*70}\n")

if __name__ == "__main__":
    main()

