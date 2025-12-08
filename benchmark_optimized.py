#!/usr/bin/env python3
"""
Benchmark script to compare original vs optimized server.
Tests both sequential and concurrent performance.
"""
import smtplib
import ssl
import time
import argparse
import concurrent.futures
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class ConnectionPool:
    """Simple connection pool for SMTP connections."""
    
    def __init__(self, host, port, protocol, username, password, context, pool_size=5):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.username = username
        self.password = password
        self.context = context
        self.pool_size = pool_size
        self.pool = []
        self.lock = None  # Will be set by ThreadPoolExecutor
    
    def get_connection(self):
        """Get a connection from pool or create new one."""
        if self.pool:
            return self.pool.pop()
        return self._create_connection()
    
    def return_connection(self, conn):
        """Return connection to pool."""
        if len(self.pool) < self.pool_size:
            self.pool.append(conn)
        else:
            try:
                conn.quit()
            except:
                pass
    
    def _create_connection(self):
        """Create new SMTP connection."""
        if self.protocol == 'smtps':
            server = smtplib.SMTP_SSL(self.host, self.port, context=self.context, timeout=10)
        else:
            server = smtplib.SMTP(self.host, self.port, timeout=10)
            server.starttls(context=self.context)
        server.login(self.username, self.password)
        return server
    
    def close_all(self):
        """Close all connections in pool."""
        for conn in self.pool:
            try:
                conn.quit()
            except:
                pass
        self.pool.clear()

def send_message(host, port, protocol, username, password, to_email, context, msg_id, use_pool=False, pool=None):
    """Send a single message."""
    try:
        if use_pool and pool:
            server = pool.get_connection()
        else:
            if protocol == 'smtps':
                server = smtplib.SMTP_SSL(host, port, context=context, timeout=10)
            else:
                server = smtplib.SMTP(host, port, timeout=10)
                server.starttls(context=context)
            server.login(username, password)
        
        msg = MIMEMultipart()
        msg['From'] = username
        msg['To'] = to_email
        msg['Subject'] = f"Test [{msg_id}]"
        msg.attach(MIMEText(f"Test message {msg_id}", 'plain'))
        server.send_message(msg)
        
        if use_pool and pool:
            pool.return_connection(server)
        else:
            server.quit()
        return True, None
    except Exception as e:
        return False, str(e)

def benchmark(host, port, protocol, username, password, to_email, num_messages, 
              num_workers, use_pool=False, warmup=5):
    """Benchmark with or without connection pooling."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    pool = None
    if use_pool:
        pool = ConnectionPool(host, port, protocol, username, password, context, pool_size=num_workers)
    
    # Warmup
    for i in range(warmup):
        try:
            send_message(host, port, protocol, username, password, to_email, context, i, use_pool, pool)
        except:
            pass
    
    # Benchmark
    start_time = time.time()
    successful = 0
    failed = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [
            executor.submit(send_message, host, port, protocol, username, password,
                          to_email, context, i+1, use_pool, pool)
            for i in range(num_messages)
        ]
        
        for future in concurrent.futures.as_completed(futures):
            success, error = future.result()
            if success:
                successful += 1
            else:
                failed += 1
    
    if pool:
        pool.close_all()
    
    end_time = time.time()
    total_time = end_time - start_time
    messages_per_second = successful / total_time if total_time > 0 else 0
    
    return {
        'successful': successful,
        'failed': failed,
        'total_time': total_time,
        'messages_per_second': messages_per_second
    }

def main():
    parser = argparse.ArgumentParser(description='Benchmark optimized server')
    parser.add_argument('--host', default='127.0.0.1', help='SMTP server host')
    parser.add_argument('--port', type=int, default=8465, help='SMTP server port')
    parser.add_argument('--protocol', choices=['smtps', 'starttls'], default='smtps')
    parser.add_argument('--username', default='testuser', help='Username')
    parser.add_argument('--password', default='testpass123', help='Password')
    parser.add_argument('--to', default='test@example.org', help='Recipient')
    parser.add_argument('--messages', type=int, default=200, help='Total messages')
    parser.add_argument('--workers', type=int, default=12, help='Concurrent workers')
    parser.add_argument('--use-pool', action='store_true', help='Use connection pooling')
    
    args = parser.parse_args()
    
    print(f"\n{'='*70}")
    print(f"Benchmarking {'with' if args.use_pool else 'without'} connection pooling")
    print(f"{'='*70}")
    print(f"Protocol: {args.protocol.upper()}")
    print(f"Workers: {args.workers}")
    print(f"Messages: {args.messages}")
    print(f"Connection pooling: {args.use_pool}")
    print(f"{'='*70}\n")
    
    result = benchmark(args.host, args.port, args.protocol, args.username, args.password,
                     args.to, args.messages, args.workers, args.use_pool)
    
    print(f"{'='*70}")
    print("Results:")
    print(f"{'='*70}")
    print(f"Successful:         {result['successful']}")
    print(f"Failed:             {result['failed']}")
    print(f"Total time:         {result['total_time']:.2f} seconds")
    print(f"Messages/second:    {result['messages_per_second']:.2f} msg/s")
    print(f"{'='*70}\n")
    
    return result

if __name__ == "__main__":
    main()

