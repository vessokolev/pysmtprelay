#!/usr/bin/env python3
"""
SMTP server with multiprocessing support for increased throughput.
Spawns multiple worker processes, each running a server instance.

Note: On Linux, this uses SO_REUSEPORT to allow multiple processes
to bind to the same port. On other systems, you may need to use
different ports per worker or use a different approach.
"""
import asyncio
import ssl
import os
import signal
import sys
import multiprocessing
import socket

# Import from smtp_server module
try:
    from smtp_server import (
        UserAuthHandler, MessageHandler, AuthenticatedController,
        create_ssl_context
    )
except ImportError:
    # If running as standalone, import directly
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from smtp_server import (
        UserAuthHandler, MessageHandler, AuthenticatedController,
        create_ssl_context
    )

def enable_reuseport(sock):
    """Enable SO_REUSEPORT on socket if available (Linux)."""
    try:
        # SO_REUSEPORT = 15 on Linux
        sock.setsockopt(socket.SOL_SOCKET, 15, 1)
        return True
    except (AttributeError, OSError):
        # Not available on this system
        return False

def run_server_worker(worker_id, host, port_465, port_587, certfile, keyfile, 
                     users_file, messages_dir, ca_certfile=None):
    """Run a single server worker process."""
    print(f"[Worker {worker_id}] Starting SMTP server (PID: {os.getpid()})...")
    
    # Create handlers (each worker has its own instances)
    auth_handler = UserAuthHandler(users_file=users_file)
    message_handler = MessageHandler(messages_dir=messages_dir)
    
    # Create SSL context
    ssl_context = create_ssl_context(certfile, keyfile, ca_certfile)
    
    # Try to enable SO_REUSEPORT for port sharing (Linux only)
    reuseport_available = False
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        reuseport_available = enable_reuseport(test_sock)
        test_sock.close()
        if reuseport_available:
            print(f"[Worker {worker_id}] SO_REUSEPORT available - multiple workers can share ports")
        else:
            print(f"[Worker {worker_id}] Warning: SO_REUSEPORT not available - only one worker can bind to each port")
    except Exception as e:
        print(f"[Worker {worker_id}] Warning: Could not check SO_REUSEPORT: {e}")
    
    # Start SMTPS server
    try:
        controller_465 = AuthenticatedController(
            message_handler,
            auth_handler,
            hostname=host,
            port=port_465,
            ssl_context=ssl_context,
            require_tls_for_auth=False
        )
        controller_465.start()
        print(f"[Worker {worker_id}] SMTPS server started on {host}:{port_465}")
    except Exception as e:
        print(f"[Worker {worker_id}] Error starting SMTPS server: {e}")
        return
    
    # Start STARTTLS server
    try:
        controller_587 = AuthenticatedController(
            message_handler,
            auth_handler,
            hostname=host,
            port=port_587,
            tls_context=ssl_context,
            require_tls_for_auth=True
        )
        controller_587.start()
        print(f"[Worker {worker_id}] STARTTLS server started on {host}:{port_587}")
    except Exception as e:
        print(f"[Worker {worker_id}] Error starting STARTTLS server: {e}")
        controller_465.stop()
        return
    
    # Run event loop
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        print(f"[Worker {worker_id}] Shutting down...")
        try:
            controller_465.stop()
            controller_587.stop()
        except:
            pass

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Multiprocessing SMTP server')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port-465', type=int, default=8465, help='Port for SMTPS')
    parser.add_argument('--port-587', type=int, default=8587, help='Port for STARTTLS')
    parser.add_argument('--certfile', default='certs/server-cert.pem', help='Server certificate file')
    parser.add_argument('--keyfile', default='certs/server-key.pem', help='Server private key file')
    parser.add_argument('--users', default='users.txt', help='Users file')
    parser.add_argument('--messages-dir', default='messages', help='Directory to store messages')
    parser.add_argument('--workers', type=int, default=None, 
                       help='Number of worker processes (default: number of CPU cores)')
    
    args = parser.parse_args()
    
    # Determine number of workers
    if args.workers is None:
        num_workers = multiprocessing.cpu_count()
    else:
        num_workers = args.workers
    
    print(f"Starting multiprocessing SMTP server with {num_workers} workers...")
    print(f"CPU cores available: {multiprocessing.cpu_count()}")
    
    # Check if certificates exist
    if not os.path.exists(args.certfile) or not os.path.exists(args.keyfile):
        print(f"Error: Certificate files not found. Please run generate_certificates.py first.")
        return
    
    ca_certfile = args.certfile.replace('server-cert.pem', 'ca-cert.pem') if 'server-cert' in args.certfile else None
    
    # Prepare arguments for worker processes
    worker_args = (
        args.host,
        args.port_465,
        args.port_587,
        args.certfile,
        args.keyfile,
        args.users,
        args.messages_dir,
        ca_certfile
    )
    
    # Spawn worker processes
    processes = []
    
    def signal_handler(sig, frame):
        """Handle shutdown signal."""
        print("\nShutting down all workers...")
        for p in processes:
            if p.is_alive():
                p.terminate()
        for p in processes:
            p.join(timeout=5)
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        for i in range(num_workers):
            p = multiprocessing.Process(
                target=run_server_worker,
                args=(i + 1,) + worker_args,
                daemon=False
            )
            p.start()
            processes.append(p)
            print(f"Started worker process {i + 1} (PID: {p.pid})")
        
        print(f"\n{'='*60}")
        print(f"Multiprocessing SMTP server running with {num_workers} workers")
        print(f"SMTPS: {args.host}:{args.port_465}")
        print(f"STARTTLS: {args.host}:{args.port_587}")
        print(f"{'='*60}")
        print("Press Ctrl+C to stop all workers\n")
        
        # Wait for all processes
        for p in processes:
            p.join()
            
    except KeyboardInterrupt:
        signal_handler(None, None)

if __name__ == "__main__":
    # Use 'spawn' method for better compatibility (required on some systems)
    multiprocessing.set_start_method('spawn', force=True)
    main()

