#!/usr/bin/env python
# Multi-threaded test to reproduce SigV4 invalid signature errors

import argparse
import sys
import ssl
import time
import threading
import boto3
<<<<<<< HEAD
=======
import os
import urllib.request
>>>>>>> ca15ae9 (Add test to reproduce connection errors)
from datetime import datetime
from cassandra.cluster import Cluster
from cassandra_sigv4.auth import SigV4AuthProvider
from boto3 import Session

def create_role_arn(account_id, role_name):
    """Create role ARN from account ID and role name."""
    return f"arn:aws:iam::{account_id}:role/{role_name}"

def create_short_lived_session(role_arn, region, role_session_duration=900):
    """
    Create a session with short-lived credentials (15 minutes).
    """
    sts_client = boto3.client('sts', region_name=region)
    session_name = f"keyspaces-test-{int(time.time())}"
    assumed_role = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        DurationSeconds=role_session_duration
    )

    credentials = assumed_role['Credentials']
    print(f"[{datetime.now()}] Session created successfully. Expires at: {credentials['Expiration']}")

    return Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )

<<<<<<< HEAD
def worker_thread(thread_id, session, endpoint, role_session_duration, results):
=======
def download_starfield_certificate():
    """Download the Starfield certificate at runtime."""
    cert_url = "https://certs.secureserver.net/repository/sf-class2-root.crt"
    cert_file = "sf-class2-root.crt.temp"
    
    # Download the certificate
    print(f"[{datetime.now()}] Downloading Starfield certificate...")
    urllib.request.urlretrieve(cert_url, cert_file)
    print(f"[{datetime.now()}] Certificate downloaded successfully")
    
    return cert_file

def worker_thread(thread_id, session, endpoint, role_session_duration, results, cert_file):
>>>>>>> ca15ae9 (Add test to reproduce connection errors)
    """Worker thread that connects and queries Keyspaces."""
    print(f"[{datetime.now()}] Thread {thread_id}: Starting")
    
    try:
        # Create auth provider with session credentials
        auth_provider = SigV4AuthProvider(session=session)
        
        # Create SSL context
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
<<<<<<< HEAD
        ssl_context.load_verify_locations('sf-class2-root.crt')
=======
        ssl_context.load_verify_locations(cert_file)
>>>>>>> ca15ae9 (Add test to reproduce connection errors)
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        # Create cluster
        cluster = Cluster(
            [endpoint], 
            auth_provider=auth_provider,
            ssl_context=ssl_context,
            port=9142
        )
        
        # Connect and run queries
        print(f"[{datetime.now()}] Thread {thread_id}: Connecting to cluster")
        session = cluster.connect()
        print(f"[{datetime.now()}] Thread {thread_id}: Connected successfully")
        
        start_time = time.time()
        end_time = start_time + role_session_duration
        query_count = 0
        
        while time.time() < end_time:
            try:
                print(f"[{datetime.now()}] Thread {thread_id}: Executing rapid query batch {query_count // 10 + 1}")
                
                # Execute 10 rapid queries to force connection scaling
                for i in range(10):
                    session.execute("SELECT keyspace_name FROM system_schema.keyspaces LIMIT 1")
                    query_count += 1
                
                print(f"[{datetime.now()}] Thread {thread_id}: Batch completed - 10/10 successful")
                time.sleep(1)  # Brief pause between batches
                
            except Exception as e:
                print(f"[{datetime.now()}] Thread {thread_id}: Query failed - {e}")
                if "Invalid signature" in str(e) or "Bad credentials" in str(e):
                    results[thread_id]['signature_errors'] += 1
                results[thread_id]['query_errors'] += 1
                time.sleep(2)
        
        cluster.shutdown()
        results[thread_id]['queries'] = query_count
        results[thread_id]['success'] = True
        print(f"[{datetime.now()}] Thread {thread_id}: Completed successfully")
        
    except Exception as e:
        print(f"[{datetime.now()}] Thread {thread_id}: Failed - {e}")
        results[thread_id]['success'] = False
        results[thread_id]['error'] = str(e)

def run_multithreaded_test(region, endpoint, account_id, role_name, num_threads=5, test_duration=10):

    '''
    This test attempts to reproduce signature errors like below that a customer reported to have
    run into when botocore session was created using instance role credentials to instantiate the driver plugin in a multi threaded
    environment. The test has not been able to reproduce the reported errors.

    <AsyncoreConnection(139806986298176) 172.16.0.195:9142>
    DEBUG:2025-06-17 20:59:57,997:cassandra.connection - Sent StartupMessage on <AsyncoreConnection(139806986298176) 172.16.0.195:9142>
    DEBUG:2025-06-17 20:59:57,998:cassandra.connection - Got AuthenticateMessage on new connection (139806986298176) from 172.16.0.195:9142: org.apache.cassandra.auth.PasswordAuthenticator
    DEBUG:2025-06-17 20:59:57,999:cassandra.connection - Sending SASL-based auth response on <AsyncoreConnection(139806986298176) 172.16.0.195:9142>
    DEBUG:2025-06-17 20:59:58,000:cassandra.connection - Responding to auth challenge on <AsyncoreConnection(139806986298176) 172.16.0.195:9142>
    DEBUG:2025-06-17 20:59:58,004:cassandra.connection - Received ErrorMessage on new connection (139806986298176) from 172.16.0.195:9142: Error from server: code=0100 [Bad credentials] message="Authentication failure: Invalid signature"
    DEBUG:2025-06-17 20:59:58,004:cassandra.connection - Defuncting connection (139806986298176) to 172.16.0.195:9142:
    Traceback (most recent call last):
      File "cassandra/connection.py", line 600, in cassandra.connection.defunct_on_error.wrapper
      File "cassandra/connection.py", line 1451, in cassandra.connection.Connection._handle_auth_response
    cassandra.AuthenticationFailed: Failed to authenticate to 172.16.0.195:9142: Error from server: code=0100 [Bad credentials] message="Authentication failure: Invalid signature"
    DEBUG:2025-06-17 20:59:58,004:cassandra.io.asyncorereactor - Closing connection (139806986298176) to 172.16.0.195:9142
    DEBUG:2025-06-17 20:59:58,004:cassandra.io.asyncorereactor - Closed socket to 172.16.0.195:9142
    WARNING:2025-06-17 20:59:58,004:cassandra.cluster - Host 172.16.0.195:9142 has been marked down
    '''

    """Run multi-threaded test to reproduce signature errors."""
    role_arn = create_role_arn(account_id, role_name)
    
    print(f"[{datetime.now()}] Starting multi-threaded test")
    print(f"Threads: {num_threads}")
    print(f"Test duration: {test_duration} minutes")
    print(f"Role: {role_arn}")
    
    # Initialize results tracking
    results = {}
    for i in range(num_threads):
        results[i] = {
            'success': False,
            'queries': 0,
            'query_errors': 0,
            'signature_errors': 0,
            'error': None
        }
    
    # Create and start threads
    threads = []
    role_session_duration = test_duration * 60

    # Initialize threads list
    threads = []
    
    cert_file = None
    try:
        # Download the certificate
        cert_file = download_starfield_certificate()
        
        # Create shared session from short lived credentials derived from a role to check if we run into errors when role's session expires (when logic to trigger explicit credential refresh doesn't exist)
        session = create_short_lived_session(role_arn, region)
        
        for i in range(num_threads):
            thread = threading.Thread(
                target=worker_thread,
                args=(i, session, endpoint, role_session_duration, results, cert_file)
            )
            threads.append(thread)
            thread.start()
            time.sleep(1)  # Stagger thread starts slightly
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
            
    except Exception as e:
        print(f"[{datetime.now()}] Error in test execution: {e}")
        return False
    finally:
        # Clean up the certificate file
        if cert_file and os.path.exists(cert_file):
            os.remove(cert_file)
            print(f"[{datetime.now()}] Removed temporary certificate file")
    
    # Print results
    print(f"\n[{datetime.now()}] Multi-threaded test completed")
    print("=" * 50)
    
    total_queries = 0
    total_errors = 0
    total_signature_errors = 0
    successful_threads = 0
    
    for thread_id, result in results.items():
        print(f"Thread {thread_id}:")
        print(f"  Success: {result['success']}")
        print(f"  Queries: {result['queries']}")
        print(f"  Query Errors: {result['query_errors']}")
        print(f"  Signature Errors: {result['signature_errors']}")
        if result['error']:
            print(f"  Error: {result['error']}")
        print()
        
        total_queries += result['queries']
        total_errors += result['query_errors']
        total_signature_errors += result['signature_errors']
        if result['success']:
            successful_threads += 1
    
    print("Summary:")
    print(f"  Successful threads: {successful_threads}/{num_threads}")
    print(f"  Total queries: {total_queries}")
    print(f"  Total errors: {total_errors}")
    print(f"  Signature errors: {total_signature_errors}")
    
    if total_signature_errors > 0:
        print(f"\n⚠️  REPRODUCED: {total_signature_errors} signature errors detected!")
        return False
    else:
        print("\n✅ No signature errors detected")
        return True

if __name__ == "__main__":
<<<<<<< HEAD
=======
    # Create .gitignore if it doesn't exist to ensure cert files aren't committed
    gitignore_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".gitignore")
    if not os.path.exists(gitignore_path):
        with open(gitignore_path, "w") as f:
            f.write("# Ignore certificate files\n*.crt\n*.crt.temp\n")
    else:
        # Ensure certificate patterns are in .gitignore
        with open(gitignore_path, "r") as f:
            content = f.read()
        if "*.crt" not in content:
            with open(gitignore_path, "a") as f:
                f.write("\n# Ignore certificate files\n*.crt\n*.crt.temp\n")
    
    parser = argparse.ArgumentParser(description="Multi-threaded test for SigV4 signature errors")
    parser.add_argument("--region", required=True, help="AWS region")
    parser.add_argument("--endpoint", required=True, help="Keyspaces endpoint")
    parser.add_argument("--account-id", required=True, help="AWS account ID for the role")
    parser.add_argument("--role-name", required=True, help="IAM role name to assume")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("--duration", type=int, default=10, help="Test duration in minutes")
    
    args = parser.parse_args()
    
    success = run_multithreaded_test(args.region, args.endpoint, args.account_id, args.role_name, args.threads, args.duration)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    # Create .gitignore if it doesn't exist to ensure cert files aren't committed
    gitignore_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".gitignore")
    if not os.path.exists(gitignore_path):
        with open(gitignore_path, "w") as f:
            f.write("# Ignore certificate files\n*.crt\n*.crt.temp\n")
    else:
        # Ensure certificate patterns are in .gitignore
        with open(gitignore_path, "r") as f:
            content = f.read()
        if "*.crt" not in content:
            with open(gitignore_path, "a") as f:
                f.write("\n# Ignore certificate files\n*.crt\n*.crt.temp\n")
    
>>>>>>> ca15ae9 (Add test to reproduce connection errors)
    parser = argparse.ArgumentParser(description="Multi-threaded test for SigV4 signature errors")
    parser.add_argument("--region", required=True, help="AWS region")
    parser.add_argument("--endpoint", required=True, help="Keyspaces endpoint")
    parser.add_argument("--account-id", required=True, help="AWS account ID for the role")
    parser.add_argument("--role-name", required=True, help="IAM role name to assume")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("--duration", type=int, default=10, help="Test duration in minutes")
    
    args = parser.parse_args()
    
    success = run_multithreaded_test(args.region, args.endpoint, args.account_id, args.role_name, args.threads, args.duration)
    sys.exit(0 if success else 1)