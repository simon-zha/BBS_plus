#!/usr/bin/env python3
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import statistics
from bbs.bbs_plus import BBSPlus
from bbs.threshold import FormalThresholdBBSPlus
from bbs.curve import BilinearGroup


# how many messages to sign at once
msg_lengths = [1, 15, 30]  
# total servers in threshold setup
servers = 4  
# threshold for need at least 3 servers to sign
threshold = 3  
iterations = 10  # run each test 10 times to get average


#Run a function and time how long it takes
def time_it(func, *args, **kwargs):
    
    start = time.time()
    result = func(*args, **kwargs)
    end = time.time()
    return result, end - start

#Print out time costs avg
def show_avg(test_name, times):
    
    avg = statistics.mean(times)
    
    print(f"{test_name}:")
    print(f"Average: {avg:.1f}s")


#Test basic elliptic curve operations to see how fast they are
def test_curve_ops():
    
    print("=== Curve Operations ===")
    print("Testing basic crypto operations...")
    
    group = BilinearGroup()
    
    # Test G1 point multiplication (used a lot in BBS+)
    print("Testing G1 scalar multiplication...")
    g1_times = []
    for i in range(iterations):
        scalar = group.random_scalar()
        _, elapsed = time_it(group.multiply_g1, group.G1, scalar)
        g1_times.append(elapsed)
        if i % 3 == 0:  # don't spam too much
            print(f" At {i+1} times: {elapsed:.1f}s")
    
    # Test G2 point multiplication (for public keys)
    print("Testing G2 scalar multiplication...")
    g2_times = []
    for i in range(iterations):
        scalar = group.random_scalar()
        _, elapsed = time_it(group.multiply_g2, group.G2, scalar)
        g2_times.append(elapsed)
    
    # Test pairing operations (the expensive part)
    print("Test bilinear pairings...")
    pairing_times = []
    for i in range(iterations):
        # Make random points to pair
        g1_point = group.multiply_g1(group.G1, group.random_scalar())
        g2_point = group.multiply_g2(group.G2, group.random_scalar())
        _, elapsed = time_it(group.pairing, g1_point, g2_point)
        pairing_times.append(elapsed)
        if i % 3 == 0:
            print(f"  Pairing {i+1}: {elapsed:.1f}s")
    
    show_avg("G1 scalar mult", g1_times)
    show_avg("G2 scalar mult", g2_times)
    show_avg("Bilinear pairing", pairing_times)
    print()

# Test how long it takes to generate keys for different message sizes
def test_keygen():
    print("=== Key Generation ===")
    
    for msg_len in msg_lengths:
        print(f"\nTesting with {msg_len} messages:")
        
        setup_times = []
        
        for i in range(iterations):
            # Create new threshold instance each time to get time costs
            threshold_bbs = FormalThresholdBBSPlus(servers, threshold)
            
            _, elapsed = time_it(threshold_bbs.setup, msg_len)
            setup_times.append(elapsed)
            print(f" Setup {i+1}: {elapsed:.1f}s")
        
        show_avg(f"Setup for {msg_len} messages", setup_times)

# test the full threshold signing process
def test_threshold_signing():
    
    print("=== Threshold Signing ===")
    print("Testing complete threshold signature generation...")
    
    for msg_len in msg_lengths:
        
        # setup once for this test
        threshold_bbs = FormalThresholdBBSPlus(servers, threshold)
        setup_data = threshold_bbs.setup(msg_len)
        print(f"  Setup done for {msg_len} messages")
        
        # dummy messages to sign
        messages = [i + 100 for i in range(msg_len)]  # just use numbers 100, 101, 102...
        parties = list(range(1, threshold + 1))  # use first 3 parties
        
        signing_times = []
        
        for i in range(iterations):
            print(f"  Signing attempt {i+1}...")
            
            # time costs for the whole signing process
            start_time = time.time()
            
            # step 1: create signing request
            signing_request = threshold_bbs.signing_step_6_8("client_1", messages, parties)
            
            # step 2: each party does their first round
            round1_data = []
            for party_id in parties:
                step9_data = threshold_bbs.signing_step_9(party_id, signing_request)
                round1_data.append(step9_data)
            
            # Step 3: exchange commitments (communication round)
            threshold_bbs.exchange_commitments(round1_data)
            
            # Step 4: each party does their second round
            partial_sigs = []
            for step9_data in round1_data:
                partial_sig = threshold_bbs.signing_step_10_11(step9_data, round1_data, messages)
                partial_sigs.append(partial_sig)
            
            # Step 5 combine partial signatures into final signature
            final_sig = threshold_bbs.signing_step_12(partial_sigs, messages, parties)
            
            elapsed = time.time() - start_time
            signing_times.append(elapsed)
            print(f"    Completed in {elapsed:.1f}s")
        
        show_avg(f"Threshold signing ({msg_len} msgs)", signing_times)

# Test signature verification, with single signatureand batch signatures
def test_verification():
    print("=== Signature Verification ===")
    
    bbs = BBSPlus()
    
    for msg_len in msg_lengths:
        print(f"\nTesting verification with {msg_len} messages:")
        
        # Generate a signature to verify
        messages = [i + 200 for i in range(msg_len)]  # use numbers 200, 201, 202...
        sk, pk = bbs.gen(msg_len)
        signature = bbs.sign(sk, messages, pk)
        print(f"  Generated test signature for {msg_len} messages")
        
        # Test single verification
        verify_times = []
        for i in range(iterations):
            _, elapsed = time_it(bbs.verify, pk, messages, signature)
            verify_times.append(elapsed)
        
        show_avg(f"Verify ({msg_len} msgs)", verify_times)
        
        print()


def main():
    print("BBS+ Threshold Signature Benchmark")
 
    # Run all the tests
    test_curve_ops()
    test_keygen() 
    test_threshold_signing()
    test_verification()
    
    print("=== Benchmark Complete ===")
      

if __name__ == "__main__":
    main()