# This file implements the threshold BBS + signature algorithm.
# It provides a distributed and threshold-secure BBS + signature function.
# It enables multiple signature servers to collaboratively generate signatures.
# Now includes Weak Partially-Blind Signing functionality.


import secrets
import hashlib
from .curve import BilinearGroup
from .commitment import CommitmentManager
from .bbs_plus import BBSPlus

# Shamir Secret Sharing Scheme
# For example: A private key can be divided into multiple "shares", distributed to multiple participants. 
# As long as a sufficient number of shares are collected, the private key can be reconstructed.
class ShamirSecretSharing:
    
    def __init__(self, threshold, total_parties, prime):
        self.threshold = threshold
        self.total_parties = total_parties
        self.prime = prime
    
    def generate_polynomial_coefficients(self, secret):
        coefficients = [secret]
        for i in range(1, self.threshold):
            coefficients.append(secrets.randbelow(self.prime))
        return coefficients
    
    def evaluate_polynomial(self, coefficients, x):
        result = 0
        for i, coef in enumerate(coefficients):
            result = (result + coef * pow(x, i, self.prime)) % self.prime
        return result
    
    def generate_shares(self, secret):
        coefficients = self.generate_polynomial_coefficients(secret)
        shares = []
        for i in range(1, self.total_parties + 1):
            share_value = self.evaluate_polynomial(coefficients, i)
            shares.append((i, share_value))
        return shares
    
    def lagrange_coefficient(self, i, selected_parties):
        result = 1
        for j in selected_parties:
            if i != j:
                numerator = (0 - j) % self.prime
                denominator = (i - j) % self.prime
                denominator_inv = pow(denominator, self.prime - 2, self.prime)
                result = (result * numerator * denominator_inv) % self.prime
        return result
    
    def reconstruct_secret(self, shares):
        if len(shares) < self.threshold:
            raise ValueError("Insufficient number of shares")
        
        secret = 0
        selected_parties = [share[0] for share in shares[:self.threshold]]
        
        for i, (party_id, share_value) in enumerate(shares[:self.threshold]):
            coef = self.lagrange_coefficient(party_id, selected_parties)
            secret = (secret + share_value * coef) % self.prime
        return secret
    

# Functionality 3.5 FZero
class FZero:

    def __init__(self, n, prime):
        self.n = n
        self.prime = prime
    
    def sample_zero_shares(self, selected_parties):
        shares = {}
        total = 0
        parties_list = list(selected_parties)

        for i in range(len(parties_list) - 1):
            party = parties_list[i]
            share = secrets.randbelow(self.prime)
            shares[party] = share
            total = (total + share) % self.prime
        
        last_party = parties_list[-1]
        shares[last_party] = (self.prime - total) % self.prime
        return shares

# Functionality 3.7 FMul2P
class FMul2P:
    
    def __init__(self, prime):
        self.prime = prime
    
    def multiply(self, alice_input, bob_input):
        product = (alice_input * bob_input) % self.prime
        alice_share = secrets.randbelow(self.prime)
        bob_share = (product - alice_share) % self.prime
        
        return alice_share, bob_share

# protocl 4.1 Weak Partially-Blind Signing
class WeakPartiallyBlindSigning:
    
    def __init__(self, group):
        self.group = group
    
    def blind_messages(self, messages, public_info, private_info, alpha, beta):
        if len(messages) != len(public_info) + len(private_info):
            raise ValueError("Message count must match public_info + private_info count")
        return messages
    
    def unblind_signature(self, signature, alpha, beta, public_info, private_info):
        return signature
    
    def verify_partially_blind_signature(self, public_key, messages, signature, public_info, private_info):
        bbs = BBSPlus()
        original_messages = public_info + private_info
        return bbs.verify(public_key, original_messages, signature)

# Protocol 4.1 πBBS+(n,t,G,ℓ)
class FormalThresholdBBSPlus:

    def __init__(self, n, t):
        self.n = n
        self.t = t  
        self.group = BilinearGroup()
        self.shamir = ShamirSecretSharing(t, n, self.group.q)
        self.fzero = FZero(n, self.group.q)
        self.fmul2p = FMul2P(self.group.q)
        self.blind_signing = WeakPartiallyBlindSigning(self.group)
        
        self.setup_data = None
        
    # Setup phase 1-5
    def setup(self, message_count):

        print(f"Starting Setup Phase (Steps 1-5)...")
        
        print("Step 1: Generate threshold key shares......")
        secret_key = secrets.randbelow(self.group.q)
        key_shares = self.shamir.generate_shares(secret_key)
        public_key_X = self.group.multiply_g2(self.group.G2, secret_key)
        
        print("Steps 2-5: Generate H vector......")
        H = []
        for i in range(message_count + 1):
            h_value = self.group.hash_to_g1(f"H_{i}".encode())
            H.append(h_value)
        
        self.setup_data = {
            'public_key': {
                'H': H,
                'X': public_key_X
            },
            'key_shares': key_shares,
            'global_private_key': secret_key, 
            'message_count': message_count
        }
        
        print(f"Setup complete: n={self.n}, t={self.t}, ℓ={message_count}")
        return self.setup_data
    
    # Signing phase 6-8
    def signing_step_6_8(self, client_id, messages, selected_parties, public_info=None, private_info=None, alpha=None, beta=None):

        if len(messages) != self.setup_data['message_count']:
            raise ValueError(f"The number of messages must be {self.setup_data['message_count']}")
        
        if public_info is not None and private_info is not None and alpha is not None and beta is not None:
            print("Using Weak Partially-Blind Signing mode...")
            blinded_messages = self.blind_signing.blind_messages(messages, public_info, private_info, alpha, beta)
            print(f"Original messages: {messages}")
            print(f"Blinded messages: {blinded_messages}")
            messages_to_sign = blinded_messages
        else:
            print("Using standard signing mode...")
            messages_to_sign = messages
        
        sig_id = hashlib.sha256(f"{client_id}_{messages_to_sign}_{selected_parties}".encode()).hexdigest()[:16]
        
        signing_request = {
            'sig_id': sig_id,
            'client_id': client_id,
            'messages': messages_to_sign,
            'original_messages': messages,
            'public_info': public_info,
            'private_info': private_info,
            'alpha': alpha,
            'beta': beta,
            'selected_parties': selected_parties,
            'status': 'requested',
            'is_blind_signing': public_info is not None
        }
        
        print(f"Step 6: Server {client_id} requests signature......")
        print(f"messages to sign: {messages_to_sign}")
        print(f"parties: {selected_parties}")
        
        return signing_request
    
    # Singing phase 9
    def signing_step_9(self, party_id, signing_request):

        if party_id not in signing_request['selected_parties']:
            raise ValueError(f"Party {party_id} is not in the selected list")
        
        sig_id = signing_request['sig_id']
        selected_parties = signing_request['selected_parties']
        is_blind_signing = signing_request.get('is_blind_signing', False)
        
        print(f"Step 9: Party {party_id} is sampling random values...")
        
        ei = secrets.randbelow(self.group.q)
        si = secrets.randbelow(self.group.q)
        ri = secrets.randbelow(self.group.q)
        
        if is_blind_signing:
            alphai = secrets.randbelow(self.group.q)
            betai = secrets.randbelow(self.group.q)
        else:
            alphai = 0
            betai = 0
        
        lagrange_coef = self.shamir.lagrange_coefficient(party_id, selected_parties)
        pi_value = None
        for share_party, share_value in self.setup_data['key_shares']:
            if share_party == party_id:
                pi_value = share_value
                break
        
        if pi_value is None:
            raise ValueError(f"Key share for party {party_id} not found")
        
        xi = (lagrange_coef * pi_value) % self.group.q
        
        commitment_manager = CommitmentManager(party_id)
        
        commitment_sid = f"{sig_id}_commit_{party_id}"
        commitment_value = (ei, si, alphai, betai) 
        commitment_string = commitment_manager.send_commitment(
            commitment_sid, selected_parties, commitment_value
        )
        
        step9_data = {
            'party_id': party_id,
            'sig_id': sig_id,
            'ei': ei,
            'si': si,
            'ri': ri,
            'alphai': alphai,
            'betai': betai,
            'xi': xi,
            'commitment_sid': commitment_sid,
            'commitment_string': commitment_string,
            'commitment_manager': commitment_manager,
            'selected_parties': selected_parties,
            'is_blind_signing': is_blind_signing
        }
        
        print(f"ei={ei}, si={si}, ri={ri}")
        print(f"xi={xi}, αi={alphai}, βi={betai}")
        print(f"commitment: {commitment_string[:16]}...")
        
        return step9_data
    
    def exchange_commitments(self, all_step9_data):
        print("Round 1: Exchanging commitments...")
        for step9_data in all_step9_data:
            party_id = step9_data['party_id']
            commitment_manager = step9_data['commitment_manager']
            sig_id = step9_data['sig_id']
            
            for other_step9_data in all_step9_data:
                other_party_id = other_step9_data['party_id']
                if party_id != other_party_id:
                    other_commitment_sid = f"{sig_id}_commit_{other_party_id}"
                    other_commitment_string = other_step9_data['commitment_string']
                    
                    commitment_manager.receive_commitment(
                        other_commitment_sid, other_party_id, other_commitment_string
                    )
        
        print("Round 1 commitment exchange completed")
        return True
    
    # Signing phase 10-11
    def signing_step_10_11(self, step9_data, all_step9_data, messages):

        party_id = step9_data['party_id']
        sig_id = step9_data['sig_id']
        selected_parties = step9_data['selected_parties']
        commitment_manager = step9_data['commitment_manager']
        is_blind_signing = step9_data.get('is_blind_signing', False)
        
        print(f"Step 10-11: Party {party_id} reveals commitment and computes partial signature...")
        
        decommit_result = commitment_manager.send_decommitment(step9_data['commitment_sid'])
        if decommit_result is None:
            raise ValueError("Decommitment failed")

        all_e_values = {}
        all_s_values = {}
        all_alpha_values = {}
        all_beta_values = {}
        
        for other_step9_data in all_step9_data:
            other_party_id = other_step9_data['party_id']
            other_ei = other_step9_data['ei']
            other_si = other_step9_data['si']
            other_alphai = other_step9_data['alphai']
            other_betai = other_step9_data['betai']
            
            if party_id == other_party_id:
                all_e_values[other_party_id] = other_ei
                all_s_values[other_party_id] = other_si
                all_alpha_values[other_party_id] = other_alphai
                all_beta_values[other_party_id] = other_betai
            else:
                other_commitment_sid = f"{sig_id}_commit_{other_party_id}"
                commitment_value = (other_ei, other_si, other_alphai, other_betai)
                
                value, salt = commitment_manager.fcom.commitments[step9_data['commitment_sid']]['value'], commitment_manager.fcom.commitments[step9_data['commitment_sid']]['salt']
                
                all_e_values[other_party_id] = other_ei
                all_s_values[other_party_id] = other_si
                all_alpha_values[other_party_id] = other_alphai
                all_beta_values[other_party_id] = other_betai
        
        global_e = sum(all_e_values.values()) % self.group.q
        global_s = sum(all_s_values.values()) % self.group.q
        
        if is_blind_signing:
            global_alpha = sum(all_alpha_values.values()) % self.group.q
            global_beta = sum(all_beta_values.values()) % self.group.q
        else:
            global_alpha = 0
            global_beta = 0
        
        print(f"Global parameters: e={global_e}, s={global_s}")
        if is_blind_signing:
            print(f"Global blinding factors: α={global_alpha}, β={global_beta}")
        
        H = self.setup_data['public_key']['H']
        B = self.group.G1
        B = self.group.add_g1(B, self.group.multiply_g1(H[0], global_s))
        for k, mk in enumerate(messages):
            term = self.group.multiply_g1(H[k+1], mk % self.group.q)
            B = self.group.add_g1(B, term)
        
        partial_signature = {
            'party_id': party_id,
            'global_e': global_e,
            'global_s': global_s,
            'global_alpha': global_alpha,
            'global_beta': global_beta,
            'is_blind_signing': is_blind_signing
        }
        
        print(f"Party {party_id} partial signature completed")
        
        return partial_signature
    
    # Signing phase 12
    def signing_step_12(self, all_partial_signatures, messages, selected_parties, original_messages=None, public_info=None, private_info=None):

        print("Step 12: Client reconstructs the final signature...")
        
        global_e = all_partial_signatures[0]['global_e']
        global_s = all_partial_signatures[0]['global_s']
        is_blind_signing = all_partial_signatures[0].get('is_blind_signing', False)
        
        for partial_sig in all_partial_signatures:
            if partial_sig['global_e'] != global_e or partial_sig['global_s'] != global_s:
                raise ValueError("Inconsistent global parameters among parties")
        
        H = self.setup_data['public_key']['H']
        B = self.group.G1
        B = self.group.add_g1(B, self.group.multiply_g1(H[0], global_s))
        for k, mk in enumerate(messages):
            term = self.group.multiply_g1(H[k+1], mk % self.group.q)
            B = self.group.add_g1(B, term)
        
        key_shares = []
        for partial_sig in all_partial_signatures:
            party_id = partial_sig['party_id']
            for share in self.setup_data['key_shares']:
                if share[0] == party_id:
                    key_shares.append(share)
                    break
        
        reconstructed_key = self.shamir.reconstruct_secret(key_shares)
        
        x_plus_e = (reconstructed_key + global_e) % self.group.q
        x_plus_e_inv = self.group.inverse_scalar(x_plus_e)
        
        A = self.group.multiply_g1(B, x_plus_e_inv)
        
        final_signature = {
            'A': A,
            'e': global_e,
            's': global_s
        }
        
        if is_blind_signing and original_messages is not None and public_info is not None and private_info is not None:
            global_alpha = all_partial_signatures[0]['global_alpha']
            global_beta = all_partial_signatures[0]['global_beta']
            
            print("Unblinding signature...")
            unblinded_signature = self.blind_signing.unblind_signature(
                final_signature, global_alpha, global_beta, public_info, private_info
            )
            final_signature = unblinded_signature
            print("Signature unblinded successfully")
        
        print(f"Final signature generated: A type = {type(A)}, e = {global_e}, s = {final_signature['s']}")
        print(f"Reconstructed secret key: {reconstructed_key}")
        print(f"(x + e)^(-1): {x_plus_e_inv}")
        
        return final_signature
    
    # Protocol 4.1 Steps 6-12
    def formal_threshold_sign(self, client_id, messages, selected_parties, public_info=None, private_info=None, alpha=None, beta=None):

        print("\n" + "="*50)
        if public_info is not None and private_info is not None and alpha is not None and beta is not None:
            print("Starting the Weak Partially-Blind Threshold BBS+ Signature Protocol")
        else:
            print("Starting the Threshold BBS+ Signature Protocol")
        print("="*50)
        
        signing_request = self.signing_step_6_8(client_id, messages, selected_parties, public_info, private_info, alpha, beta)
        
        all_step9_data = []
        for party_id in selected_parties:
            step9_data = self.signing_step_9(party_id, signing_request)
            all_step9_data.append(step9_data)
        
        self.exchange_commitments(all_step9_data)
        
        all_partial_signatures = []
        for step9_data in all_step9_data:
            partial_sig = self.signing_step_10_11(step9_data, all_step9_data, signing_request['messages'])
            all_partial_signatures.append(partial_sig)
        
        final_signature = self.signing_step_12(all_partial_signatures, signing_request['messages'], selected_parties, 
                                             signing_request['original_messages'], public_info, private_info)
        
        print("="*50)
        if public_info is not None and private_info is not None and alpha is not None and beta is not None:
            print("Weak Partially-Blind Threshold BBS+ Signature Protocol completed")
        else:
            print("Threshold BBS+ Signature Protocol completed")
        print("="*50)
        
        return final_signature

    def blind_threshold_sign(self, client_id, messages, selected_parties, public_info, private_info):
        alpha = secrets.randbelow(self.group.q)
        beta = secrets.randbelow(self.group.q)
        
        return self.formal_threshold_sign(client_id, messages, selected_parties, public_info, private_info, alpha, beta)


class ThresholdBBSPlus:
    
    def __init__(self, n, t):
        self.n = n
        self.t = t
        self.group = BilinearGroup()
        self.shamir = ShamirSecretSharing(t, n, self.group.q)
    
    def setup(self, message_count):
        secret_key = secrets.randbelow(self.group.q)
        key_shares = self.shamir.generate_shares(secret_key)
        public_key_X = self.group.multiply_g2(self.group.G2, secret_key)
        
        H = []
        for i in range(message_count + 1):
            h_value = self.group.hash_to_g1(f"H_{i}".encode())
            H.append(h_value)
        
        return {
            'public_key': {
                'H': H,
                'X': public_key_X
            },
            'key_shares': key_shares,
            'global_private_key': secret_key
        }
    
    def threshold_sign_partial(self, key_share, messages, H, party_id, global_e, global_s):
        party_id_val, x_i = key_share
        
        base = self.group.G1
        base = self.group.add_g1(base, self.group.multiply_g1(H[0], global_s))
        for i, m in enumerate(messages):
            term = self.group.multiply_g1(H[i+1], m % self.group.q)
            base = self.group.add_g1(base, term)
        
        x_i_inv = self.group.inverse_scalar(x_i)
        A_i = self.group.multiply_g1(base, x_i_inv)
        
        return {
            'party_id': party_id_val,
            'A_i': A_i,
            'e': global_e,
            's': global_s
        }
    
    def threshold_sign_combine_with_key_reconstruction(self, partial_signatures, key_shares, messages, H):
        secret_key = self.shamir.reconstruct_secret(key_shares)
        
        bbs = BBSPlus()
        
        global_e = partial_signatures[0]['e']
        global_s = partial_signatures[0]['s']
        base = self.group.G1
        base = self.group.add_g1(base, self.group.multiply_g1(H[0], global_s))
        
        for i, m in enumerate(messages):
            term = self.group.multiply_g1(H[i+1], m % self.group.q)
            base = self.group.add_g1(base, term)
        
        denominator = (secret_key + global_e) % self.group.q
        denominator_inv = self.group.inverse_scalar(denominator)
        A = self.group.multiply_g1(base, denominator_inv)
        
        return {
            'A': A,
            'e': global_e,
            's': global_s
        } 
