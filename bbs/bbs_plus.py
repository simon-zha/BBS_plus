# BBS+ Signature Algorithm
# This code implements the BBS+ signature algorithm
# This BBS+ signature scheme used bilinear groups to produce a signature for a verctor of messages.

import secrets
from .curve import BilinearGroup

class BBSPlus:
    
    def __init__(self):
        self.group = BilinearGroup()
    
    # Algorithm 2.1 BBS+Gen
    def gen(self, message_count):
        secret_key = self.group.random_scalar()
        X = self.group.multiply_g2(self.group.G2, secret_key)
        H = []

        for i in range(message_count + 1):
            seed = f"H_{i}".encode()
            h_i = self.group.hash_to_g1(seed)
            H.append(h_i)
        
        public_key = {
            'H': H,
            'X': X
        }

        return secret_key, public_key
    
    # Algorithm 2.2 BBS+Sign
    def sign(self, secret_key, messages, public_key):
        e = self.group.random_scalar()
        s = self.group.random_scalar()
        return self.sign_with_params(secret_key, messages, public_key['H'], e, s)
    
    def sign_with_params(self, secret_key, messages, H, e, s):
        B = self.group.G1
        B = self.group.add_g1(B, self.group.multiply_g1(H[0], s))
        
        for i, message in enumerate(messages):
            term = self.group.multiply_g1(H[i + 1], message % self.group.q)
            B = self.group.add_g1(B, term)
        
        denominator = (secret_key + e) % self.group.q
        denominator_inv = self.group.inverse_scalar(denominator)
        A = self.group.multiply_g1(B, denominator_inv)
        
        return {'A': A, 'e': e, 's': s}


    # Algorithm 2.3 BBS+Verify
    def verify(self, public_key, messages, signature):

        A = signature['A']
        e = signature['e']
        s = signature['s']
        H = public_key['H']
        X = public_key['X']

        B = self.group.G1
        B = self.group.add_g1(B, self.group.multiply_g1(H[0], s))
        
        for i, message in enumerate(messages):
            term = self.group.multiply_g1(H[i + 1], message % self.group.q)
            B = self.group.add_g1(B, term)
        
        X_plus_eG2 = self.group.add_g2(X, self.group.multiply_g2(self.group.G2, e))
        
        left_pairing = self.group.pairing(A, X_plus_eG2)
        right_pairing = self.group.pairing(B, self.group.G2)
        
        return left_pairing == right_pairing 



