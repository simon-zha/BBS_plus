# This file is to provide the elliptic curve operations required for the BBS+ signature algorithm.
# It encapsulates the relevant operations of bilinear groups (BLS12-381 curve) 

import hashlib
import secrets
from py_ecc import bls12_381
from py_ecc.fields import bls12_381_FQ
from py_ecc.fields import bls12_381_FQ2
class BilinearGroup:

    def __init__(self):
        self.curve = bls12_381
        self.q = bls12_381.curve_order
        self.G1 = bls12_381.G1
        self.G2 = bls12_381.G2

    def random_scalar(self):
        return secrets.randbelow(self.q)

    def hash_to_g1(self, message):
        hash_bytes = hashlib.sha256(message.encode() if isinstance(message, str) else message).digest()
        scalar = int.from_bytes(hash_bytes, 'big') % self.q
        return self.curve.multiply(self.G1, scalar)
    
    def multiply_g1(self, point, scalar):
        return bls12_381.multiply(point, scalar % self.q)

    def multiply_g2(self, point, scalar):
        return bls12_381.multiply(point, scalar % self.q)
    
    def add_g1(self, point1, point2):
        return bls12_381.add(point1, point2)
    
    def add_g2(self, point1, point2):
        return bls12_381.add(point1, point2)
    
    def pairing(self, g1_point, g2_point):
        return bls12_381.pairing(g2_point, g1_point)
    
    def inverse_scalar(self, scalar):
        return pow(scalar, self.q - 2, self.q)
    
    # Serialization methods for bls12_381
    # simply convert the coordinates to intergets then concatenate into strings
    def serialize_g1_point(self, point):
        # Handle both FQ and int types
        if hasattr(point[0], 'n'):
            # FQ type - get the underlying integer value
            x = point[0].n
            y = point[1].n
        else:
            # Regular integer
            x = point[0]
            y = point[1]
        return f"{x}:{y}"
    
    def serialize_g2_point(self, point):
        # G2 point structure: ((FQ2, FQ2))
        # Each FQ2 has .coeffs[0] and .coeffs[1]
        try:
            return f"{point[0].coeffs[0]}:{point[0].coeffs[1]}:{point[1].coeffs[0]}:{point[1].coeffs[1]}"
        except AttributeError:
            # Fallback for different G2 point structures
            return f"{point[0][0]}:{point[0][1]}:{point[1][0]}:{point[1][1]}"

    # deserilization for g1 and g2 points
    def deserialize_g1_point(self, point_str):
        coords = point_str.split(':')
        # Create proper bls12_381_FQ elements to match BBS+
        x = bls12_381_FQ(int(coords[0]))
        y = bls12_381_FQ(int(coords[1]))
        return (x, y)
    
    def deserialize_g2_point(self, point_str):
        coords = point_str.split(':')
        # Create proper bls12_381_FQ2 elements to match BBS+
        fq2_a = bls12_381_FQ2([int(coords[0]), int(coords[1])])
        fq2_b = bls12_381_FQ2([int(coords[2]), int(coords[3])])
        return (fq2_a, fq2_b)

