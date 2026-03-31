#!/usr/bin/env python3
import struct
import os

def analyze_r1cs(file_path):
    """分析R1CS头部信息"""
    if not os.path.exists(file_path):
        return None
    
    with open(file_path, 'rb') as f:
        magic = f.read(4)
        if magic != b'r1cs':
            return None
        
        version = struct.unpack('<I', f.read(4))[0]
        num_sections = struct.unpack('<I', f.read(4))[0]
        
        for i in range(num_sections):
            section_type = struct.unpack('<I', f.read(4))[0]
            section_size = struct.unpack('<Q', f.read(8))[0]
            section_data = f.read(section_size)
            
            if section_type == 1:  # Header
                reader = section_data
                pos = 0
                
                field_size = struct.unpack('<I', reader[pos:pos+4])[0]
                pos += 4 + field_size
                
                n_wires = struct.unpack('<I', reader[pos:pos+4])[0]
                pos += 4
                n_pub_out = struct.unpack('<I', reader[pos:pos+4])[0]
                pos += 4
                n_pub_in = struct.unpack('<I', reader[pos:pos+4])[0]
                pos += 4
                n_prv_in = struct.unpack('<I', reader[pos:pos+4])[0]
                
                primary = 1 + n_pub_out + n_pub_in + n_prv_in
                internal = n_wires - primary
                
                return {
                    'n_wires': n_wires,
                    'n_pub_out': n_pub_out,
                    'n_pub_in': n_pub_in,
                    'n_prv_in': n_prv_in,
                    'primary_signals': primary,
                    'internal_signals': internal
                }

# Analyze different circuits
circuits = [
    ('AND', 'target/circom_build/circomlib_and_main/circomlib_and_main.r1cs'),
    ('Matrix 4x4', 'target/circom_build/matrix_mul_4x4_main/matrix_mul_4x4_main.r1cs'),
    ('Poseidon', 'target/circom_build/circomlib_poseidon_main/circomlib_poseidon_main.r1cs'),
]

print("Signal Structure Comparison:")
print("=" * 70)

for name, circuit in circuits:
    result = analyze_r1cs(circuit)
    if result:
        print(f"\n{name}:")
        print(f"  Total wires:            {result['n_wires']:4d}")
        print(f"  Output signals:         {result['n_pub_out']:4d}")
        print(f"  Public input signals:   {result['n_pub_in']:4d}")
        print(f"  Private input signals:  {result['n_prv_in']:4d}")
        print(f"  Primary signals total:  {result['primary_signals']:4d}")
        print(f"  → Internal/witness:     {result['internal_signals']:4d} ({result['internal_signals']*100//result['n_wires']}%)")
