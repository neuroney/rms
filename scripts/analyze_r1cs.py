#!/usr/bin/env python3
# Analyze R1CS header structure
import struct

with open('target/circom_build/circomlib_poseidon_main/circomlib_poseidon_main.r1cs', 'rb') as f:
    # Read magic number (4 bytes)
    magic = f.read(4)
    if magic != b'r1cs':
        print(f"ERROR: Invalid magic {magic}")
        exit(1)
    
    # Read version (4 bytes)
    version = struct.unpack('<I', f.read(4))[0]
    print(f"Version: {version}")
    
    # Read number of sections (4 bytes)
    num_sections = struct.unpack('<I', f.read(4))[0]
    print(f"Number of sections: {num_sections}")
    
    # Read sections to find header (type 1)
    for i in range(num_sections):
        section_type = struct.unpack('<I', f.read(4))[0]
        section_size = struct.unpack('<Q', f.read(8))[0]
        print(f"\nSection {i}: type={section_type}, size={section_size}")
        
        section_data = f.read(section_size)
        
        if section_type == 1:  # Header section
            reader = section_data
            pos = 0
            
            field_size = struct.unpack('<I', reader[pos:pos+4])[0]
            pos += 4
            print(f"  field_size: {field_size}")
            
            prime = reader[pos:pos+field_size]
            pos += field_size
            print(f"  prime: {len(prime)} bytes")
            
            n_wires = struct.unpack('<I', reader[pos:pos+4])[0]
            pos += 4
            
            n_pub_out = struct.unpack('<I', reader[pos:pos+4])[0]
            pos += 4
            
            n_pub_in = struct.unpack('<I', reader[pos:pos+4])[0]
            pos += 4
            
            n_prv_in = struct.unpack('<I', reader[pos:pos+4])[0]
            pos += 4
            
            n_labels = struct.unpack('<Q', reader[pos:pos+8])[0]
            pos += 8
            
            m_constraints = struct.unpack('<I', reader[pos:pos+4])[0]
            pos += 4
            
            print(f"\n  n_wires: {n_wires}")
            print(f"  n_pub_out: {n_pub_out}")  
            print(f"  n_pub_in: {n_pub_in}")
            print(f"  n_prv_in: {n_prv_in}")
            print(f"  n_labels: {n_labels}")
            print(f"  m_constraints: {m_constraints}")
            
            print(f"\nSignal ranges (1-indexed):")
            print(f"  Output signals: 1 to {n_pub_out}")
            print(f"  Public input signals: {n_pub_out + 1} to {n_pub_out + n_pub_in}")
            print(f"  Private input signals: {n_pub_out + n_pub_in + 1} to {n_pub_out + n_pub_in + n_prv_in}")
            print(f"  Internal/witness signals: {n_pub_out + n_pub_in + n_prv_in + 1} to {n_wires}")
            print(f"\n** ISSUE: Signals 78-81 are in the internal/witness range **")
            print(f"   They should be found and defined by constraints, but aren't.")
