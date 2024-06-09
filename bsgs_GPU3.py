# -*- coding: utf-8 -*-
"""
Usage :
 > python bsgs_GPU.py -pubkey 02CEB6CBBCDBDF5EF7150682150F4CE2C6F4807B349827DCDBDD1F2EFA885A2630 -n 100000000000000000 -d 0 -t 64 -b 10 -p 256 -bp 500000 -keyspace 800000000000000000000000000000:ffffffffffffffffffffffffffffff -rand
 
 
@author: iceland
@Credit: KanhaVishva and AlbertoBSD
"""
import secp256k1_lib as ice
import bit
import ctypes
import os
import sys
import platform
import random
import math
import signal
import argparse
import time

#==============================================================================
parser = argparse.ArgumentParser(description='This tool use bsgs algo for searching 1 pubkey in the given range', 
                                 epilog='Enjoy the program! :)    Tips BTC: bc1q39meky2mn5qjq704zz0nnkl0v7kj4uz6r529at \
                                 \nThanks a lot to AlbertoBSD and KanhaVishva for their help.')
parser.version = '15112021'
parser.add_argument("-pubkey", help = "Public Key in hex format (compressed or uncompressed)", action="store", required=True)
parser.add_argument("-n", help = "Total random search attempts in 1 loop. default=10000000000000000", action='store')
parser.add_argument("-d", help = "GPU Device. default=0", action='store')
parser.add_argument("-t", help = "GPU Threads. default=64", action='store')
parser.add_argument("-b", help = "GPU Blocks. default=10", action='store')
parser.add_argument("-p", help = "GPU Points per Threads. default=256", action='store')
parser.add_argument("-bp", help = "bP Table Elements for GPU. default=500000", action='store')
parser.add_argument("-keyspace", help = "Keyspace Range ( hex ) to search from min:max. default=1:order of curve", action='store')
parser.add_argument("-rand", help = "Search in 100% random mode within the given range", action="store_true")
parser.add_argument("-output", help = "Output file to save the found private key", action="store", default="found_keys.txt")

if len(sys.argv)==1:
    parser.print_help()
    sys.exit(1)
args = parser.parse_args()
#==============================================================================

seq = int(args.n) if args.n else 10000000000000000  # 10000 Trillion
ss = args.keyspace if args.keyspace else '1:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140'
flag_random = True if args.rand else False
gpu_device = int(args.d) if args.d else 0
gpu_threads = int(args.t) if args.t else 64
gpu_blocks = int(args.b) if args.b else 10
gpu_points = int(args.p) if args.p else 256
bp_size = int(args.bp) if args.bp else 500000
public_key = args.pubkey if args.pubkey else '02e9dd713a2f6c4d684355110d9700063c66bc823b058e959e6674d4aa6484a585'
output_file = args.output if args.output else "found_keys.txt"

#==============================================================================
a, b = ss.split(':')
a = int(a, 16)
b = int(b, 16)

# Function to generate a random key within the range
def randk(a, b):
    return random.SystemRandom().randint(a, b)

#==============================================================================
gpu_bits = int(math.log2(bp_size))
#==============================================================================

def pub2upub(pub_hex):
    x = int(pub_hex[2:66],16)
    if len(pub_hex) < 70:
        y = bit.format.x_to_y(x, int(pub_hex[:2],16)%2)
    else:
        y = int(pub_hex[66:],16)
    return bytes.fromhex('04'+ hex(x)[2:].zfill(64) + hex(y)[2:].zfill(64))

#==============================================================================
    
print('\n[+] Starting Program.... Please Wait !')
if flag_random == True:
    print('[+] Search Mode: 100% Random in the given range')

#==============================================================================
P = pub2upub(public_key)
G = ice.scalar_multiplication(1)
P3 = ice.point_loop_addition(bp_size, P, G)
#==============================================================================
if platform.system().lower().startswith('win'):
    dllfile = 'bt2.dll'
    if os.path.isfile(dllfile) == True:
        pathdll = os.path.realpath(dllfile)
        bsgsgpu = ctypes.CDLL(pathdll)
    else:
        print('File {} not found'.format(dllfile))
    
elif platform.system().lower().startswith('lin'):
    dllfile = 'bt2.so'
    if os.path.isfile(dllfile) == True:
        pathdll = os.path.realpath(dllfile)
        bsgsgpu = ctypes.CDLL(pathdll)
    else:
        print('File {} not found'.format(dllfile))
        
else:
    print('[-] Unsupported Platform currently for ctypes dll method. Only [Windows and Linux] is working')
    sys.exit()
    
bsgsgpu.bsgsGPU.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_char_p] # t,b,p,rb,dv,upubs,size,keyspace,bp
bsgsgpu.bsgsGPU.restype = ctypes.c_void_p
bsgsgpu.free_memory.argtypes = [ctypes.c_void_p] # pointer
#==============================================================================

while True:
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    k1 = randk(a, b)  # Generate a new random starting key
    k2 = randk(a, b)  # Generate a new random ending key
    if k1 > k2:
        k1, k2 = k2, k1  # Ensure k1 is less than k2
    st_en = hex(k1)[2:] + ':' + hex(k2)[2:]
    start_time = time.time()  # Start time for speed calculation
    res = bsgsgpu.bsgsGPU(gpu_threads, gpu_blocks, gpu_points, gpu_bits, gpu_device, P3, len(P3)//65, st_en.encode('utf8'), str(bp_size).encode('utf8'))
    end_time = time.time()  # End time for speed calculation
    elapsed_time = end_time - start_time
    keys_per_second = seq / elapsed_time
    pvk = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    bsgsgpu.free_memory(res)
    
    if pvk != '':
        print('Magic:  ', pvk)
        foundpub = bit.Key.from_int(int(pvk, 16)).public_key
        idx = P3.find(foundpub[1:33], 0)
        if idx >= 0:
            BSGS_Key = int(pvk, 16) - (((idx-1)//65)+1)
            print('============== KEYFOUND ==============')
            print('BSGS FOUND PrivateKey ',hex(BSGS_Key))
            print('======================================')
            with open(output_file, "a") as f:
                f.write(f"Private Key: {hex(BSGS_Key)}\n")
                f.write(f"Public Key: {foundpub.hex()}\n")
                f.write('======================================\n')
            break
        else:
            print('Something is wrong. Please check ! [idx=', idx,']')
    
    print(f'Searched range: {hex(k1)} - {hex(k2)}')
    print(f'Keys searched per second: {keys_per_second:.2f}')

print('Program Finished.')
