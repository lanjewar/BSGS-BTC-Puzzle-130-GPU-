# -*- coding: utf-8 -*-
"""
Modified secp256k1_lib.py with performance and usability improvements
"""

import platform
import os
import sys
import ctypes

# Load the appropriate DLL/SO file
if platform.system().lower().startswith('win'):
    dllfile = 'ice_secp256k1.dll'
elif platform.system().lower().startswith('lin'):
    dllfile = 'ice_secp256k1.so'
else:
    print('[-] Unsupported Platform currently for ctypes dll method. Only [Windows and Linux] is working')
    sys.exit()

if os.path.isfile(dllfile):
    pathdll = os.path.realpath(dllfile)
    ice = ctypes.CDLL(pathdll)
else:
    print('File {} not found'.format(dllfile))
    sys.exit()

# Define argument types for the C functions
ice.scalar_multiplication.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
ice.point_increment.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
ice.point_negation.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
ice.point_doubling.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
ice.privatekey_to_coinaddress.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_bool, ctypes.c_char_p]
ice.privatekey_to_coinaddress.restype = ctypes.c_void_p
ice.privatekey_to_address.argtypes = [ctypes.c_int, ctypes.c_bool, ctypes.c_char_p]
ice.privatekey_to_address.restype = ctypes.c_void_p
ice.hash_to_address.argtypes = [ctypes.c_int, ctypes.c_bool, ctypes.c_char_p]
ice.hash_to_address.restype = ctypes.c_void_p
ice.pubkey_to_address.argtypes = [ctypes.c_int, ctypes.c_bool, ctypes.c_char_p]
ice.pubkey_to_address.restype = ctypes.c_void_p
ice.privatekey_to_h160.argtypes = [ctypes.c_int, ctypes.c_bool, ctypes.c_char_p, ctypes.c_char_p]
ice.privatekey_loop_h160.argtypes = [ctypes.c_ulonglong, ctypes.c_int, ctypes.c_bool, ctypes.c_char_p, ctypes.c_char_p]
ice.pubkey_to_h160.argtypes = [ctypes.c_int, ctypes.c_bool, ctypes.c_char_p, ctypes.c_char_p]
ice.pbkdf2_hmac_sha512_dll.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
ice.create_baby_table.argtypes = [ctypes.c_ulonglong, ctypes.c_ulonglong, ctypes.c_char_p]
ice.point_addition.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
ice.point_subtraction.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
ice.point_loop_subtraction.argtypes = [ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
ice.point_loop_addition.argtypes = [ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
ice.point_vector_addition.argtypes = [ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
ice.point_sequential_increment.argtypes = [ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p]
ice.pubkeyxy_to_ETH_address.argtypes = [ctypes.c_char_p]
ice.pubkeyxy_to_ETH_address.restype = ctypes.c_void_p
ice.privatekey_to_ETH_address.argtypes = [ctypes.c_char_p]
ice.privatekey_to_ETH_address.restype = ctypes.c_void_p
ice.privatekey_group_to_ETH_address.argtypes = [ctypes.c_char_p, ctypes.c_int]
ice.privatekey_group_to_ETH_address.restype = ctypes.c_void_p
ice.free_memory.argtypes = [ctypes.c_void_p]

ice.init_secp256_lib()

def scalar_multiplication(kk):
    '''Integer value passed to function. 65 bytes uncompressed pubkey output'''
    res = (b'\x00') * 65
    pass_int_value = hex(kk)[2:].encode('utf8')
    ice.scalar_multiplication(pass_int_value, res)
    return bytes(bytearray(res))

def point_increment(pubkey_bytes):
    x1 = pubkey_bytes[1:33]
    y1 = pubkey_bytes[33:]
    res = (b'\x00') * 65
    ice.point_increment(x1, y1, res)
    return bytes(bytearray(res))

def point_negation(pubkey_bytes):
    x1 = pubkey_bytes[1:33]
    y1 = pubkey_bytes[33:]
    res = (b'\x00') * 65
    ice.point_negation(x1, y1, res)
    return bytes(bytearray(res))

def point_doubling(pubkey_bytes):
    x1 = pubkey_bytes[1:33]
    y1 = pubkey_bytes[33:]
    res = (b'\x00') * 65
    ice.point_doubling(x1, y1, res)
    return bytes(bytearray(res))

def privatekey_to_coinaddress(coin_type, addr_type, iscompressed, pvk_int):
    pass_int_value = hex(pvk_int)[2:].encode('utf8')
    res = ice.privatekey_to_coinaddress(coin_type, addr_type, iscompressed, pass_int_value)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addr

def privatekey_to_address(addr_type, iscompressed, pvk_int):
    pass_int_value = hex(pvk_int)[2:].encode('utf8')
    res = ice.privatekey_to_address(addr_type, iscompressed, pass_int_value)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addr

def hash_to_address(addr_type, iscompressed, hash160_bytes):
    res = ice.hash_to_address(addr_type, iscompressed, hash160_bytes)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addr

def pubkey_to_address(addr_type, iscompressed, pubkey_bytes):
    res = ice.pubkey_to_address(addr_type, iscompressed, pubkey_bytes)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addr

def privatekey_to_h160(addr_type, iscompressed, pvk_int):
    pass_int_value = hex(pvk_int)[2:].encode('utf8')
    res = (b'\x00') * 20
    ice.privatekey_to_h160(addr_type, iscompressed, pass_int_value, res)
    return bytes(bytearray(res))

def privatekey_loop_h160(num, addr_type, iscompressed, pvk_int):
    pass_int_value = hex(pvk_int)[2:].encode('utf8')
    res = (b'\x00') * (20 * num)
    ice.privatekey_loop_h160(num, addr_type, iscompressed, pass_int_value, res)
    return bytes(bytearray(res))

def pubkey_to_h160(addr_type, iscompressed, pubkey_bytes):
    res = (b'\x00') * 20
    ice.pubkey_to_h160(addr_type, iscompressed, pubkey_bytes, res)
    return bytes(bytearray(res))

def pbkdf2_hmac_sha512_dll(words):
    seed_bytes = (b'\x00') * 64
    ice.pbkdf2_hmac_sha512_dll(seed_bytes, words.encode("utf-8"), len(words))
    return seed_bytes

def create_baby_table(start_value, end_value):
    res = (b'\x00') * ((1+end_value-start_value) * 32)
    ice.create_baby_table(start_value, end_value, res)
    return res

def point_addition(pubkey1_bytes, pubkey2_bytes):
    x1 = pubkey1_bytes[1:33]
    y1 = pubkey1_bytes[33:]
    x2 = pubkey2_bytes[1:33]
    y2 = pubkey2_bytes[33:]
    res = (b'\x00') * 65
    ice.point_addition(x1, y1, x2, y2, res)
    return bytes(bytearray(res))

def point_subtraction(pubkey1_bytes, pubkey2_bytes):
    x1 = pubkey1_bytes[1:33]
    y1 = pubkey1_bytes[33:]
    x2 = pubkey2_bytes[1:33]
    y2 = pubkey2_bytes[33:]
    res = (b'\x00') * 65
    ice.point_subtraction(x1, y1, x2, y2, res)
    return bytes(bytearray(res))

def point_loop_subtraction(num, pubkey1_bytes, pubkey2_bytes):
    res = (b'\x00') * (65 * num)
    ice.point_loop_subtraction(num, pubkey1_bytes, pubkey2_bytes, res)
    return bytes(bytearray(res))

def point_loop_addition(num, pubkey1_bytes, pubkey2_bytes):
    res = (b'\x00') * (65 * num)
    ice.point_loop_addition(num, pubkey1_bytes, pubkey2_bytes, res)
    return bytes(bytearray(res))

def point_vector_addition(num, pubkeys1_bytes, pubkeys2_bytes):
    res = (b'\x00') * (65 * num)
    ice.point_vector_addition(num, pubkeys1_bytes, pubkeys2_bytes, res)
    return bytes(bytearray(res))

def point_sequential_increment(num, pubkey1_bytes):
    res = (b'\x00') * (65 * num)
    ice.point_sequential_increment(num, pubkey1_bytes, res)
    return bytes(bytearray(res))

def pubkey_to_ETH_address(pubkey_bytes):
    xy = pubkey_bytes[1:]
    res = ice.pubkeyxy_to_ETH_address(xy)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return '0x'+addr

def privatekey_to_ETH_address(pvk_int):
    pass_int_value = hex(pvk_int)[2:].encode('utf8')
    res = ice.privatekey_to_ETH_address(pass_int_value)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return '0x'+addr

def privatekey_group_to_ETH_address(pvk_int, m):
    if m <= 0: m = 1
    start_pvk = hex(pvk_int)[2:].encode('utf8')
    res = ice.privatekey_group_to_ETH_address(start_pvk, m)
    addrlist = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addrlist

def batch_scalar_multiplication(kk_list):
    ''' List of integer values passed to function. 65 bytes uncompressed pubkey output for each '''
    results = []
    for kk in kk_list:
        res = (b'\x00') * 65
        pass_int_value = hex(kk)[2:].encode('utf8')
        ice.scalar_multiplication(pass_int_value, res)
        results.append(bytes(bytearray(res)))
    return results

def scalar_multiplication_threaded(kk_list):
    ''' Perform scalar multiplication using threading for faster results '''
    def worker(kk):
        res = (b'\x00') * 65
        pass_int_value = hex(kk)[2:].encode('utf8')
        ice.scalar_multiplication(pass_int_value, res)
        return bytes(bytearray(res))
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(worker, kk_list))
    return results

def privatekey_to_coinaddress_optimized(coin_type, addr_type, iscompressed, pvk_bytes):
    res = ice.privatekey_to_coinaddress(coin_type, addr_type, iscompressed, pvk_bytes)
    addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addr

def safe_scalar_multiplication(kk):
    ''' Integer value passed to function. 65 bytes uncompressed pubkey output '''
    try:
        res = (b'\x00') * 65
        pass_int_value = hex(kk)[2:].encode('utf8')
        ice.scalar_multiplication(pass_int_value, res)
        return bytes(bytearray(res))
    except Exception as e:
        print(f"Error in scalar_multiplication: {e}")
        return None
