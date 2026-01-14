# Buffer Overflow / Arbitrary Write Challenge

This repository contains a pwn challenge binary (`chall_patched`) with an arbitrary file write vulnerability.

## Challenge Description

The binary is a simple program that allows users to write a single byte to any file at any offset. This is a classic arbitrary write primitive vulnerability commonly found in CTF pwn challenges.

## 🔑 Solution Hints

### Hint 1: Use special files, not regular files
**Answer**: `/proc/self/mem` and `/proc/self/fd/0` (stdin)

Special files in `/proc` provide direct access to process resources:
- `/proc/self/mem` - Direct memory access to the current process
- `/proc/self/fd/0` - stdin file descriptor
- `/proc/self/fd/1` - stdout file descriptor
- `/proc/self/fd/2` - stderr file descriptor

### Hint 2: A 1 byte write isn't enough, how can you get more?
**Answer**: Write to stdin (`/proc/self/fd/0`) to inject additional input!

By writing to the stdin file descriptor, we can **inject data into the input stream** that will be read by subsequent `scanf()` and `read()` calls. This allows:
1. Injecting the offset value for the next write
2. Injecting the data byte for the next write
3. Creating a self-sustaining loop for multi-byte writes
4. OR calling the binary multiple times to build up a multi-byte payload

## 💡 Key Exploitation Techniques

### Technique 1: Memory Manipulation via /proc/self/mem
```python
# Write to process memory directly
filename = '/proc/self/mem'
offset = 0x404000  # Address of puts@GOT, for example
data = '\x41'  # Byte to write

# This overwrites memory at address 0x404000!
```

### Technique 2: Stdin Injection for Multi-Byte Writes
```python
# Write to stdin to inject future inputs
filename = '/proc/self/fd/0'
offset = 0  # Current position in stdin buffer
data = '\n'  # Inject a newline

# The next read() will receive our injected data!
```

### Technique 3: Multiple Invocations for Complete Address Overwrite
```python
# Call the binary 8 times to write an 8-byte address
for i in range(8):
    # Each call writes 1 byte to /proc/self/mem
    # at address (target_got + i)
    # Building up a complete 64-bit address
```

## Vulnerability Analysis

The binary performs the following operations:

1. **Prompts for filename**: Accepts up to 256 bytes for a filename
2. **Prompts for offset**: Accepts an integer offset value
3. **Prompts for data**: Accepts a single byte of data
4. **Opens the file** with write permissions
5. **Seeks to the specified offset** using `lseek()`
6. **Writes the single byte** at that offset

### Key Vulnerability Points

- **No file path validation**: The binary doesn't validate which files can be written to
- **No permission checks**: Only limited by the process's file permissions
- **Arbitrary offset**: Can write at any offset within the file
- **Single byte write**: While limited to one byte, multiple invocations can write arbitrary data

## Binary Details

```bash
$ file chall_patched
chall_patched: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, for GNU/Linux 3.2.0, not stripped

$ checksec chall_patched
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE
```

## Exploitation Strategies

### 1. Single Byte Write
Write a single byte to a target file:
```bash
python3 exploit.py local
```

### 2. Multi-Byte Write
Execute the binary multiple times to write multiple bytes:
```bash
python3 exploit.py advanced
```

### 3. Remote Exploitation
Connect to a remote service:
```bash
python3 exploit.py remote <host> <port>
```

## Potential Attack Vectors

1. **Overwrite Configuration Files**: Modify system or application configs
2. **SSH Authorized Keys**: Add your SSH public key to gain access
3. **Cron Jobs**: Create scheduled tasks for persistence
4. **Binary Patching**: Modify executable files to change behavior
5. **Library Hooking**: Modify shared libraries loaded by other processes

## Security Implications

This type of vulnerability can lead to:
- **Privilege Escalation**: If the binary runs with elevated permissions
- **Remote Code Execution**: By modifying executable files or configs
- **Data Corruption**: Overwriting critical system or application files
- **Persistence**: Creating backdoors via cron, SSH keys, etc.

## Usage

### Requirements
```bash
pip install pwntools
```

### Running the Exploits

#### Main Solution: Complete Exploitation Chain
```bash
chmod +x chall_patched
python3 pwn_solution.py demo    # Stdin injection demo
python3 pwn_solution.py got     # GOT overwrite demo
python3 pwn_solution.py full    # Full explanation
python3 pwn_solution.py all     # Run all demos
```

#### Demo 1: Stdin Injection (Multi-byte write trick)
```bash
python3 exploit_stdin.py stdin
```

#### Demo 2: GOT Overwrite via Multiple Invocations
```bash
python3 exploit_stdin.py got
```

#### Demo 3: General Exploitation Framework
```bash
python3 exploit.py local
python3 exploit.py advanced
```

### Files in this Repository

- `chall_patched` - The vulnerable binary
- `pwn_solution.py` - **Complete solution** with full exploitation chain
- `exploit_stdin.py` - Stdin injection demonstration
- `exploit.py` - General exploitation framework  
- `solution.py` - Detailed solution with multiple strategies
- `requirements.txt` - Python dependencies
- `README.md` - This file

## Educational Purpose

This challenge demonstrates:
- The dangers of unrestricted file operations
- How seemingly small vulnerabilities (1-byte write) can be chained
- The importance of input validation and permission checking
- Common patterns in pwn/exploitation challenges

## Mitigation

To prevent this type of vulnerability:
1. **Validate file paths**: Whitelist allowed files/directories
2. **Check permissions**: Ensure the user has appropriate access rights
3. **Sandbox operations**: Use chroot, containers, or SELinux/AppArmor
4. **Limit file operations**: Restrict which files can be modified
5. **Audit logging**: Log all file modification attempts
6. **Drop privileges**: Run with minimum required permissions

## References

- [Arbitrary Write Vulnerabilities](https://ctf101.org/binary-exploitation/arbitrary-write/)
- [Pwntools Documentation](https://docs.pwntools.com/)
- [Binary Exploitation Techniques](https://github.com/nnamon/linux-exploitation-course)
- [/proc filesystem documentation](https://man7.org/linux/man-pages/man5/proc.5.html)

## Quick Reference

### Key Special Files
```
/proc/self/mem     - Process memory (read/write)
/proc/self/maps    - Memory mappings (read-only)
/proc/self/fd/0    - stdin (read/write)
/proc/self/fd/1    - stdout (write)
/proc/self/fd/2    - stderr (write)
```

### Exploitation Workflow
```
1. Reconnaissance
   - objdump -d chall_patched | grep "<main>:"
   - readelf -s chall_patched | grep FUNC
   - checksec chall_patched

2. Find Target Address
   - GOT entries: readelf -r chall_patched
   - Stack addresses: gdb + break point
   - Return addresses: analyze call stack

3. Write Payload
   - Filename: /proc/self/mem
   - Offset: target_address (e.g., 0x404000)
   - Data: byte_value (0x00-0xFF)
   - Repeat 8 times for full address

4. Trigger Execution
   - Call the overwritten function
   - Get shell/flag
```

### Common GOT Targets
```
puts@GOT    - Often used at end of program
printf@GOT  - Frequently called, good target
fgets@GOT   - Called early, can hijack flow
```

## License

This is educational material for learning about binary exploitation and security vulnerabilities.
