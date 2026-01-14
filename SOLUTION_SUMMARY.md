# Solution Summary

## Challenge: CyberStudents Advent 2025 - PWN Challenge

### Vulnerability
The binary `chall_patched` contains an arbitrary write vulnerability that allows writing a single byte to any file at any offset.

### Key Insights (Based on Hints)

#### Hint 1: Use special files, not regular files
**Solution:** Use `/proc` filesystem special files:
- `/proc/self/mem` - Direct process memory access
- `/proc/self/fd/0` - stdin file descriptor

#### Hint 2: A 1 byte write isn't enough, how can you get more?
**Solution:** Two approaches:
1. **Multiple invocations** - Call the binary multiple times to write multiple bytes
2. **Stdin injection** - Write to `/proc/self/fd/0` to inject input for subsequent reads

### Exploitation Strategy

1. **Memory Corruption via /proc/self/mem:**
   - Use filename: `/proc/self/mem`
   - Use offset: target memory address (e.g., GOT entry at 0x404000)
   - Write bytes one at a time by calling binary 8 times
   - Build complete 64-bit addresses byte-by-byte

2. **Stdin Injection for Loop Control:**
   - Use filename: `/proc/self/fd/0`
   - Write data that will be consumed by next read/scanf
   - Create self-sustaining input loops
   - Achieve multi-byte writes in single execution

3. **GOT Hijacking:**
   - Target: `puts@GOT` (called at program end)
   - Overwrite with: `system()` address
   - Result: `puts("Write complete.")` becomes `system("...")`
   - Achieve code execution

### Files Provided

1. **pwn_solution.py** - Complete exploitation with demonstrations
2. **exploit_stdin.py** - Stdin injection techniques
3. **exploit.py** - General framework
4. **solution.py** - All strategies documented
5. **README.md** - Full documentation
6. **requirements.txt** - Dependencies

### Usage

```bash
# Install dependencies
pip install pwntools

# Run demonstrations
python3 pwn_solution.py demo    # Stdin injection
python3 pwn_solution.py got     # GOT overwrite
python3 pwn_solution.py full    # Complete chain
python3 pwn_solution.py all     # All demos
```

### Educational Value

This challenge teaches:
- Special files in `/proc` filesystem
- Arbitrary write exploitation
- GOT overwrite techniques
- Stdin manipulation
- Multi-byte write primitives
- Binary exploitation fundamentals

### Security Lessons

- Always validate file paths
- Implement proper permission checks
- Sandbox file operations
- Avoid unrestricted file access
- Use security mechanisms (SELinux, AppArmor)
