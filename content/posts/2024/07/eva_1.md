---
title: "E²VA: Android Basics (Part 2)"
date: 2024-07-22T16:46:21+01:00
author: "Pascal Kühnemann"
draft: false
authorTwitter: "" #do not include @
cover: ""
tags: ["Android", "Binary Exploitation", "JNI", "E²VA"]
keywords: ["Android", "Binary Exploitation", "JNI", "E²VA"]
description: ""
showFullContent: false
readingTime: true
---

# Android Binary Exploitation

In this post, we will examine security mechanisms that Android 12 employs in order to make binary exploitation a bit harder. Also, we will discuss how to get to certain information like shared - object files that are necessary for successful exploitation. The latter will be generalized to getting limited source code access to an app given a corresponding `.apk` file.

## Environment

Before diving into details, the technical setup has to be clarified. All of the following observations on security mechanisms were encountered on a x86_64 Pixel 3 emulator running Android 12 (build number is [`SE1A.220203.002.A1`](https://source.android.com/docs/setup/about/build-numbers#build-ids-defined)). When referencing source code from *Android Open Source Project* (AOSP), it will be w.r.t. [Android 12.0.0_r31](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:). The build variant for *damnvulnerableapp* is currently only `debug`. Also there is no GooglePlay enabled as we require root on the device for debugging purposes only.

In addition to that, standard compilation configurations of [*Android Studio*](https://developer.android.com/studio) are used to construct the app and compile native code. The version of *Android Studio* is as follows:
- Android Studio Dolphin | 2021.3.1
- Build #AI-213.7172.25.2113.9014738, built on August 31, 2022
- Runtime version: 11.0.13+0-b1751.21-8125866 amd64
- VM: OpenJDK 64-Bit Server VM by JetBrains s.r.o.
- Linux 5.15.0-46-generic
- GC: G1 Young Generation, G1 Old Generation
- Memory: 2048M
- Cores: 12
- Registry:
    - external.system.auto.import.disabled=true
    - debugger.watches.in.variables=false
    - ide.text.editor.with.preview.show.floating.toolbar=false
- Current Desktop: ubuntu:GNOME

If your environment differs even in the slightest way, you might need different offsets, addresses etc. to get your exploits to work. Thus, if I presents exploit sketches, **do not assume that they work out of the box!**

## Overview of Security Mechanisms on Android

Next, via a non - exhaustive list of security mechanisms we will dive into the details of how Android makes life of an attacker (a bit) harder. If possible, we will try to figure out a way to bypass each security mechanism through additional assumptions.

### Permissions

As usual, an app has certain permissions to access specific data or perform specific actions. E.g. in order to create a connection to a remote host via [`java.net.Socket`](https://docs.oracle.com/javase/7/docs/api/java/net/Socket.html), an app has to declare the install - time permission [`android.permission.INTERNET`](https://developer.android.com/reference/android/Manifest.permission#INTERNET) in its manifest. If a permission is not declared (install - time) or not granted (runtime), then the app will not be able to provide the functionality that needs the respective permission(s).

Continuing the example above, if we somehow manage to get abitrary code execution inside of an Android app, but the app does not declare `android.permission.INTERNET`, then we will not be able to create a socket connection to call back to our netcat - listener for a reverse shell.

Permissions can further be divided into
1. [Install - time permissions](https://developer.android.com/guide/topics/permissions/overview#install-time): System automatically grants these upon installation. These permissions can be further classified into
    1. [Normal permissions](https://developer.android.com/guide/topics/permissions/overview#normal): Allow for access to data and actions beyond the app's sandbox.
    2. [Signature permissions](https://developer.android.com/guide/topics/permissions/overview#signature): Irrelevant for now!
2. [Runtime permissions](https://developer.android.com/guide/topics/permissions/overview#runtime): User will be shown a permission prompt that specifically asks for a potentially dangerous permission. These prompts will be presented only if the app is running/starting.
3. [Special permissions](https://developer.android.com/guide/topics/permissions/overview#special): Irrelevant for now! We assume an app that is not even capable of specifying these permissions.

Assuming source code access and thus access to `AndroidManifest.xml`, we can deduce which actions are allowed in our shellcode. Another (naive) assumption is to believe that an app is incapable of adding additional permissions without a user's consent via publicly known means (otherwise this would be a severe security issue). Of couse, our shellcode could try to present the user permission prompts that give us further tools to play with, but this is **far from stealthy**!

Summarizing, a shellcode is limited to the app's permissions. Theoretically it is possible for shellcode to request runtime permissions ... at runtime. It would be interesting to see whether it is possible to request install - time permissions at runtime.

### FORTIFY

This mechanism adds additional compile - time and/or runtime checks to the C standard library. These are mainly memory - related checks, e.g. 
```C
struct Foo {
    int val;
    struct Foo *next;
};
void initFoo(struct Foo *f) {
    memset(&f, 0, sizeof(struct Foo));
}
```
will not work, because *FORTIFY* is able to detect the 8 - byte overflow at compile - time (example taken from [here](https://android-developers.googleblog.com/2017/04/fortify-in-android.html)).

At compile - time, *FORTIFY* will block compilation, if it is able to detect a bad call to a standard library function like e.g. `memset`. If *FORTIFY* is missing information or is very certain that a call is safe, then *FORTIFY* will be not be part of the process image. Finally, if there is a call, but *FORTIFY* is not sure whether the call is safe or not, it will redirect the call to a special *FORTIFY*'ed version of the called function, which applies additional checks to ensure correct usage of the function.

Lets consider an Android - related example of the function [`memset`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:bionic/libc/include/bits/fortify/string.h;l=122;bpv=0;bpt=1):
```C
__BIONIC_FORTIFY_INLINE
void* memset(void* const s __pass_object_size0, int c, size_t n) __overloadable
        /* If you're a user who wants this warning to go away: use `(&memset)(foo, bar, baz)`. */
        __clang_warning_if(c && !n, "'memset' will set 0 bytes; maybe the arguments got flipped?") {
#if __ANDROID_API__ >= 17 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    return __builtin___memset_chk(s, c, n, __bos0(s));
#else
    return __builtin_memset(s, c, n);
#endif
}
```
As these are builtins, they are implemented by the compiler and thus pretty hard to track down (if you are interested, consider code that looks like a [compile - time check](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/clang/lib/Sema/SemaChecking.cpp;l=974) and a [runtime - check](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/clang/lib/CodeGen/CGBuiltin.cpp;l=1052); no guarantees that these references are what is actually being called!).

Sooo...how to break it? Apparently, if *FORTIFY* is lacking information, it will just give up. The developers gave a pretty nice [example](https://android-developers.googleblog.com/2017/04/fortify-in-android.html) for *FORTIFY*'s limitations:
```C
__attribute__((noinline)) // Tell the compiler to never inline this function.
inline void intToStr(int i, char *asStr) { sprintf(asStr, "%d", i); }

char *intToDupedStr(int i) {
    const int MAX_INT_STR_SIZE = sizeof("2147483648"); // MAX_INT_STR_SIZE = 11 = 10 + 1
    char buf[MAX_INT_STR_SIZE];
    intToStr(i, buf);
    return strdup(buf);
}
```
Setting `i = -2147483648` (which is `0x80000000`, because of 2's - complement for 4 - byte values) would result in an off - by - one bug, because `buf` is a buffer of `11` elements, the last of which is supposed to be a null - terminator. Because `sprintf` will also put a `-` sign into `buf`, the null - terminator will be moved back by one and therefore overwrite the least - significant byte of the next qword on the stack. If `rbp` was modified, then this would most likely crash the entire program. *FORTIFY* does **not** catch this bug, because from the perspective of `intToStr`, *FORTIFY* cannot "see" the allocation of `buf`. Neither can *FORTIFY* determine for sure the size of a `char*`, which could be of arbitrary length, nor can it determine where `buf` is pointing to (`stack`, `heap`, `.bss`, `.data`, ...).

Observe that *FORTIFY* makes it significantly harder for developers to write vulnerable code. Still, if developers decide to implement their own versions of e.g. `memcpy` this fully bypasses *FORTIFY*. Also, as can be seen in the above example, there are settings, in which *FORTIFY* cannot help, i.e. e.g. if the allocation of a buffer takes place in a different function and this buffer is passed as a `type*`.

### On defeating PIEs

When building native apps on Android via *Android Studio*, we will almost always use [cmake's `add_library`](https://cmake.org/cmake/help/latest/command/add_library.html) with the `SHARED` flag. This will encapsulate the native code into a [`lib<somename>.so`](https://developer.android.com/studio/projects/configure-cmake#create_script) file, which is actually a shared - object file ([ELF](http://www.sco.com/developers/gabi/latest/contents.html)). According to [documentation](https://cmake.org/cmake/help/latest/command/add_library.html), for such `SHARED` libraries the property `POSITION_INDEPENDENT_CODE` is automatically set to `ON`, thus resulting in Position - Independent - Executables (PIEs; To be precise with terminology, the shared - object file contains Position - Independent - Code (PIC). From *ELF's* perspective, not every shared - object file is an executable and vice versa).

When calling `System.loadLibrary("xyz")`, we can trace down the call hierarchy to versions of [`dlopen`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:art/runtime/jni/java_vm_ext.cc;l=1003;bpv=0;bpt=0), which is implemented in the [linker](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:bionic/linker/linker.cpp;l=2063;bpv=0;bpt=1). Finally, [`ReserveWithAlignmentPadding`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:bionic/linker/linker_phdr.cpp;l=561) will be called, which returns a [randomized base address](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:bionic/linker/linker_phdr.cpp;l=623). This confirms that when loading native shared - object files, they will have [ASLR](https://guyinatuxedo.github.io/5.1-mitigation_aslr_pie/index.html) enabled by default.

Defeating ASLR is thus key to handling binary exploitation in PIEs. This can be archieved in numerous ways. The following is a non - exhaustive list of possible ways to break ASLR:
1. Leaking an address from e.g. a code region. It seems that the random shift used for the stack (and heap etc.) and a loaded shared - object file differ. This follows from the [randomized base address](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:bionic/linker/linker_phdr.cpp;l=623), which is different on each execution of `ReserveWithAlignmentPadding`.
2. Abusing a side channel that allows for brute - forcing / leaking bytes of an address one by one instead of being forced into brute - forcing / leaking the entire address at once.
3. From [`ReserveWithAlignmentPadding`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:bionic/linker/linker_phdr.cpp;l=626), by probing for accessible memory mappings. Depending on the app, we might be able to even distinguish different kinds of errors / signals when accessing / returning to invalid memory. However, for memory probing to work the process should not crash upon signals like `SIGSEG` or `SIGILL`, which is very rare.

### Full RELRO

With the above security mechanisms in place, it would still be "easy" to abuse a leak combined with a *Write - What - Where* condition, as e.g. `.got` is still writable. E.g. overwriting a `.got` entry of `strlen` that is given a string of our choice could result in a redirection to `system` (for a more detailed discussion, see [this blog post](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html)). This is, among other things, prevented by full / partial *Relocations Read - Only*, i.e. full / partial *RELRO*, which can be [enabled](https://source.android.com/docs/security/enhancements/enhancements41) on Android. Full *RELRO* marks certain memory regions, like e.g. `.got`, as read - only after program startup. It seems that it is enabled by default, when creating a new native android app in Android Studio.

Now the question arises, how this mitigation can be circumvented. This again depends on the app. Lets consider the non - exhaustive list:
1. Given a *Write - What - Where* condition and knowledge on all addresses:
    1. Try to find and overwrite a global variable (located in `.bss` or `.data`) that impacts the control flow, e.g. a function pointer.
    2. Overwrite the return address on the stack to return to a [ROP - chain](https://ctf101.org/binary-exploitation/return-oriented-programming/) located "somewhere else".
2. Given access to `mprotect`:
    1. Call `mprotect` on `.got` to make it writable again.

### Non - executable Stack (and Heap)

As has been the case for decades, the [stack and heap is marked as non - executable](https://source.android.com/docs/security/enhancements/enhancements41) by default. Thus, calling your classical NOP - sledge for help won't do any good.

(Un-)fortunately, the stack and heap can be used to store gadgets for a ROP - chain.

### Canaries and cookies

Depending on how a native function is implemented and compiled, it can be given a stack canary. This canary aims to protect the stack frame, i.e. the return address and stored `rbp`, from potential buffer overflows on the stack. In our case, this canary is an 8 - byte random value that is very hard to predict. Doing the math reveals that we have a `1/(2^64)` chance to hit the correct canary. This is why we often assume that there is some kind of leak that (partially) reveals the canary (bytes). Naturally, two approaches come to mind when thinking of "leaking an 8 byte random value":
1. Reading it directly from the stack. Trivially, this will reveal the value.
2. Brute - forcing it via a side channel. The side channel could be e.g. an oracle that either says
    - "Canary is correct", i.e. process keeps running
    - "Canary is incorrect", i.e. process crashes.

    If we overwrite just the least - significant byte of the canary, this byte will be in either of the above categories. If the process does not crash, we can continue with the next canary byte until all 8 bytes are leaked.

So, why would the latter approach work? The canary will be consisting of 8 random bytes for each process start, right? Right? No! Not going into the [details](https://link.springer.com/article/10.1007/s10207-018-00425-8), the underlying syscall `fork`, which is used to spawn *damnvulnerableapp* and its subprocess that is running the vulnerable module, will be called from the same parent process (zygote) over and over again, i.e. for **each** app. Therefore, apps contain large duplicated memory regions, canary included.

[//]: # (### Scudo, the Allocator)

[//]: # "From Android 11 onwards, [*Scudo* is used by default for native code](https://source.android.com/docs/security/test/scudo). The implementation **greatly** differs from [`dlmalloc`](https://www.gnu.org/software/libc/manual/html_node/The-GNU-Allocator.html), which is the foundation of *glibc's* `malloc` implementation. For those interested in implementation details, the [`Allocator`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=46) is the main component of *Scudo* on Android."

[//]: # "Lets first try to come up with a (non - exhaustive) list of security features that *Scudo* offers (there are [other nice lists](http://expertmiami.blogspot.com/2019/05/high-level-overview-of-scudo.html) aswell):"
[//]: # "(1. Large allocations, i.e. allocations that use the *Secondary*, will be surrounded by [*Guard Pages*](https://llvm.org/docs/ScudoHardenedAllocator.html#allocator). From what can be seen in the [source code](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=497), the guard pages seem to just be additional buffers that are not checked for overflow. This statement needs further analysis!"
[//]: # "2. Meta data of blocks are [crc32 - checksummed](http://expertmiami.blogspot.com/2019/05/high-level-overview-of-scudo.html). This looks nice at first glance, but *CRC32* is **not** a cryptographic hash function! Some people already started [messing with collisions](https://blog.infosectcbr.com.au/2020/04/breaking-secure-checksums-in-scudo_8.html). Also the header for large allocations seems to [not be checksummed](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=26). Again this needs further analysis of the code, as it is also stated that a [combined header](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=26) is used, which again could be checksummed."

## Getting the source

And now for something completely different. Well, technically speaking it is not *that* different, because packing the source code could be considered a form of obfuscation, which again could be considered a security precaution. Now we will take the perspective of an attacker that tries to get access to the source code of an app while only having access to an app's `apk` file.

### Finding the *apk* file

There are numerous ways to get an `apk` file of an app, among which the following seem to be the easiest ones:
1. Use *Android Studio* to build the app and search for the `apk` file in the directory tree of the app. This implies source code access and therefore makes analyzing an `apk` file obsolete, but it is a way.
2. Assuming root access on an Android device / emulator, user - installed apps can be found at e.g. `/data/app/`. There can be a corresponding `.apk` file to grab for further static analysis (this might depend on the Android version).

### Unpacking *apk* files

Assuming we grabbed ourselves an `apk` file, we can start analyzing it:
```bash
$ file base.apk
base.apk: Zip archive data, at least v?[0] to extract
$ unzip base.apk -d ./base
...
$ ls base
AndroidManifest.xml  classes10.dex  classes11.dex  classes2.dex  classes3.dex  classes4.dex  classes5.dex  classes6.dex  classes7.dex  classes8.dex  classes9.dex  classes.dex  lib  META-INF  res  resources.arsc
```

Going from here we can easily access the native libraries that are part of the app:
```bash
$ ls base/lib/x86_64
libDoubleFreeModule.so  libEasyStackBufferOverflowModule.so  libHeapOverflowModule.so  libOffByOneModule.so  libStackBufferOverflowModule.so  libUseAfterFreeExecModule.so  libUseAfterFreeWriteModule.so
```

These shared - object files can later be used for finding gadgets and so on. Further they can be analyzed / decompiled via e.g. [*Ghidra*](https://ghidra-sre.org/). The decompiled code of `logMessage#libOffByOneModule.so` could look like this:
```C
undefined8
Java_com_damnvulnerableapp_vulnerable_modules_OffByOneModule_logMessage
		(long *param_1,undefined8 param_2,undefined8 param_3)

{
	int iVar1;
	undefined4 uVar2;
	undefined8 uVar3;
	void *pvVar4;
	undefined8 uVar5;
	long in_FS_OFFSET;
	int local_cc;
	undefined8 local_a0;
	timespec local_28;
	undefined local_11;
	long local_10;

	local_10 = *(long *)(in_FS_OFFSET + 0x28);
	uVar3 = (**(code **)(*param_1 + 0x5c0))(param_1,param_3,&local_11);
	DAT_00103028 = DAT_00103028 + 1;
	DAT_00103020 = realloc(DAT_00103020,DAT_00103028 * 0x108);
	if (DAT_00103020 == (void *)0x0) {
		local_a0 = 0;
	}
	else {
		pvVar4 = (void *)((long)DAT_00103020 + (DAT_00103028 + -1) * 0x108);
		__memset_chk(pvVar4,0,0x108,0xffffffffffffffff);
		__memcpy_chk((long)pvVar4 + 0x100,&PTR_FUN_00103010,8,0xffffffffffffffff);
		local_cc = (**(code **)(*param_1 + 0x558))(param_1,param_3);
		if (0x100 < local_cc + -1) {
			local_cc = 0xff;
		}
		__memcpy_chk(pvVar4,uVar3,(long)local_cc,0xffffffffffffffff);
		iVar1 = clock_gettime(0,&local_28);
		if (iVar1 != -1) {
			local_28.tv_nsec = local_28.tv_nsec + 10;
		}
		uVar5 = (**(code **)((long)pvVar4 + 0x100))(pvVar4,(long)local_cc);
		uVar2 = __strlen_chk(uVar5,0xffffffffffffffff);
		local_a0 = (**(code **)(*param_1 + 0x580))(param_1,uVar2);
		(**(code **)(*param_1 + 0x680))(param_1,local_a0,0,uVar2,uVar5);
		(**(code **)(*param_1 + 0x600))(param_1,param_3,uVar3,2);
	}
	if (*(long *)(in_FS_OFFSET + 0x28) == local_10) {
		return local_a0;
	}
				/* WARNING: Subroutine does not return */
	__stack_chk_fail();
}
```

In order to not being forced into manually setting up the jni type definitions, see either [`jni_all.h`](https://github.com/extremecoders-re/ghidra-jni) or [`jni_all.h`](https://gist.github.com/jcalabres/bf8d530b3f18c30ca6f66388357b1d91). When in the *CodeBrowser*, try running *File -> Parse C Source...*, add the corresponding file to "Source files to parse", choose the correct base profile ("parse configuration") and set the parse options to e.g. [this](https://github.com/extremecoders-re/ghidra-jni#how-to-load-in-ghidra).

To be more precise, first download any of the above mentioned `jni_all.h` files. Then open *File -> Parse C Source...*. You should be prompted with the following window:
![Parse C Source Window](/2024/07/eva_1_ghidra_parse_c_source.png)

Next, choose an existing profile as a base profile. E.g. choose `generic_clib_32.prf` and click on the *Save profile to new name* button (upper right corner). Then choose a name that you recognize:
![Save New Profile](/2024/07/eva_1_ghidra_save_new_profile.png)

After giving the new profile a nice name, we need to adjust the parse options. E.g. you can copy them over from [here](https://github.com/extremecoders-re/ghidra-jni#how-to-load-in-ghidra). **Do not overwrite -I options**:
![Parse Options](/2024/07/eva_1_ghidra_parse_options.png)

Finally, add `jni_all.h` to the *Source files to parse* panel by clicking on the green plus sign to the right. This should open *files*. Navigate to `jni_all.h` and open it. You should see a new entry if you scrolled all the way down. Now click the *Save profile* button at the top and then *Parse to program* at the bottom. If you now retype a variable, e.g. the first argument of a JNI function to `JNIEnv*`, you will see actual function names like `NewByteArray` etc.

Now we are just missing the Java code that calls this native function...

### Getting Java code

In order to obtain the Java code of an app, an attacker could utilize a tool like [*jadx*](https://github.com/skylot/jadx). This basically reconstructs the project structure we see in *Android Studio*:
```bash
$ jadx-gui ./base.apk
...
```
This decompiles a large portion of the app. Continuing the example of the *OffByOneModule*, we can get the following decompiled code for the `OffByOneModule` class:
```Java
package com.damnvulnerableapp.vulnerable.modules;

import com.damnvulnerableapp.common.exceptions.VulnerableModuleException;

/* loaded from: classes10.dex */
public class OffByOneModule extends VulnerableModule {
    private static native byte[] logMessage(byte[] bArr);

    static {
        System.loadLibrary("OffByOneModule");
    }

    public OffByOneModule() {
        super(new OffByOneModuleConfiguration());
    }

    @Override // com.damnvulnerableapp.vulnerable.modules.VulnerableModule
    public void main() throws VulnerableModuleException {
        output("Welcome to the most secure message logger in the world!".getBytes());
        while (true) {
            output("Enter a message to log: ".getBytes());
            byte[] message = input();
            if (message == null) {
                output("Failed to receive the message to log...Better safe than sorry!".getBytes());
            } else if (new String(message).equals("EXIT")) {
                output("Your logged message(s) were stored successfully.".getBytes());
                return;
            } else {
                output(logMessage(message));
            }
        }
    }
}
```

### Grabbing System Libraries

Often there are libraries, of which we have a leaked pointer. Having such a pointer is nice and all, but it will not help, if we do not have access to the corresponding shared - object file. Lets try to get access to `libart.so`, the android runtime that runs the Java code we wrote for the app. Among other things, it handles native calls via trampoline functions like [`art_quick_generic_jni_trampoline`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:art/runtime/arch/x86_64/quick_entrypoints_x86_64.S;l=1536).

In order to find `libart.so`, again assuming root access, running the *damnvulnerableapp* reveals the binary that underlies the process:
```
# ps -e | grep damn
u0_a107       4122   357 13798620 114268 do_epoll_wait      0 S com.damnvulnerableapp
# file /proc/4122/exe
/proc/4122/exe: symbolic link to /system/bin/app_process64
# readelf -d /system/bin/app_process64
...
 0x0000000000000001 (NEEDED)             Shared library: [libandroid_runtime.so]
 0x0000000000000001 (NEEDED)             Shared library: [libbinder.so]
 0x0000000000000001 (NEEDED)             Shared library: [libcutils.so]
 0x0000000000000001 (NEEDED)             Shared library: [libhidlbase.so]
 0x0000000000000001 (NEEDED)             Shared library: [liblog.so]
 0x0000000000000001 (NEEDED)             Shared library: [libnativeloader.so]
 0x0000000000000001 (NEEDED)             Shared library: [libsigchain.so]
 0x0000000000000001 (NEEDED)             Shared library: [libutils.so]
 0x0000000000000001 (NEEDED)             Shared library: [libwilhelm.so]
 0x0000000000000001 (NEEDED)             Shared library: [libc++.so]
 0x0000000000000001 (NEEDED)             Shared library: [libc.so]
 0x0000000000000001 (NEEDED)             Shared library: [libm.so]
 0x0000000000000001 (NEEDED)             Shared library: [libdl.so]
...
```
This means that `libart.so` will be loaded later on, i.e. not at startup. Further analysis reveals:
```
# cat /proc/4122/maps | grep libart.so
730c03400000-730c0357b000 r--p 00000000 fe:0f 57                         /apex/com.android.art/lib64/libart.so
730c0377a000-730c03e0b000 r-xp 0017a000 fe:0f 57                         /apex/com.android.art/lib64/libart.so
730c0400a000-730c0401d000 r--p 0080a000 fe:0f 57                         /apex/com.android.art/lib64/libart.so
730c0421c000-730c04220000 rw-p 0081c000 fe:0f 57                         /apex/com.android.art/lib64/libart.so
# exit
$ adb pull /apex/com.android.art/lib64/libart.so ./libart.so
```

After the above commands, `libart.so` should be in our current working directory, ready to be analyzed via *Ghidra*, [*objdump*](https://man7.org/linux/man-pages/man1/objdump.1.html)(which will most likely not work, because *objdump* does not recognize the architecture) or [*readelf*](https://man7.org/linux/man-pages/man1/readelf.1.html).

There may be two unexpected aspects:
1. Even if you do **not** have root access on the emulator, it is possible to run `adb pull <from remote> <to local>`. We only used root to access `/proc/4122/maps` etc.
2. The name of the binary that underlies *damnvulnerableapp* is `/system/bin/app_process64`. To that end, observe that Java apps are [forked from the zygote process](https://link.springer.com/article/10.1007/s10207-018-00425-8). The zygote process, among other things, initializes the JVM to allow for faster app starts.

### Analysing the Stack Trace

There is one more thing to consider. When given a leak, e.g. an address from the stack, then it is important to (partially) understand what values are located on the stack. To that end, one may write a small native app via *Android Studio*, set a breakpoint on the native function and run the app. This could result in the following stack trace:
```
Java_com_damnvulnerableapp_vulnerable_modules_EasyStackBufferOverflowModule_vulnerableToUpper EasyStackBufferOverflowModule.c:32
art_quick_generic_jni_trampoline 0x000071636dba032c
art_quick_invoke_stub 0x000071636db95015
art::ArtMethod::Invoke(art::Thread *, unsigned int *, unsigned int, art::JValue *, const char *) 0x000071636dc1d9fb
art::interpreter::ArtInterpreterToCompiledCodeBridge(art::Thread *, art::ArtMethod *, art::ShadowFrame *, unsigned short, art::JValue *) 0x000071636dda335d
art::interpreter::DoCall<…>(art::ArtMethod *, art::Thread *, art::ShadowFrame &, const art::Instruction *, unsigned short, art::JValue *) 0x000071636dd9d16d
art::interpreter::ExecuteSwitchImplCpp<…>(art::interpreter::SwitchImplContext *) 0x000071636dbac1d0
ExecuteSwitchImplAsm 0x000071636dba23d6
art::interpreter::ExecuteSwitch(art::Thread *, const art::CodeItemDataAccessor &, art::ShadowFrame &, art::JValue, bool) 0x000071636dd9ca6e
art::interpreter::Execute(art::Thread *, const art::CodeItemDataAccessor &, art::ShadowFrame &, art::JValue, bool, bool) 0x000071636dd94ae1
art::interpreter::ArtInterpreterToInterpreterBridge(art::Thread *, const art::CodeItemDataAccessor &, art::ShadowFrame *, art::JValue *) 0x000071636dd9c55c
art::interpreter::DoCall<…>(art::ArtMethod *, art::Thread *, art::ShadowFrame &, const art::Instruction *, unsigned short, art::JValue *) 0x000071636dd9d14e
MterpInvokeVirtual 0x000071636e16e306
mterp_op_invoke_virtual 0x000071636db7e71a
art::interpreter::Execute(art::Thread *, const art::CodeItemDataAccessor &, art::ShadowFrame &, art::JValue, bool, bool) 0x000071636dd94b43
art::interpreter::ArtInterpreterToInterpreterBridge(art::Thread *, const art::CodeItemDataAccessor &, art::ShadowFrame *, art::JValue *) 0x000071636dd9c55c
art::interpreter::DoCall<…>(art::ArtMethod *, art::Thread *, art::ShadowFrame &, const art::Instruction *, unsigned short, art::JValue *) 0x000071636dd9d14e
MterpInvokeVirtual 0x000071636e16e306
mterp_op_invoke_virtual 0x000071636db7e71a
art::interpreter::Execute(art::Thread *, const art::CodeItemDataAccessor &, art::ShadowFrame &, art::JValue, bool, bool) 0x000071636dd94b43
art::interpreter::ArtInterpreterToInterpreterBridge(art::Thread *, const art::CodeItemDataAccessor &, art::ShadowFrame *, art::JValue *) 0x000071636dd9c55c
art::interpreter::DoCall<…>(art::ArtMethod *, art::Thread *, art::ShadowFrame &, const art::Instruction *, unsigned short, art::JValue *) 0x000071636dd9d14e
MterpInvokeInterface 0x000071636e175bfd
mterp_op_invoke_interface 0x000071636db7e91a
art::interpreter::Execute(art::Thread *, const art::CodeItemDataAccessor &, art::ShadowFrame &, art::JValue, bool, bool) 0x000071636dd94b43
artQuickToInterpreterBridge 0x000071636e159a70
art_quick_to_interpreter_bridge 0x000071636dba04bd
<unknown> 0x000071636dba07c0
```

This is a stack - trace of a module that will be exploited in a later post. The most important address is the return address of `Java_com_damnvulnerableapp_vulnerable_modules_EasyStackBufferOverflowModule_vulnerableToUpper`, i.e the address into `art_quick_generic_jni_trampoline: 0x000071636dba032c`. Depending on whether the native method is e.g. declared as `static` or not, [different stubs](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:art/runtime/art_method.cc;l=369) are called, which may result in different return addresses. Thus it might be beneficial to produce a small sample app with the same setup as the target app, especially w.r.t. access modifiers etc. of the native method, to get an idea of the stack - trace.

### Debugging on Android

Another very important aspect of binary exploitation is *debugging*. There are a lot of good resources out there (like [1](https://simoneaonzo.it/gdb-android/), [2](https://wladimir-tm4pda.github.io/porting/debugging_gdb.html)). One possible debugger is [*GDB*](https://man7.org/linux/man-pages/man1/gdb.1.html). As *GDB* by itself is pretty hard to use, I will use an extensions in this series, called [*GEF*](https://github.com/hugsy/gef). A prerequisite is that we have root access on the device/emulator.

#### Starting an app from terminal

In order to debug an app, the app needs to run. In this case, as we are using a "special" app, we just need to run it without waiting for a debugger to attach. Running an app can be done as follows:
```bash
$ adb shell "am start -n com.damnvulnerableapp/com.damnvulnerableapp.managerservice.ManagerActivity"
```
Here we assume that the app of choice is the *DamnVulnerableApp*, which is the main focus of this series.

From here onwards, the manager will run in the background and wait for incoming connections. Once a connection is established, the messages will be used to tell the manager what to do, like spawning a vulnerable module.

#### Starting an exploit script

Assuming that connecting to a socket server is not a great challenge, right after the connection has been established and a vulnerable module selected, the exploit script should wait for the debugger to attach. This can be achieved like demonstrated in the following:
```python
# Need tcp forward, i.e. 'adb forward tcp:8080 tcp:8080'
client = PwnClient('127.0.0.1', 8080)

client.select('EasyStackBufferOverflowModule')
print(client.fetch())

input('Press <enter> to continue...')
...
```
This is not *the clean way*, but it works just fine.

#### Attaching gdb

Notice that selecting a module should spawn a new process that encapsulates the vulnerable module. Now we need a *gdbserver*, which is part of the [*Android NDK*](https://developer.android.com/ndk). Uploading the *gdbserver* to e.g. `/data/local/tmp/gdbserver` will enable us to attach to running processes. The command history could look like this:
```bash
$ adb push gdbserver /data/local/tmp/gdbserver
$ adb shell "chmod 777 /data/local/tmp/gdbserver"
$ adb forward tcp:1337 tcp:1337
$ adb shell "/data/local/tmp/gdbserver :1337 --attach $(pidof com.damnvulnerableapp:VulnerableActivity)"
...
Listening on port 1337
```
We will make *gdb* connect to port `1337` for debugging. After the last command, the process will block until a debugger connects. Before that, we should provide gdb with all necessary symbol information that is helpful for debugging. Namely (inspired from [here](https://simoneaonzo.it/gdb-android/)):
```bash
$ mkdir ~/dbgtmp
$ adb pull /system/lib64 ~/dbgtmp
$ mkdir ~/dbgtmp/tmp
$ adb pull /apex/com.android.art/lib64 ~/dbgtmp/tmp
$ mv ~/dbgtmp/tmp/* ~/dbgtmp/lib64
$ cp ~/path/to/unpacked/apk/lib/x86_64/* ~/dbgtmp/lib64
```

Then, in *gdb/gef* (taken from [here](https://wladimir-tm4pda.github.io/porting/debugging_gdb.html) and [here](https://simoneaonzo.it/gdb-android/)):
```bash
gef➤  set solib-absolute-prefix ~/dbgtmp/
gef➤  set solib-search-path ~/dbgtmp/lib64/
gef➤  gef-remote :1337
...
[+] Connected to ':1337'
[+] Remote information loaded to temporary path '/tmp/gef/6695'
gef➤  sharedlibrary
...
```
The last command will take **ages** to run, but its worth as we get access to almost all symbols we need (there is most likely a better way to do this). Basically we just need to do this once with all the libraries, then identify the libraries we are interested in and create a directory next to `lib64` on our local machine that only contains this interesting subset of the shared - object files. This will speed up loading time by a lot!

## Summary

We have seen some security mechanisms that will make the life of an attacker harder. Depending on the assumptions, like e.g. leaking an address, some mechanisms can be rendered useless. Also, we are now able to get limited source code access and debug Android apps using `gdb`. This will allow us to exploit the available modules in *damnvulnerableapp*.