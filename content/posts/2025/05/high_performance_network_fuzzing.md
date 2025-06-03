---
title: "How to build a high-performance network fuzzer with LibAFL and libdesock"
date: 2025-05-21T18:32:12+02:00
draft: false
author: "Patrick Detering"
tags: ["network", "fuzzing"]
description: "We explain how we built a fuzzer for network applications that we tried to make as efficient and as effective as possible. We utilized custom mutators and input passing over shared memory and found that it gave us a huge speed and coverage boost compared to other network fuzzers."
showFullContent: false
---

## Introduction
Existing network fuzzing solutions struggle on all fronts.
Speed is a big problem because they use either real network connections or
emulation/virtualization for snapshot-based fuzzing, both of which have a
huge overhead.
And, they struggle with deeply exploring the target since most of
the tools out there are built on top of AFL.   
For our vulnerability research, we built a high-performance network fuzzer
that tackles these problems and would like to present its setup in this post.   
The first issue we addressed was the problem of input generation. We developed
our own input representation and mutators that work with text-based protocols.
For that we used [LibAFL](https://github.com/AFLplusplus/LibAFL), a library for building custom fuzzers, which made
this very easy.   
The second problem we approached was how to feed inputs to network applications.
For this, we chose to "desocket" the applications with [libdesock](https://github.com/fkie-cad/libdesock) and serve
the individual packets over a shared memory channel.   
We compared our tool to [AFLNet](https://github.com/aflnet/aflnet), arguably the most popular network fuzzer at
the time of writing this, and found that our setup gave us a 42x performance boost,
orders of magnitude more coverage and new vulnerabilities in already heavily
fuzzed software.

## Writing a Custom Fuzzer
If we want to find bugs we need to emancipate ourselves from off-the-shelf tools like AFL.   
Let's have a look at this message exchange in the FTP protocol that is used to establish
a connection for data transmission:
```
> PORT 192,168,1,178,12,34
< 200 Okay
```
What could be sensible ways to mutate this message? Do we just want to fuzz the message parser
or could some mutations exercise the application logic on a higher level?   
Perhaps we could replace the numbers in the command with other numbers like `-1`, `127` or `4294967295`.
Or, we could replace the `PORT` command with another command.
Or, we could try if `PORT` takes other arguments by inserting more text separated by spaces.
Either way, our fuzzer needs meaningful text-based mutations and an input representation that enables them.

Our approach was to represent individual messages of a protocol as a stream of tokens, i.e. a `TokenStream`,
where a `Token` is either a `Number`, `Whitespace`, or `Text`.
The `PORT` command above would be parsed as:
```
TokenStream([
  Text("PORT"),
  Whitespace(" "),
  Number("192"),
  Text(","),
  Number("168"),
  ...
  Whitespace("\r\n"),
])
```
This enables our mutators to have some sense of "awareness", i.e. the
ability to operate on entire meaningful, semantic units of text. Now
we can individually mutate the numbers, the command, entire arguments,
and much more while still being low-level enough to just flip some bits
in the text.    
Then we can get to the next level of our input representation.
Since network protocols are a back and forth of multiple messages, our
input needs to be a sequence of `TokenStream`s, not just a single one.
In Rust, this is very easy to implement. We simply define our data types...
```rs
enum TextToken {
    Number(Vec<u8>),
    Whitespace(Vec<u8>),
    Text(Vec<u8>),
}

struct TokenStream(Vec<TextToken>);

struct PacketBasedInput(Vec<TokenStream>);
```
...and plug the `PacketBasedInput` into our fuzzer without hassle, thanks to LibAFL.  
The rest of the fuzzer is kept very simple: No powerschedules, mutation scheduling,
compare coverage or extra feedback about the protocol state.

## Implementing Fast Message Passing
Now we have a good method for input generation but we don't want to sacrifice efficiency for effectiveness.
In other words: We need a high-performance method of transmitting fuzz input to the application.
And this is where our desocketing library [libdesock](https://github.com/fkie-cad/libdesock) comes into play.   
With the [desocketing approach](https://lolcads.github.io/posts/2022/02/libdesock/), we can hook the network functions of the target and handle
network I/O that would otherwise be delegated to the kernel in userspace.
Normally desocketing libraries redirect `recv()`'s on network sockets to some other input channel like stdin
but libdesock allows us to customize this behavior and implement our own input channel.
We chose to use shared memory because it has by far the lowest overhead of all IPC methods.

We made use of the [*hooks*](https://github.com/fkie-cad/libdesock/blob/main/src/hooks.c) feature of libdesock and quickly wrote
our own *input hook* in less than 50 lines of C code that attaches to the shared memory channel and copies its data to the
application whenever requested:
```c
// Set by the fuzzer in each iteration:
typedef struct {
    size_t cursor; // set to 0 for each new input
    size_t size; // length of fuzz input
    char data[]; // fuzz input
} PacketBuffer;

PacketBuffer* packet_buffer = /* points to shm */;

// Called whenever a read on a network connection occurs.
// We place `size` bytes from the shm channel into `buf`.
size_t hook_input (char* buf, size_t size) {
    size_t cursor = packet_buffer->cursor;
    size_t rem_bytes = packet_buffer->size - cursor;
    
    size = (size < rem_bytes) ? size : rem_bytes;
    
    memcpy(buf, &packet_buffer->data[cursor], size);
    packet_buffer->cursor += size;
    
    return size;
}
```
You might ask yourself how multiple messages are handled since we are just dealing with one flat shared memory buffer.   
The `Token`s of a `TokenStream` in a `PacketBasedInput` get concatenated to create a single message.
Then, the individual messages get separated by the string `--------`, which is understood by libdesock.
libdesock automatically detects this separator and feeds input to the application one message at a time.
For example, a valid SMTP transaction to send an E-Mail looks like this:
```
EHLO fuzz
--------
AUTH PLAIN
--------
AHRlc3QAdGVzdA==
--------
MAIL FROM:<fuzzer@localhost>
--------
RCPT TO:<user@localhost>
--------
DATA
--------
<email content here>
.
--------
QUIT
```

## Reaping the Results
We did some network fuzzing with AFLNet and our tool.   
With AFLNet we got around \~30 exec/s on one core and were not able to utilize multiple cores for fuzzing.
With our fuzzer, we got around \~1200 exec/s pro core and were able to utilize multicore-fuzzing with linear
scaling (!), which came as a surprise to us since our targets were very syscall-heavy.
Overall we got hundreds of lines more coverage and found multiple bugs in already heavily fuzzed code.   

The lesson we learned is that if we want to find bugs, we can't just rely on off-the-shelf
fuzzers. A fuzzing solution that gave us an edge was not as far away as we thought.
Even with a little bit of effort we got substantial performance increases.

If you're interested in the implementation details, you can find our fuzzer  [here](https://github.com/pd-fkie/exim-fuzzer) on Github.

Thanks for reading!
