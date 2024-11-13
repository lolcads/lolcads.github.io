---
title: "Towards utilizing BTF Information in Linux Memory Forensics"
date: 2024-11-13T12:38:49+01:00
draft: false
author: "Valentin Obst"
tags: ["Linux", "Kernel", "BTF", "Forensics"]
keywords: ["Linux", "Kernel", "BTF", "Forensics"]
readingTime: true
---

This post is about some work that I did on automatic profile generation for memory forensics of Linux systems. To be upfront about it: This work is somewhat half-finished -- it already does something quite useful, but it could do a lot more, and it has not been evaluated thoroughly enough to be considered "production ready". The reason I decided to publish it anyway is that I believe that there is an interesting opportunity to change the way in which we generate profiles for the analysis of Linux memory images _in practice_. However, in order for it to become a production tool, at least one outstanding problem has to be addressed (I have some ideas on that one) and lots of coding work needs to be done -- and I simply do not have the resources to work on that right now.

_Note_: It has been a while since I actively worked on this project, so if someone else ran with this idea in the meantime, please let me know!

_Note_: You can find the code of the prototype [here](https://github.com/vobst/btf2json).

So, what is this work about? To analyze memory images, we need _profiles_, usually those are generated from DWARF debug information, e.g., using tools like [`dwarf2json`](https://github.com/volatilityfoundation/dwarf2json). However, here is the problem: DWARF is HUGE, so production kernels never ship with it; thus, it is highly unlikely that the kernel on the target whose memory we are analyzing includes them. Luckily, most (but not all!) Linux distributions provide debug-packages for their kernels. Consequently, a precondition for the generation of a profile is usually to figure out the distribution and exact version of the kernel in the image, and then to download the corresponding debug package.

But now comes the surprise: What if I tell you that virtually every production kernel that ships today comes with most of the information that we need to generate a profile for it? And that this information can be readily extracted from a raw memory image? Exploring this opportunity is what this work was all about.

To explain how and why this works, I'll start by [introducing the notion of a _profile_ in memory forensics](#whats-a-profile), [state the problem that we strive to address](#whats-the-problem), then [talk about the BPF Type Format (BTF)](#whats-our-solution-meet-the-bpf-type-format-btf), [describe how BTF can be used to generate a part of a profile](#what-we-have) (+ an [evaluation of our implementation](#evaluation)), [discuss some open questions around symbols](#symbols-are-only-partially-solved), and finally [outline what needs to be done for this project to reach its full potential](#call-to-action).

Let's get started!

## What's a Profile?

In short: A _profile_ is a bunch of information that is used by _analyses_ to make sense of the raw bytes in a memory image. In other words, it allows you to "bridge the semantic gap" between 1s and 0s in a dump and the answer to interesting questions like "Which network connections did the process that was stated at 13:37 made?".

Usually, a profile consists of two parts: Information about _symbols_ and _types_ of the kernel that was running on the machine. Symbols are what get you a foot in the door, i.e. where an analysis starts. For example, the head of the list of all tasks can be found via the `init_task` symbol. From there onward, the types are what allows an analysis to make sense of the raw bytes it finds, to transition between objects by following pointers, and eventually to extract useful information.

Symbols are pretty simple, they are just _names_ for memory _locations_ together with the _type_ of the data that is stored there. We will say that the triple of `(name, location, type)` forms a symbol.

Types are essentially recipes that tell you how to turn raw bytes back into a value of a C-type, i.e., they are a description of the memory layout of a C-type. We will say that the tuple `(c_type_kind, c_type_name, memory_layout)` forms a type.


## What's the problem?

The information in a profile is specific to a _particular compilation_ of the operating system kernel, e.g., think of the linker’s freedom in arranging global variables or compile-time options that influence the layout of types. For Windows and macOS it is possible to build a profile database of all released kernels, i.e., you only have to find out which release you have in your dump and then you are ready to go. For Linux, there is a whole zoo of distros and even more kernel packages, a new one of which gets released every few days [^1]. Building a comprehensive Linux profile database is an endeavor that is doomed to fail.

There are reliable heuristics for inferring the release of the OS in your dump. Those work well for Windows, macOS and most Linux distros. However, the infeasibility of building a Linux profile database means that you must still use that information about the release to build the profile yourself. Usually this involves downloading the debug package of that exact release and running some tool against it. If this package does not exist, you are lost at that point. In particular this implies that you are completely lost if you are not analyzing a dump of a system running a mainstream Linux distro.

So, let's get to the definition of the "profile generation problem": Given only the bytes in a memory dump, tell me the symbols and types of the kernel that was running in there (maybe not all of them, but enough to do useful analyses).

Are there existing solutions to this problem? Yes, plenty. There is like 1m of papers, some dating back many years, that identify and address this problem using all sorts of creative approaches, e.g., [Oliveri et al.](https://www.ndss-symposium.org/ndss-paper/an-os-agnostic-approach-to-memory-forensics/), [Pagani et al.](https://dl.acm.org/doi/full/10.1145/3485471), [Franzen et al.](https://dl.acm.org/doi/abs/10.1145/3545948.3545980), [Qi et al.](https://www.ndss-symposium.org/ndss-paper/auto-draft-193/), [Cohen et al.](https://dfrws.org/presentation/automatic-profile-generation-for-live-linux-memory-analysis/), or [Feng et al.](https://dl.acm.org/doi/abs/10.1145/2897845.2897850).

Seemingly, the "rule of the game" seems to be that you are allowed to do all sorts of up-front or on-demand analyses that involve the upstream Linux _source code_, and sometimes even on the live system, to support your analysis of the raw image. We'll also need to make use of the former crutch to make our solution work.

Why yet another solution you may ask? Well, to the best of my knowledge, none of the proposed solutions has seen widespread adoption as of now. My hope is that the simplicity of our approach might mean that it can make generating profiles for images that meet _certain requirements_ as easy as running a cli tool against it and waiting for a few seconds or so. No need to do some complicated setup, download tons of dependencies, compile a thousand Linux kernels with an aging clang fork, and to wait dozens of minutes or even hours for the profile to be finished - just download the binary and you are good to go [^2]. In short, our approach is less general, but hopefully more practical than previous work.

[^1]: Not to mention all the self-compiled kernels that do not have publicly available binary packages at all.
[^2]: Sorry Windows users, no pre-compiled binaries for you – WSL for the win!


## What's our solution? Meet The BPF Type Format (BTF)!

You might have heard about [BPF](https://datatracker.ietf.org/wg/bpf/about/), if not, think of it as an abstract machine with its own bytecode format (a bit like the JVM or WASM). The Linux kernel has its own implementation of this abstract machine, the Linux BPF runtime, i.e., it can execute BPF bytecode programs. The whole point of this subsystem is to have a flexible, fast, safe, and portable way to extend the kernel at runtime. For example, I recently started using the [opensnitch](https://github.com/evilsocket/opensnitch) application-level firewall, and it is in fact enforcing its network policies via multiple BPF programs.

Wait, did you just say _portable_ kernel extensions?!? But how can a program that is compiled to some assembly-like bytecode language and operates on kernel data structures in memory be portable across kernel versions? After all code like:

```c
struct my_struct {
#ifdef BAR
    long bar;
#else
    long foo;
}

long read_foo(struct my_struct* x) {
    return my_struct->foo;
}
```

should be compiled down to instructions that have things like "Is a `long` 4 or 8 bytes?" or "Was `BAR` defined?" hard coded inside them. The solution to this apparent paradox lies in the interplay of four components: the [`preserve-access-index` C-language attribute](https://clang.llvm.org/docs/AttributeReference.html#preserve-access-index), the compiler toolchain, the user-space dynamic loader, and the kernel that the program should be loaded into.

In the program's C source code, structures/unions whose member accesses should be portable must be marked with the `preserve-access-index` attribute [^3]. The compiler will then generate the accessing code without hard-coded offsets and record which field of which type was accessed at a particular location in [relocation information](https://www.kernel.org/doc/html/latest/bpf/llvm_reloc.html#co-re-relocations). This information is processed by the user-space dynamic loader running on the target system, which adjusts the program to the layout of types in the running kernel before loading it. The information about memory layout of types is supplied by the running kernel itself via the files in the `/sys/kernel/btf/` pseudo file system.

Whaaat? Each and every kernel out there that wants to support portable BPF programs (pretty much every single one) must ship with a description of the memory layout of all its types? That's like having Christmas and your birthday together! Indeed, the relevant information is stored in the `.BTF` sections of the kernel and module ELF files in the [well documented BPF Type Format](https://www.kernel.org/doc/html/latest/bpf/btf.html).

This solves the whole _types_ part of the "profile-generation-problem" for most modern kernels without the need for a debug build. Furthermore, since the kernel image is contiguous in physical memory, it is straight forward to carve the section from a memory image.

_Note:_ The reason why it is feasible to include the BTF information in production kernels is since it is much smaller than DWARF debug information. In part, this is achieved by the format being much less wasteful with disk space, however, it is also fundamentally less expressive. Thus, it is a priori not clear that BTF contains all the type information needed by memory forensics analyses. It was part of this work to establish that this is indeed the case (not too surprising given BTF's original use case described above). I recommend [this post](https://nakryiko.com/posts/btf-dedup/) for an introduction to the BTF format and its relationship to DWARF.

_Note:_ BTF has been around for quite a while, since [Linux 4.18](https://github.com/torvalds/linux/commit/69b693f0aefa0ed521e8bd02260523b5ae446ad7) to be precise, so it is not like you will only find it in bleeding edge kernels.

[^3]: Alternatively, a portable program can make use of [compiler built-ins](https://gcc.gnu.org/onlinedocs/gcc/BPF-Built-in-Functions.html) that can be combined to achieve the same effect, but allow it to do even crazier things, like testing whether a field of an enum exists. I recommend reading [this post](https://nakryiko.com/posts/bpf-core-reference-guide/) if you are interested in learning more about the mechanics of portable programs.


## What we have!

Let's start with the good news: the [released prototype `btf2json`](https://github.com/vobst/btf2json) can generate working Volatility3 profiles! At the time of our evaluation, those profiles were even "better" than the ones generated by `dwarf2json`, in the sense that they supported more analyses on more memory images. It is also worth noting that the profile generation is about 10x faster.

Currently, `btf2json` accepts either an ELF `vmlinux` image or a raw `.BTF`-section for the type information, as well as a `System.map` file for symbol information, to generate a Volatility3 profile.

```shell
$ btf2json --help
Generate Volatility 3 ISF files from BTF type information

Usage: btf2json [OPTIONS]

Options:
      --btf <BTF>
          BTF file for obtaining type information (can also be a kernel image)

      --map <MAP>
          System.map file for obtaining symbol names and addresses

      --banner <BANNER>
          Linux banner.

          Mandatory if using a BTF file for type information. Takes precedence over all other possible sources of banner information.

      --version
          Print btf2json version

      --verbose
          Display debug output

      --debug
          Display more debug output

      --image <IMAGE>
          Memory image to extract type and/or symbol information from (not implemented)

  -h, --help
          Print help (see a summary with '-h')
$ btf2json --btf path/to/vmlinux/or/btf/section --map path/to/system/map
# prints ISF to stdout
```

_Note_: If you use just the `.BTF`-section for type information, you also need to provide a Linux banner so that Volatility can match the profile to a memory image.

The resulting profile can then be used to drive Volatility analyses, just like any other profile that you would have previously generated with `dwarf2json`.

In its current form, `btf2json` already has one key advantage over `dwarf2json` (besides being much faster :P): no need for debug kernels! This means you can generate profiles for custom, self-compiled kernels (useful when investigating nerds like me) or distributions that do not provide kernel debug symbols (e.g., Arch Linux). Furthermore, you do not have to bother with figuring out the exact kernel release and searching the corresponding debug package in a gigantic repository. Just grab the `vmlinux` and `System.map` from the file system and you are good to go!


### Evaluation

We evaluated `btf2json` on the following kernels:

- Almalinux 9
    - kernel: 5.14.0-362.8.1.el9_3.x86_64 (`f844e`)
- Archlinux
    - kernel: 6.6.7-arch1-1 (`59a42`)
    - kernel: 6.11.6-arch1-1 (`a54bd`)
- Fedora 38
    - kernel: 6.6.6-100.fc38.x86_64 (`85565`)
- Fedora 39
    - kernel: 6.6.6-200.fc39.x86_64 (`7bd7a`)
    - kernel: 6.11.6-100.fc39.x86_64 (`d2be6`)
- Fedora 40
    - kernel: 6.11.6-200.fc40.x86_64 (`bbbb3`)
- Centos 9s
    - kernel: 5.14.0-391.el9.x86_64 (`20d08`)
- Debian 11
    - kernel: 5.10.0-26-amd64 (`2c41e`)
- Rocky 8
    - kernel: 4.18.0-513.9.1.el8_9.x86_64 (`9a6e2`)
- Ubuntu 22.04
    - kernel: 5.15.0-88-generic (`6f76f`)
- Ubuntu 23.10
    - kernel: 6.5.0-10-generic (`ccbb5`)
- Kali Rolling
    - kernel: 6.11.2-amd64 (`c0965`)

For each kernel, we

- used `dwarf2json` (with normal kernel + system map) and `btf2json` (with debug kernel + system map) to generate a profile (we also measured the time this took the tools),
- booted the kernel in a VM,
- took a memory snapshot of the VM,
- ran all upstream Volatility3 Linux analysis plugins on the memory image, with the debug output cranked up to the highest level.

For each analysis the

- exit code,
- stdout stream,
- stderr stream,

were saved.

We then compared the exit codes, and diffed the stdout and stderr streams, of the analysis plugins with the `dwarf2json` and `btf2json` profiles, respectively. Cases where the exit code and/or the stdout/stderr streams differed were manually investigated.

In total, we evaluated 32 analysis plugins on memory images of 13 different kernels, resulting in a total of **416 unique pairs of memory image and analysis plugin**.

- In 394 cases the exit codes of the plugins running with the `btf2json`- and `dwarf2json`-generated profiles were identical.
- In 9 cases the `btf2json` profile lead to a successful analysis while the analysis with the `dwarf2json` profile failed. This was the case for the `linux.capabilities.Capabilities` plugin on all images but Fedora, Ubuntu 23.10, Kali and Archlinux (5 images), and for the `linux.check_syscall.Check_syscall` plugin on Fedora (4 images).
- In 13 cases the analysis failed with both plugins. This was the case for the `linux.vmayarascan.VmaYaraScan` plugin on all images.

We tracked the reason for the failure of the `linux.capabilities.Capabilities` analysis with the `dwarf2json` profiles down to the fact that they assigned the `kernel_cap_t` type for the capabilities in `struct cred` while `btf2json` assigned the `struct kernel_cap_struct` type. While those are in fact related via a typedef, the Volatility3 framework differentiates between them in their implementation to obtain the capability bits. In particular, Volatility uses this distinction to differentiate between pre and post 6.3 kernels (which is why it works on Fedora, Ubuntu, Kali, and Arch), so we believe that there is a bug in the interplay of `dwarf2json`-profiles and Volatility on older kernels.

Concerning the failure of the `linux.check_syscall.Check_syscall` plugin on Fedora, we did not perform an in-depth investigation, however, it seems to be due to issues in the type information of the `dwarf2json` profile. With the `btf2json` profile the system call table is correctly extracted.

Finally, the `linux.vmayarascan.VmaYaraScan` counts as a failure since it throws an exception if no rules are given.

Apart from the 9 cases where only the `btf2json` analysis was successful, the stdout streams of the analyses were identical. On the stderr streams, we observed slight differences in the `DEBUG`-level log messages that hint at differing inconsistencies in the type information of the profiles (`volatility3.framework.symbols: Unresolved reference: ` messages). On average, running all analyses over an image with the `btf2json` profile reports 65 unique inconsistencies, whereas a run with the `dwarf2json` profile detects 90 such inconsistencies.

With regards to the average runtime, our evaluation showed that the profile generation of `btf2json` (1.54s) is significantly faster than that of `dwarf2json` (18.5s), i.e., we see a 12x speedup.

_Note:_ For the evaluation, we used Volatility3 at commit `a00a59cd235cb18b7dc28ccf2669e2a82368fab5`, `btf2json` at commit `18bd9d1015a7433a85ac2634a7a4f34f6d04c851`, and `dwarf2json` at commit `9f14607e0d339d463ea725fbd5c08aa7b7d40f75`.


## Symbols Are Only Partially Solved

Sounds great, right? Well, unfortunately I must admit that `btf2json` has a dirty secret: the `symdb`.

Recall that we defined a symbol as the triple of `(name, location, type)`. We can get the names and locations from the `System.map`. However, while BTF is technically able to encode the types of global variables via the [`BTF_KIND_VAR`](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-var) and [`BTF_KIND_DATASEC`](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-datasec) entries, this is only done for the 400ish per-CPU variables. This leads us to our problem: How do we assign types to symbols?

Let's take a step back and ask ourselves why we even _need_ the type as part of our definition of a symbol. Symbols are usually the "entry point" for an analysis. Think of an analysis that lists all tasks, it will usually start at the `init_task` symbol, and then traverse the dynamically allocated doubly linked list that hangs off it. This stage of "getting a foot into the door" is where the type of a symbol is needed, and in my experience each analysis is only using a handful of symbols for that purpose.

Therefore, we decided to measure for which symbols their types are accessed by the existing Volatility analyses. To do so we instrumented the [method responsible for retrieving the type of a symbol](https://github.com/volatilityfoundation/volatility3/blob/1e871af0644fbd03ba22085241ed795104ccc580/volatility3/framework/interfaces/symbols.py#L60) and re-ran all analyses. We found that **32**, of the 150k+, unique symbols have their type accessed. See the Appendix for a [list of those symbols](#Appendix-A:-Accessed-Symbols).

As we can see, it is only a tiny fraction of the 150k+ symbols that exist in a Linux kernel.

This leads me to a bold claim: It is feasible to build and maintain a map `([kernel m.m.p version], symbol name) -> (type name)` that works in practice.

I believe that this works for three reasons:

1. The subset of symbols that are actually used by analyses is fairly small.
2. The type names of these symbols are very stable between kernel versions.
3. The type names of these symbols do not depend on build-time configuration options.

We call this mapping `symdb` and embed it into the final, stand-alone `btf2json` executable. Thus, under the above assumptions, `btf2json` can generate working profiles just from a kernel's BTF information and `System.map`.

_Note_: This solution is, in general, inferior to what `dwarf2json` does. The `symdb` will contain missing or wrong entries. I just believe that the entries _that matter_ will be correct due to the above considerations.

_Note_: Currently the `symdb` is a mapping `(symbol name) -> (type name)` generated of some kernel I had laying around (and it still works fine for Linux 4.18-6.11!!!). Generating a proper `symdb` and rigorously evaluating the approach is part of the future work outlined below.


## Call to Action

Now, as I said above, I consider this work to be in a half-finished-but-usable state. It can already bring a real benefit to the community, but it is far from reaching its full potential. Thus, here is my vision of what `btf2json` could become through the investment of considerable time and energy (which I currently do not have). If the community decides that it is a goal worth pursuing, I am confident that we can get there.

### Working on a Raw Memory Image

Recall that the ultimate goal of automatic profile generation is to generate the profile off a raw memory image. For that to work we would roughly need to add the following things:

- **Carve the banner from the image** (conceptually trivial, little work).
- **Carve the `.BTF` section from the image** (conceptually simple, little to medium work). Scanning for the magic bytes `0xeb9f` and performing some heuristic checks on matches is sufficient, we already prototyped and evaluated this.
- **Extract kallsyms from the image**, either
    - using a carving approach like [`vmlinux-to-elf`](https://github.com/marin-m/vmlinux-to-elf) (conceptually simple, loooots of work),
    - using an emulation approach like academic papers (conceptually advanced, medium work). This introduces some big dependencies that make shipping a stand-alone cross-platform executable hard.

_Note_: `kallsyms` in memory may contain the addresses with ASLR offsets while the `System.map` has an ASLR-slide of zero. One would either need to find a way to adjust them or teach Volatility to work with "real" addresses, which would tie the profile to a particular image. I have a rough idea how to do the former: scan for swapper as usual, transition to its root page tables via symbol information, reconstruct page tables and read off slide of kernel region.

_Note:_ This obviously only works for kernels compiled with `KALLSYMS=y`.

### Evaluating the `symdb` Approach

Currently, everything around the `symdb` is more or less just me eyeballing based on my (limited) experience that "this stuff should probably work" and our small-scale evaluation. Anyway, we need to actually implement and evaluate this for real!

- **Building and automatically maintaining the `symdb` as it was described above** (conceptually difficult, lots of work). For this we need at the very least the preprocessed C code but working with LLVM IR would be a lot nicer. Then, the extraction of type names for all global symbols is possible for the C code and easy for the LLVM IR. One issue I already see is that to get the preprocessed C code one needs to make choices for all configuration options, and the set of symbols depends on those options - some sort of compromise will be needed here.
- **Evaluating the `symdb` and its underlying assumptions** (conceptually simple, medium work). By using DWARF as ground truth, it should be rather straightforward to evaluate the correctness of the `symdb` mapping.

That's it, thanks for reading!


## Appendix A: Accessed Symbols

List of all symbols whose type is queried when running all Volatility3 analysis plugins. This data was generated by instrumenting the `get_type` method of the `SymbolInterface`.

_Note_: We excluded `linux.check_syscall.CheckSyscall` as this plugin iterates over (all) symbols and calls `get_symbol` which, accesses the type for caching purposes. However, it does not use the type information.

```plaintext
__sched_class_highest
__sched_class_lowest
_etext
_text
cap_last_cap
dl_sched_class
fair_sched_class
idle_sched_class
idt_table
init_files
init_mm
init_pid_ns
init_task
iomem_resource
keyboard_notifier_list
mod_tree
module_kset
modules
net_namespace_list
prb
prog_idr
rt_sched_class
socket_file_ops
sockfs_dentry_operations
stop_sched_class
tcp4_seq_afinfo
tcp6_seq_afinfo
tty_drivers
udp4_seq_afinfo
udp6_seq_afinfo
udplite4_seq_afinfo
udplite6_seq_afinfo
```
