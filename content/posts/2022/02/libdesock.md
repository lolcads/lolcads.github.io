---
title: "libdesock"
date: 2022-02-22T14:24:40+01:00
draft: false
author: Patrick Detering
tags: [fuzzing, network, sockets, emulation]
keywords: [fuzzing, network, sockets, emulation]
---

# Fuzzing Network Applications with AFL and libdesock

Fuzzing network servers with AFL is challenging since AFL provides its 
input via stdin or command line arguments while servers get their input 
over network connections.
As the popularity of AFL grew, many attempts have been made of fuzzing
popular servers like apache and nginx using different
techniques and hacky workarounds. However an off-the-shelf network fuzzing
solution for AFL didn't exist for a long time until so-called "desocketing"
tools emerged.
These desocketing tools enabled network fuzzing without
making a lot of additional modifications to the program under test
and quickly became widely used in combination with AFL.

### What is "desocketing"?
Before desocketing tools were published two common techniques for
network fuzzing were
1. Sending fuzz input over real network connections
2. Modifying the target source to use stdin instead of sockets

The first approach is the most prevalent used by popular fuzzers
like [boofuzz](https://github.com/jtpereyda/boofuzz) or in academia by [AFLnet](https://github.com/aflnet/aflnet) or [StateAFL](https://github.com/stateafl/stateafl).
This however suffers performance- and stability-drawbacks. 
Stability is affected because the servers run with all threads and child processes
enabled. Background threads can be scheduled independently from the input being sent
resulting in invalid coverage information.
Performance is affected because of the amount of kernel activity and network overhead involved.

The second approach solves the network overhead problem but does not reduce the
kernel activity. It also takes a considerable amount of effort that may lead
to changing [thousands of lines of code](https://securitylab.github.com/research/fuzzing-sockets-FTP/).

Desocketing aims to reduce kernel activity and the amount of modifications necessary to a program.
It works by building a shared library that implements functions
like `socket()` and `accept()` and preloading it via `LD_PRELOAD`
into the address space of a network application where it replaces
the network stack of the libc.
The desocketing library simulates incoming connections to the server
but every read on a socket is replaced by a read on stdin
and every write on a socket is redirected to stdout.
Strictly speaking the latter isn't necessary for fuzzing but it's useful
for debugging.

The following figure demonstrates how to desock nginx such that the network
traffic becomes visible on a terminal.

![](/2022/02/demo.svg)

### How desocketing works
Making desocketing libraries has its complexities.
AFLplusplus' [socketfuzz](https://github.com/AFLplusplus/AFLplusplus/tree/stable/utils/socket_fuzzing)
ships a desocketing library that just returns `0` (stdin) in `accept()`.
Unfortunately this doesn't quite work because `send()` and `recv()` need an
fd that actually refers to a network connection. If you pass them an fd that 
refers to a file the kernel will complain.
Thus we need more complicated methods.

At the time of writing this, there exists only one popular desocketing solution: [preeny](https://github.com/zardus/preeny).
preeny creates a socketpair `(a,b)` and spawns two threads `t1` and
`t2` in every call to `socket()`.   
- Thread `t1` forwards all data from stdin to `a`
- Thread `t2` forwards all data from `a` to stdout
- In `socket()` preeny returns `b`
- When AFL writes input to stdin, thread `t1` forwards that data to `a`
- Writing to `a` means that the data will become available in `b` and the 
  application can read the request from `b`
- The application writes a response back to `b`, making the data available
  in socket `a` where `t2` forwards it to stdout.
  
![](/2022/02/preeny.png)

Unfortunately this design makes preeny unsuitable for fuzzing:

1. Spawning threads and joining them introduces additional overhead.
2. Each thread realizes busy waiting by calling `poll()` every 15ms
3. Preeny still relies on a lot of kernel interaction. I/O multiplexing (select, poll, epoll)
   is left completely to the kernel.
4. The threads may introduce additional instability.  
   Normally you want to disable threads when fuzzing with AFL.
5. It can handle only single-threaded applications but most of the servers
   are multi-threaded

A better desocketing library is needed that is more resource-efficient and handles the complexities of 
modern network applications correctly.
So we created a new desocketing library: "libdesock".

### Using libdesock
libdesock fully emulates the network stack of the kernel. The kernel is only queried to obtain file
descriptors and to do I/O on stdin and stdout.
Everything else - handling of connections, I/O multiplexing (select, poll, epoll), handling socket metadata (getsockname, getpeername) - entierly happens in userland.   
In contrast to preeny, libdesock supports multi-threaded applications and its overall design
makes it more resource efficient and 5x faster than preeny.
This has no effect on AFL's exec/s though, since that primarily depends on the program
and the input.

We have tested libdesock on common network daemons like
- nginx
- Apache httpd
- OpenSSH
- Exim
- bind9
- OpenVPN
- Redis
- dnsmasq
- cupsd
- curl (clients are supported too)

and several smaller applications.   
libdesock also supports event libraries like
- libevent
- libuv
- libapr-2

Network applications generally are very complex and require modifications to be fuzzable with AFL.   
They use multiple processes and threads, encryption, compression, checksums, hashes
and sometimes custom allocators that don't work with ASAN.
They also run in an endless loop and have a lot of disk I/O (pidfiles, logfiles, temporary files).
Setting these targets up for fuzzing means to reduce the complexity of the applications.
The following example demonstrates the modifications necessary to fuzz [vsftpd](https://security.appspot.com/vsftpd.html), a popular FTP server on Linux.

### Fuzzing vsftpd
#### Getting the source
Download version 3.0.5 of vsftpd:
```sh
wget https://security.appspot.com/downloads/vsftpd-3.0.5.tar.gz
tar -xf vsftpd-3.0.5.tar.gz
cd vsftpd-3.0.5
```

#### Patching the source
vsftpd creates a new child process for each connection. We prohibit that
by commenting out the code that does the fork in `standalone.c`:
```diff
@@ -153,6 +153,7 @@ vsf_standalone_main(void)
     child_info.num_this_ip = 0;
     p_raw_addr = vsf_sysutil_sockaddr_get_raw_addr(p_accept_addr);
     child_info.num_this_ip = handle_ip_count(p_raw_addr);
+    /*
     if (tunable_isolate)
     {
       if (tunable_http_enable && tunable_isolate_network)
@@ -168,6 +169,8 @@ vsf_standalone_main(void)
     {
       new_child = vsf_sysutil_fork_failok();
     }
+    */
+    new_child = 0;
     if (new_child != 0)
     {
       /* Parent context */
```

vsftpd duplicates the FTP command socket to stdin, stdout and stderr.
This obviously interfers with AFL so we disable that in `defs.h` ...
```diff
@@ -3,7 +3,7 @@
 
 #define VSFTP_DEFAULT_CONFIG    "/etc/vsftpd.conf"
 
-#define VSFTP_COMMAND_FD        0
+#define VSFTP_COMMAND_FD        29
 
 #define VSFTP_PASSWORD_MAX      128
 #define VSFTP_USERNAME_MAX      128
```
... and in `standalone.c`
```diff
@@ -205,9 +205,7 @@ static void
 prepare_child(int new_client_sock)
 {
   /* We must satisfy the contract: command socket on fd 0, 1, 2 */
-  vsf_sysutil_dupfd2(new_client_sock, 0);
-  vsf_sysutil_dupfd2(new_client_sock, 1);
-  vsf_sysutil_dupfd2(new_client_sock, 2);
+  vsf_sysutil_dupfd2(new_client_sock, VSFTP_COMMAND_FD);
   if (new_client_sock > 2)
   {
     vsf_sysutil_close(new_client_sock);
```

Next, vsftpd enforces a custom memory limit that interfers with ASAN.
We disable the memory limit in `sysutil.c`
```diff
@@ -2793,6 +2793,7 @@ void
 vsf_sysutil_set_address_space_limit(unsigned long bytes)
 {
   /* Unfortunately, OpenBSD is missing RLIMIT_AS. */
+  return;
 #ifdef RLIMIT_AS
   int ret;
   struct rlimit rlim;
```

Then we add a forkserver to vsftpd in `prelogin.c`
```diff
@@ -59,6 +59,7 @@ init_connection(struct vsf_session* p_sess)
   {
     emit_greeting(p_sess);
   }
+  __AFL_INIT();
   parse_username_password(p_sess);
 }
```

vsftpd registers a `SIGCHLD` handler that interfers with the forkserver
so we have to disable that too in `standalone.c`
```diff
@@ -74,7 +74,7 @@ vsf_standalone_main(void)
   {
     vsf_sysutil_setproctitle("LISTENER");
   }
-  vsf_sysutil_install_sighandler(kVSFSysUtilSigCHLD, handle_sigchld, 0, 1);
+  //vsf_sysutil_install_sighandler(kVSFSysUtilSigCHLD, handle_sigchld, 0, 1);
   vsf_sysutil_install_sighandler(kVSFSysUtilSigHUP, handle_sighup, 0, 1);
   if (tunable_listen)
   {
```

Last but not least we disable the `bug()` function in `utility.c`. This function does a failing `fcntl()`
on an fd returned by the desocketing library since the fd is not a real socket. vsftpd handles the `fcntl()` failure by calling `bug()` again
leading to an infinite loop.
```diff
@@ -40,6 +40,7 @@ die2(const char* p_text1, const char* p_text2)
 void
 bug(const char* p_text)
 {
+  return;
   /* Rats. Try and write the reason to the network for diagnostics */
   vsf_sysutil_activate_noblock(VSFTP_COMMAND_FD);
   (void) vsf_sysutil_write_loop(VSFTP_COMMAND_FD, "500 OOPS: ", 10);
```

#### Build configuration
In the `Makefile` replace:
```diff
@@ -1,16 +1,16 @@
 # Makefile for systems with GNU tools
-CC 	=	gcc
+CC 	=	afl-clang-fast
 INSTALL	=	install
 IFLAGS  = -idirafter dummyinc
 #CFLAGS = -g
-CFLAGS	=	-O2 -fPIE -fstack-protector --param=ssp-buffer-size=4 \
-	-Wall -W -Wshadow -Werror -Wformat-security \
+CFLAGS	=	-fsanitize=address -g -Og -fPIE -fstack-protector \
+	-Wall -W -Wshadow -Wformat-security \
     -D_FORTIFY_SOURCE=2 \
     #-pedantic -Wconversion
 
 LIBS	=	`./vsf_findlibs.sh`
-LINK	=	-Wl,-s
-LDFLAGS	=	-fPIE -pie -Wl,-z,relro -Wl,-z,now
+LINK	=	
+LDFLAGS	=	-fPIE -pie -Wl,-z,relro -Wl,-z,now -fsanitize=address
 
 OBJS	=	main.o utility.o prelogin.o ftpcmdio.o postlogin.o privsock.o \
         tunables.o ftpdataio.o secbuf.o ls.o \
```

#### Runtime configuration
Like most other servers, vsftpd needs a config file. Create
`fuzz.conf` with the following contents:
```
listen=YES
seccomp_sandbox=NO
one_process_model=YES

# User management
anonymous_enable=YES
no_anon_password=YES
nopriv_user=nobody

# Permissions
connect_from_port_20=NO
run_as_launching_user=YES
listen_port=2121
listen_address=127.0.0.1
pasv_address=127.0.0.1

# Filesystem interactions
write_enable=NO
download_enable=NO
```

#### Start fuzzing
To use the desocketing library with AFL we need to set the `AFL_PRELOAD`
variable.
```sh
export AFL_PRELOAD=libdesock.so
afl-fuzz -i corpus -o findings -m none -- ./vsftpd fuzz.conf
```

![](/2022/02/afl.svg)

Now it's only a matter of high-quality custom mutators and time to find some bugs.

libdesock can be downloaded here: https://github.com/fkie-cad/libdesock