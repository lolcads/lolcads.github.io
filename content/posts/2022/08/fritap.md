+++
title = "friTap - Decrypting TLS on the fly"
date = "2022-08-12T13:09:24+02:00"
author = "Daniel Baier and Francois Egner"
authorTwitter = "" #do not include @
cover = ""
tags = ["frida", "network", "TLS", "TLS decryption"]
keywords = ["frida", "network", "TLS", "TLS decryption"]
description = ""
showFullContent = false
readingTime = true
+++

## Encryption - a curse and a blessing at the same time
Digital communication in today's world has a particularly high status in our society. Financial transactions are conducted via online banking, private communication is increasingly limited to digital messenger services, and even health data is experiencing a shift to digital form. Due to the growth of such sensitive digital data, the need for secure transmission of such data has become increasingly important over the past decades. With the introduction of high-performance and digitally secure cryptographic methods, such as SSL/TLS, today's digital communications are predominantly encrypted. Whereas back then, for example, an attacker could hang himself between the client and the server and read the data traffic without encryption, today all he sees is a jumble of letters.
Encryption is truly a boon for protecting sensitive personal data, but it also has its drawbacks, as with almost everything. Encrypted communications negate the ability to analyze communications, which is very relevant when reverse engineering malware or researching vulnerabilities.



## Man-in-the-middle proxy as a solution
One of the best known solutions to intercept and decrypt encrypted communications is the so-called "man-in-the-middle" attack. In this case, the attacker or analyst pretends to be a trustworthy communication partner to the client. However, since the client often does not know how the client's communication partner, referred to hereafter as the server, communicates or behaves, the attacker (or analyst) forwards the communication to the server and pretends to be the client.
To establish encrypted communication via TLS, for example, a certificate is required, which the server sends to the client when the connection is established. So a connection is established between the MitM proxy and the client using a MitM certificate (fake certificate) and a connection is established between the MitM proxy and the server using a server certificate.
![MitM](/2022/08/mitm_proxy_without_cert_pinning.svg)

Due to this setup, the communication between client and server is routed through the MitM proxy and can be processed on it without encryption.

There are some preventive measures that can prevent such an attack, especially on mobile devices. One of the best known measures is the so-called "certificate pinning". This involves storing the expected server certificate or a hash of the certificate in the binary of the client itself. If the client subsequently receives a certificate from the alleged server, this is compared with the embedded certificate or verified by means of a hash value. If this verification is not successful, then the connection is aborted.


A possible solution to this problem would be to modify the pinning code itself:

![Pinning](/2022/08/certpinning_hooking.svg)

This approach is possible, but in many cases it is very time-consuming, since the implementations of the pinning can differ greatly depending on the version and the analysis of the code must be performed again for each new version if the pinning is not used from a well known library. In addition, there are, especially with malware, several different implementations of pinning, which is why a general approach often does not lead to the goal.

## Our approach: 

One thing is certain: in order to get the unencrypted communication, the client application must be "attacked". This led us to ask why we don't directly extract the decrypted SSL/TLS stream or the key material from the target appliaction.


### Abstraction of using a library

Most applications that perform encrypted communication use a widely available library to do so, such as OpenSSL and NSS. These libraries try to keep the encryption of the data as abstract as possible, so that the use of the library is very convenient. Among other things, they encapsulate the TLS handshake and the sending and receiving of encrypted data.

A common program flow utilizing a TLS library looks like this:

The application wants to establish a secure TLS connection to a server. It uses the TLS library for this purpose, which performs the handshake as shown below:

![GIF here](/2022/08/connection.gif)

After establishing the TLS connection, data can now be sent and received using the read and write functions of the TLS library as shown in the figure below.

![TLS hooking](/2022/08/fritap_approach.svg)


Exactly these TLS-read and TLS-write functions are used by the target application to read and write the plaintext from TLS stream, respectively. 
Hence our tool, [friTap](https://github.com/fkie-cad/friTap), is hooking them in order to receive the plaintext of the encrypted packets. Beside this friTap is also able to extract the used TLS keys.

![friTap](/2022/08/hooking_Fritap.svg)

### friTap usage

[friTap](https://github.com/fkie-cad/friTap) comes with two operation modes. One is to get the plaintext from the TLS payload as PCAP and the other is to get the used TLS keys. 
In order to get the decrypted TLS payload we need the `-p` parameter:
```bash
$ ./friTap.py –m –p decryptedTLS.pcap <target_app>
…
[*] BoringSSL.so found & will be hooked on Android!
[*] Android dynamic loader hooked.
[*] Logging pcap to decryptedTLS.pcap
```

The `-m` paramter indicates that we are analysing a mobile application in the above example. For extracting the TLS keys from a target application we need the `-k` parameter:

```bash
$ ./friTap.py –m –k TLS_keys.log <target_app>
…
[*] BoringSSL.so found & will be hooked on Android!
[*] Android dynamic loader hooked.
[*] Logging keylog file to TLS_keys.log
```

As a result friTap writes all TLS keys to the `TLS_keys.log` file using the [NSS Key Log Format](https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html).

## friTap internals

After understanding the overall approach lets dive into the internals of [friTap](https://github.com/fkie-cad/friTap).

### FRIDA

[friTap](https://github.com/fkie-cad/friTap) is built on the dynamic instrumentation toolkit [FRIDA](https://frida.re/), which allows developers, reverse engineers and security researchers to dynamically analyze and instrument programs. FRIDA allows you to execute Javascript code within the target program, which gives you the ability to hook functions, read and write program memory, execute custom code, and more. A Python API is provided for using FRIDA, which makes it very user-friendly.

To accomplish this, FRIDA injects the [QuickJS Javascript engine](https://bellard.org/quickjs/) (can also be changed to the [V8 runtime](https://v8.dev/)) into the target process and an agent that acts as communication interfaces between the instrumentarized process and its own tool later on. 
After injection of the engine and the agent, the user is able to execute own Javascript code inside the target process and receive data from it. More on the inner workings of FRIDA can be found [here](https://frida.re/docs/presentations/).


### Program flow
A rough overview of the flow of friTap can be seen in the following diagrams, which are explained in more detail in the sections that follow.
The first step after loading the friTap JS script into the target process is to identify the operating system (os) of the target process:

![](/2022/08/fritap_choose_os_agent_final.svg)
             
Then an os specific agent will be loaded. This agent enumerates all loaded libraries/modules from the target process. FRIDA provides a function for this purpose that returns for each loaded module its name, base address, size and path in the file system. Based on the name of the modules friTap can identify a SSL/TLS library. Depending on the version and operating system, the name of the loaded module can vary greatly. friTap tries to cover all potential module names of supported libraries as best as possible using expressive regex. The operating system-specific agent determines which libraries are supported and how its hooking is implemented:


![](/2022/08/fritap_hook.svg)

 When a supported library is detected, friTap tries to hook the `SSL-read()`, `SSL-write()` and `SSL-keyexport()` functions of the respective library and all other functions required for this. Sometimes the target library doesn't provide a key export function, in those cases friTap have to parse the heap in order to find the keys in the memory of the target process.

Next we want to dive into the implementation details of the mentioned parts of friTap. As mentioned above friTap checks at first on which plattform our target process is running and invoke than its respective os specific agent:

```javascript
function load_os_specific_agent() {
    if(isWindows()){
        load_windows_hooking_agent()
    }else if(isAndroid()){
        load_android_hooking_agent()
    }else if(isLinux()){
        load_linux_hooking_agent()
    }else if(isiOS()){
        load_ios_hooking_agent()
    }else if(isMacOS()){
        load_macos_hooking_agent()
    }else{
        log("Error: not supported plattform!\nIf you want to have support for this plattform please make an issue at our github page.")
    }

}
```

This agent installs the hooks for the detected libraries. First the enumerations of the supported SSL/TLS libaries are safed (`module_library_mapping`) and provided for the different hooks. In the following we see how this is done for Android:

```javascript
export function load_android_hooking_agent() {
    module_library_mapping[plattform_name] = [[/.*libssl_sb.so/, boring_execute],[/.*libssl\.so/, boring_execute],[/.*libgnutls\.so/, gnutls_execute],[/.*libwolfssl\.so/, wolfssl_execute],[/.*libnspr[0-9]?\.so/,nss_execute], [/libmbedtls\.so.*/, mbedTLS_execute]];
    install_java_hooks();
    hook_native_Android_SSL_Libs(module_library_mapping);
    hook_Android_Dynamic_Loader(module_library_mapping);
}
```
If supported, friTap installs java based hooks. Right now these java hooks only installed for Android applications. Next the plattform (operating system) specific hooks are installed. After a supported SSL/TLS library has been found, the search for the corresponding functions (read, write, key export) inside the module is started. This is done using the mapped functions from `module_library_mapping`. When we have a closer look into the enumerations we can see that for each detected library an appropriate so called `<libname>-execute` function is mapped. This mapped function contains the implementation details of the `SSL-read()`, `SSL-write()` and `SSL-keyexport()` hooks. Strictly speaking, for each identified library, its platform-specific hook (read, write, export) is installed for the corresponding library. Fortunately, the majority of hooking implementations are platform independent, with only a few platforms having differences. This means that the overall hooking implementation for a specific library is provided by an os independent super class. In the following we see the Android OpenSSL hooking implementation with the implementations inherited from its superclass:

```javascript
/* from openssl_boringssl_android.ts */
export class OpenSSL_BoringSSL_Android extends OpenSSL_BoringSSL {

    constructor(public moduleName:String, public socket_library:String){
        super(moduleName,socket_library);
    }


    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }

}


export function boring_execute(moduleName:String){
    var boring_ssl = new OpenSSL_BoringSSL_Android(moduleName,socket_library);
    boring_ssl.execute_hooks();
}
```
The specific functions of the library are only then hooked in the superclass. This is done by library's specific function names (SSL\_read, SSL\_write...) which are passed to our `readAddresses()` function in order to obtain the addresses for hooking.

```javascript
/* super class openssl_boringssl.ts */
export class OpenSSL_BoringSSL {

    // global variables
    library_method_mapping: { [key: string]: Array<String> } = {};
    addresses: { [key: string]: NativePointer };
    ...

    constructor(public moduleName:String, public socket_library:String,public passed_library_method_mapping?: { [key: string]: Array<String> }){
        if(typeof passed_library_method_mapping !== 'undefined'){
            this.library_method_mapping = passed_library_method_mapping;
        }else{
            this.library_method_mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback"]
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
        }
        
        this.addresses = readAddresses(this.library_method_mapping);
        ...
    }

    ...
```

FRIDA provides with the [ApiResolver](https://frida.re/docs/javascript-api/#apiresolver) a function `enumerateMatches("exports:" + library_name + "!" + method)`: 
This is passed the name of the function, the name of the module and the type (export, import) in a single string. If a match is found, information about this function is returned, of which friTap only needs and stores the address. Below is the whole listing of friTap's `readAddresses()` function:


```javascript
//File: agent/shared/shared_functions.ts

/**
* Read the addresses for the given methods from the given modules
* @param {{[key: string]: Array<String> }} library_method_mapping A string indexed list of arrays, mapping modules to methods
* @return {{[key: string]: NativePointer }} A string indexed list of NativePointers, which point to the respective methods
*/
export function readAddresses(library_method_mapping: { [key: string]: Array<String> }): { [key: string]: NativePointer } {
    var resolver = new ApiResolver("module")
    var addresses: { [key: string]: NativePointer } = {}
    for (let library_name in library_method_mapping) {
        library_method_mapping[library_name].forEach(function (method) {
            var matches = resolver.enumerateMatches("exports:" + library_name + "!" + method)
            var match_number = 0;
            var method_name = method.toString();

            if(method_name.endsWith("*")){
             method_name = method_name.substring(0,method_name.length-1)
            }

            if (matches.length == 0) {
            throw "Could not find " + library_name + "!" + method
            }
            else if (matches.length == 1){
            devlog("Found " + method + " " + matches[0].address)
            }else{
                for (var k = 0; k < matches.length; k++) {
                    if(matches[k].name.endsWith(method_name)){
                        match_number = k;
                        devlog("Found " + method + " " + matches[match_number].address)
                        break;
                    }
                }
            }
            addresses[method_name] = matches[match_number].address;
        })
    }
    return addresses
}
```
After all relevant function addresses are available, friTap finally installs the hooks when entering or leaving the respective functions. More on this later.


It is possible that a program to be analyzed does not load an SSL/TLS library at program start or loads an SSL/TLS library again at another time. For this case friTap hooks a function in the respective standard library of the operating system. The following is the implementation for Android:

```javascript
/* File agent/android/android_agent.ts */

function hook_Android_Dynamic_Loader(module_library_mapping: { [key: string]: Array<[any, (moduleName: string)=>void]> }): void{
    ...
    const regex_libdl = /.*libdl.*\.so/
    const libdl = moduleNames.find(element => element.match(regex_libdl))
    ...

    let dl_exports = Process.getModuleByName(libdl).enumerateExports()
    var dlopen = "dlopen"
    for (var ex of dl_exports) {
        if (ex.name === "android_dlopen_ext") {
            dlopen = "android_dlopen_ext"
            break
        }
    }


    Interceptor.attach(Module.getExportByName(libdl, dlopen), {
        onEnter: function (args) {
            this.moduleName = args[0].readCString()
        },
        onLeave: function (retval: any) {
            if (this.moduleName != undefined) {
                for(let map of module_library_mapping[plattform_name]){
                    let regex = map[0]
                    let func = map[1]
                    if (regex.test(this.moduleName)){
                        log(`${this.moduleName} was loaded & will be hooked on Android!`)
                        func(this.moduleName)
                    } 
                    
                }
            }
        }

        
    })

    console.log(`[*] Android dynamic loader hooked.`)
    ...
}
```
Now all functions for extracting the streams or the key material should have been identified so that friTap can use the hooks for extracting the plaintext payload or the TLS keys.

Lets dive into the hooking implementations itself. The way of instrumentation varies partly between the different supported libraries and plattform, but all follow the same principle.

### Hooking the read function

The read functions of the libraries generally have function signature of the following structure:

```javascript
int read (void*, void*, int)
```

The first parameter is a pointer to an SSL object that holds all information about the SSL session in use in the background. This object is used to identify the SSL/TLS stream over which data is received. The second parameter is a pointer to a temporary buffer that holds unencrypted data received from the SSL/TLS stream. The third parameter is the maximum number of bytes that can be stored in the buffer for data received from the SSL/TLS stream.

For friTap, the second parameter, the buffer containing the unencrypted data, is the important one. To read the contents of this buffer, friTap needs the pointer to it and the number of bytes that were received.
FRIDA's interceptor allows to define hooks for function start and end. These callbacks are executed before the execution and after the execution of the function.
The callback function for the hook of the function start is passed all parameters of the hooked function. Thus the callback function is able to extract and manipulate all passed parameters.
friTap takes advantage of this and extracts from the parameters the second pointer of the read function, which points to the buffer that holds the received, unencrypted data. The implementation is here as an example (using OpenSSL) for the other implementations and it looks like this:


```javascript
Interceptor.attach(addresses["SSL_read"],
    {
        onEnter: function (args: any) {
            var message = getPortsAndAddresses(SSL_get_fd(args[0]) as number, true, addresses)
            message["ssl_session_id"] = getSslSessionId(args[0])
            message["function"] = "SSL_read"
            this.message = message
            this.buf = args[1]
        }
        ...
    })
```

The pointer to the buffer is in the paramter array named `args`, strictly speaking in the second position (it is the second function parameter). This is now saved in the execution context using `this.buf = args[1]`, since the buffer will only be filled with the received data after the read function has been executed.

The hook of the function end has exactly one parameter, the return value of the function. In the case of the read function, this is the number of bytes received, which is important for reading the buffer. The hook for the end of the function looks like the following, again demonstrated with OpenSSL as an example:


```javascript
Interceptor.attach(addresses["SSL_read"],
    {
       ...
        onLeave: function (retval: any) {
            retval |= 0 // Cast retval to 32-bit integer.
            if (retval <= 0) {
                return
            }
            const buffer_content = this.buf.readByteArray(retval)
            this.message["contentType"] = "datalog"
            send(this.message, buffer_content)
        }
    })
```

`retval` is the return value of the read function, i.e. the number of bytes received. The previously saved pointer to the buffer can now be read with `readByteArray()`. By the return value of the read function friTap knows exactly how many bytes have to be read from the buffer. The extracted bytes are then stored in a dictionary object, which in addition to the data also contains information such as port numbers, sender and receiver addresses, etc. . This is then sent via `send()` from the target process to the main script ([python script](https://github.com/fkie-cad/friTap/blob/9ba62ad1aecffb3baed812690b74efe99d970d22/friTap.py)), which then processes this information.


### Hooking the write function

As with the read functions, the write functions have the same function signature for all libraries supported by friTap:


```javascript
int write (void*, void*, int)
```

The first parameter is a pointer to an SSL object that holds all information about the SSL session being used in the background. This object is used to identify the SSL/TLS stream over which data is sent.
The second parameter is a pointer to a buffer that holds the data to be transmitted, in unencrypted form.
The third parameter specifies how many bytes from the referenced buffer should be sent over the associated SSL/TLS stream.

Unlike the read function, all information necessary for friTap is already available before function execution. The implementation is again exemplified with the implementation of OpenSSL:


```javascript
Interceptor.attach(addresses["SSL_write"],
    {
        onEnter: function (args: any) {
            var message = getPortsAndAddresses(SSL_get_fd(args[0]) as number, false, addresses)
            message["ssl_session_id"] = getSslSessionId(args[0])
            message["function"] = "SSL_write"
            message["contentType"] = "datalog"
            const bytesToBeSent = args[1].readByteArray(parseInt(args[2]))
            send(message, bytesToBeSent)
        }
})
```

`args[1]` is the pointer to the buffer, `args[2]` the number of bytes to send. With `readByteArray()` the bytes to send can be copied from the buffer. The extracted bytes are then stored in a dictionary object, which contains besides the data also information like port numbers, sender and receiver address etc.. This is then sent via `send()` from the target process to the main script (Python script), which then processes this information.

### Key extraction

In addition to hooking the read and write functions, friTap also provides the ability to export all keys created/received during the handshake. These keys can then be used to decrypt encrypted TLS traffic. Wirehsark provides the ability to specify a keylog file that friTap created when the client connected to the server.
The implementation of this functionality varies widely. This is due to the default behavior of the individual libraries, especially depending on the operating system.

Again, we would like to show an example, based on the implementation of OpenSSL on linux:

```javascript
const SSL_CTX_set_keylog_callback = ObjC.available ? new NativeFunction(addresses["SSL_CTX_set_info_callback"], "void", ["pointer", "pointer"]) : new NativeFunction(addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"])

const keylog_callback = new NativeCallback(function (ctxPtr, linePtr: NativePointer) {
    var message: { [key: string]: string | number | null } = {}
    message["contentType"] = "keylog"
    message["keylog"] = linePtr.readCString()
    send(message)
}, "void", ["pointer", "pointer"])
```

If OpenSSL is selected as a dynamically loaded library, many functions are exported by default. Fortunately, the function `SSL_CTX_set_keylog_callback` (linux desktop) is also exported. This function gives the user the ability to define a callback function that will be called whenever new key material is generated or received. This function is passed two parameters when it is called: An SSL object associated with the connection and the newly generated or received key material in the form of a string. FRIDA allows you to define your own callback functions, which we did for this use case. friTap creates a new callback function that reads the passed string and stores it in a dictionary object, which is sent to the main script (python script) and processed by it (log or write out).

In order to register the own callback, the function `SSL_CTX_set_keylog_callback` must be called once, before the handshake, with the callback function as parameter. friTap hooks the `SSL_new` method for this. This function is called before the handshake, but also after the SSL context has been created, i.e. the binding options have already been set so that the callback function can receive the key material of the subsequent handshake.





For each operating system, friTap knows the usual library/module and the function that is ultimately responsible for loading the new library. When a new library is loaded into program memory, the name of the new module is checked to see if it matches any of the SSL/TLS library names. If this is the case, the usual read, write and key export functions are hooked.



## Special Thanks

We like to thank our college Max J. Ufer for his initial work in creating friTap. Further we like to thank Martin Lambertz and Jan-Niclas Hilgert for their feedback while working on friTap. Finally we have to thank Ole André Vadla Ravnås for his tireless efforts in the development of FRIDA. 

## Getting started

friTap can be downloaded here: [https://github.com/fkie-cad/friTap](https://github.com/fkie-cad/friTap)

