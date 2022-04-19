+++
title = "Installing new .NET versions on a Windows 7 VM"
date = "2022-03-16T12:01:43+01:00"
author = "Manuel Blatt"
authorTwitter = "" #do not include @
cover = ""
tags = ["Win7", ".NET", "dynamic analysis"]
keywords = ["", ""]
description = ""
showFullContent = false
readingTime = false
+++

# Installing new .NET versions on a Windows 7 VM

In this post, I will explain how to install .NET Framework 4.8 on a Windows 7 VM.

## Motivation
Virtual Machines running Microsoft Windows are frequently used for dynamic analysis of Windows executables.
Windows 7 is still used for analysis VM, although it is no longer supported by Microsoft and ships with an outdated .NET version.
If a sample requires a .NET version which is not present on the analysis VM, the execution fails and the file cannot be analysed.
For this reason it might be required to install a recent .NET version on a Windows 7 VM.


## Problem
The .NET Framework 4.8 installer tries to verify the integritiy of the installation data prior to the installation.
However, the root certificates required for this verification process are not present on Windows 7.
![Problem: the installation process fails](/2022/03/net_0.png)
This issue cannot be fixed via Windows updates, as they are not available for Windows 7 anymore.

## Solution
First, download the [offline installer for .NET Framework 4.8](https://go.microsoft.com/fwlink/?linkid=2088631)

Execute the file. This will extract the installation data into a temporary subfolder of `C:\` with a random name.
![Extraction of the installation data into a temporary directory](/2022/03/net_1.png)

Wait until the extraction process has finished and an installer opens. You don't have to interact with this installer window at all. Just leave it opened to prevent the deletion of the temporary subfolder. 
![Installer to be left opened](/2022/03/net_2.png)

Next, navigate to the temporary folder and execute the file `netfx_Full_x64.msi` or `netfx_Full_x86.msi`.
This will trigger the installation of .NET Framework 4.8. Restart the system after the installation finished.
![Locating netfx_Full](/2022/03/net_3.png)

That's it, you're all set! :)
