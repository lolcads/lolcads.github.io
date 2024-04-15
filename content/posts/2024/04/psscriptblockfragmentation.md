+++
title = "*PowerView* is evil, but *PowerVi* and *ew* are legit, right? - Missing signature-based detections due to PowerShell Script Block Logging Fragmentation"
date = "2024-04-15T11:01:40+02:00"
author = "Louis Hackländer-Jansen"
authorTwitter = "L015H4CK" #do not include @
cover = ""
tags = ["SIEM", "ThreatDetection", "Sigma", "PowerShell", "ScriptBlockLogging", "Forensics"]
keywords = ["", ""]
description = "[Sigma](https://github.com/SigmaHQ/sigma) offers more than 3000 rules for signature-based threat detection. 140 of these rules aim to detect suspicious/malicious PowerShell scripts by looking into PowerShell script block logs. Fragmentation of script blocks during Script Block Logging results in varying number of alerts when loading the same script multiple times. On the one hand, there is a trend of more alerts being generated when the script is split into more fragments (which is fine), but on the other hand, the fragmentation of scripts into blocks may result in missed detections. "
showFullContent = false
readingTime = true
+++

# *PowerView* is evil, but *PowerVi* and *ew* are legit, right? - Missing signature-based detections due to PowerShell Script Block Logging Fragmentation

**TL;DR:** Sigma rules and similar signature-based threat detection measures may miss malicious PowerShell scripts due to unpredictable fragmentation of script block logs.

## Introduction
[Sigma](https://github.com/SigmaHQ/sigma) offers more than 3000 rules for signature-based threat detection. 140 of these rules aim to detect suspicious/malicious PowerShell scripts by looking into PowerShell script block logs. Fragmentation of script blocks during Script Block Logging results in varying number of alerts when loading the same script multiple times. On the one hand, there is a trend of more alerts being generated when the script is split into more fragments (which is fine), but on the other hand, the fragmentation of scripts into blocks may result in missed detections. 

I know this is a lot, but bear with me as I tell you the whole story. If you are only interested in the juicy part, you can skip to 'The case of split "PowerVi/ew"'.

## The Uncertainty of Script Block Logging
[It is known](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/) that when loading a very large script, PowerShell breaks it into multiple parts before logging them - sometimes resulting in dozens of fragments. To illustrate this behavior, we loaded the well-known [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) script a total of 10 times (on the same machine and configuration) and recorded into how many block fragments it was broken. The results are shown in the table below.

| Run      | 1   | 2   | 3   | 4   | 5   | 6   | 7   | 8   | 9   | 10  |
| -------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| # Blocks | 54  | 76  | 57  | 49  | 64  | 57  | 55  | 69  | 39  | 47  |

We can see that the number of blocks ranges from 39 to 76, which is quite a significant difference.

## More script blocks -> More alerts?
Now, when using Sigma rules that operate on single logged ScriptBlockTexts, the number of generated alerts might differ because the number of logged blocks differs. More specific, the number of generated alerts usually increases with increasing number of blocks, because the malicious/suspicious strings were found in more blocks. Using "all rules" from Sigma release [r2024-03-11](https://github.com/SigmaHQ/sigma/releases/tag/r2024-03-11) and the 10 recorded PowerView loadings, the following number of alerts were generated using [Chainsaw](https://github.com/WithSecureLabs/chainsaw) (sorted by number of blocks).

| Blocks                   | 39  | 47  | 49  | 54  | 55  | 57  | 57  | 64  | 69  | 76  |
| ------------------------ | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Alarms                   | 79  | 91  | 94  | 103 | 99  | 106 | 107 | 110 | 119 | 126 |
| ... raised on ... blocks | 39  | 46  | 48  | 53  | 53  | 56  | 56  | 60  | 65  | 70  |

Here, we see that the number of alarms usually increases with the number of blocks - that is the expected behavior. The only run that does not match this trend is the one that generated 55 script blocks. Here, less alerts are generated than in the run generating 54 script blocks. Although this behavior leads to inconsistency, it can be considered "not too bad" since in some cases more alerts are generated than in other cases, but overall we still catch everything, right?

## More script blocks -> Less alerts??
To investigate how the number of blocks influences the number of generated alerts, we further looked into the generated alarms. Below, the number of generated alerts for each triggered rule is listed for each of the 10 runs.

| Rule / Run#Blocks                                                    | 9#39  | 10#47 | 4#49 | 1#54  | 7#55 | 3#57 | 6#57  | 5#64 | 8#69                                   | 2#76 | AVG   |
|----------------------------------------------------------------------|-------|-------|------|-------|------|------|-------|------|----------------------------------------|------|-------|
| Total                                                                | 79    | 91    | 94   | 103   | 99   | 106  | 107   | 110  | 119                                    | 126  | 103.4 |
| Execute Invoke-command on Remote Host                                | 5     | 6     | 6    | 6     | 6    | 7    | 6 [2] | 7    | 7                                      | 7    | 6.3   |
| Malicious PowerShell Commandlets - ScriptBlock                       | 35    | 42    | 43   | 49    | 46   | 51   | 51    | 53   | 58                                     | 61   | 48.9  |
| Malicious PowerShell Keywords                                        | 3     | 2     | 2    | 2     | 2    | 2    | 3     | 2    | 3                                      | 2    | 2.3   |
| Manipulation of User Computer or Group Security Principals Across AD | 4     | 4     | 4    | 6 [3] | 4    | 4    | 4     | 4    | 4                                      | <5>  | 4.3   |
| Potential In-Memory Execution Using Reflection.Assembly              | 1     | 1     | 1    | 1     | 1    | 1    | 1     | 1    | 1                                      | 1    | 1     |
| Potential Suspicious PowerShell Keywords                             | 1 [1] | 2     | 2    | 2     | 2    | 2    | 2     | 2    | 2                                      | 2    | 1.9   |
| PowerView PowerShell Cmdlets - ScriptBlock                           | 27    | 30    | 32   | 34    | 35   | 35   | 36    | 38   | 40                                     | 45   | 35.2  |
| Request A Single Ticket via PowerShell                               | 1     | 1     | 1    | 1     | 1    | 1    | 1     | 1    | <2> +1 because of script block cut-off | 1    | 1.1   |
| Usage Of Web Request Commands And Cmdlets - ScriptBlock              | 1     | 1     | 1    | 1     | 1    | 1    | 1     | 1    | 1                                      | 1    | 1     |

First, let's look at some results that were expected.

\[1] Potential Suspicious PowerShell Keywords: When having only 39 script block fragments, only 1 alarm is generated because all the "suspicious" strings fitted into the first block - because it is larger compared to the other cases.

\[2] Execute Invoke-command on Remote Host: Goes from 5 to 7 raised alerts - increasing with the number of blocks because the search strings are found in more blocks. Only run 6 with 57 blocks is an outlier, producing less alerts than run 3 with the *same amount* of 57 blocks. This is getting suspicious..

\[3] Manipulation of User Computer or Group Security Principals Across AD: In all but two runs exactly 4 alarms are generated. The run that raised 5 alarms was the one with the largest number of blocks - so this behavior is expected - but the one with the most alarms (6) only created 54 blocks. Further investigation showed that this is the result of the "random" script fragmentation, where all 6 "suspicious" strings were found in 6 different blocks, where in the other runs multiple strings where found in a single block resulting in less alerts.

Okay, so these results are kind of expected and not too bad. So we should be fine, right?

Well, when investigating the results of the rule [Malicious PowerShell Commandlets - ScriptBlock](https://github.com/SigmaHQ/sigma/blob/4319f5807ff4eb8035ecf1a8f86ab3bdc1ab8960/rules/windows/powershell/powershell_script/posh_ps_malicious_commandlets.yml), a case came true that we thought was extremely unlikely.

## The case of split "*PowerVi/ew*"
Among others, the rule [Malicious PowerShell Commandlets - ScriptBlock](https://github.com/SigmaHQ/sigma/blob/4319f5807ff4eb8035ecf1a8f86ab3bdc1ab8960/rules/windows/powershell/powershell_script/posh_ps_malicious_commandlets.yml), detects the string "PowerView" inside script blocks. Now, comparing two different runs, run3 with 57 blocks generated 51 alerts and run2 with 76 blocks generated 61 alerts for this rule. So more blocks -> more alerts, this is fine. But, looking deeper into the script blocks and generated alerts, we noticed something at the end of script block 38 of 57 of run 3.

```
Add-Member Noteproperty 'Comment' $Info.lgrpi1_comment\n
$LocalGroup.PSObject.TypeNames.Insert(0, 'PowerVi
```
___
And the beginning of script block 39 of 57:

```
ew.LocalGroup.API')\n
```

So, in this case the PowerView script was fragmented in such a way, that a string that should have been detected was no longer detected, i.e., "PowerView" was split into "PowerVi" and "ew". (To be fair, script block 38 still raised an alarm because the string "PowerView" occures in it multiple times, but still this example illustrates the problem at hand.)

## Losing alerts
This shows, that depending on the fragmentation of script blocks, we can indeed lose alerts and miss contents of scripts that should be detected, e.g., by strings split into two parts in two different blocks. But there are other cases: Rules like [Execute Invoke-command on Remote Host](https://github.com/SigmaHQ/sigma/blob/49adcf9a00247ed6c3daacba03b589470f6716d0/rules/windows/powershell/powershell_script/posh_ps_invoke_command_remote.yml) detect multiple strings in a single script block (`ScriptBlockText|contains|all`). Now, when one of those strings is randomly put into a different block, the rule no longer triggers. Although this case should be more likely than the case of "search strings split in two", the 10 simulations did not result in such a case since the number of alerts for this specific rule is much smaller (only 5-7 alarms compared to 35-61 for "Malicious PowerShell Commandlets - ScriptBlock").

## Conclusion
We learned that loading the PowerView script multiple times results in fragmentations of it ranging from 39 to 76 blocks. The alerts raised on these script blocks showed the trend of increasing number of alerts with increasing number of script blocks. Although this behavior adds uncertainty to the generation of alerts, it is of no critical nature. But, another example showed, that the fragmentation of scripts into blocks might result in suspicious/malicious strings being split into two blocks, resulting in a case where the search strings could not be found and the detection is completely missed. Furthermore, when searching for multiple strings in a single block, the fragmentation of scripts might result in these strings being split into two different blocks - where detection is also no longer possible.

**Is there a remedy?** Maybe re-combining script fragments ([like this](https://news.sophos.com/en-us/2022/03/29/reconstructing-powershell-scripts-from-multiple-windows-event-logs/)) to run detection mechanisms on the reconstructed scripts?

**Sidenote:** To add, this behavior might also be leveraged by malicious actors to avoid detection...

The described findings were observed on a Windows 10 host with PowerShell Version 5.1 and PowerShell logging configurations according to the [recommendations by the Australian Cyber Security Centre (ACSC)](https://www.cyber.gov.au/sites/default/files/2023-03/PROTECT%20-%20Windows%20Event%20Logging%20and%20Forwarding%20(October%202021).pdf) which include PowerShell Module and PowerShell Script Block Logging.
