---
title: "Adversary Emulation is a Complicated Profession - Intelligent Cyber Adversary Emulation with the Bounty Hunter"
date: 2024-09-12T10:00:00+02:00
author: "Louis Hackländer-Jansen"
authorTwitter: "L015H4CK" #do not include @
image: "/2024/09/bountyhunter_logo_v1_title.png"
tags: ["Adversary Emulation", "Caldera", "Cybersecurity"]
keywords: ["Adversary Emulation", "Caldera"]
description: "This blog post introduces the Bounty Hunter - a novel Caldera plugin for intelligent cyber adversary emulation. Its main contribution is the emulation of complete, realistic cyber attack chains. The Plugin is avaible on [**GitHub**](https://github.com/fkie-cad/bountyhunter)."
showFullContent: false
draft: false
---

## Cyber Adversary Emulation
Cyber adversary emulation is an assessment method where tactis, techniques, and procedures (TTPs) of real-world attackers are used to test the security controls of a system.
It helps to understand how an attacker might penetrate defenses, to evaluate installed security mechanisms and to improve the security posture by addressing identified weaknesses.
Furthermore, it allows running training scenarios for security professionals, e.g., in cyber ranges where practical exercises can be performed.
Unfortunately, adversary emulation requires significant time, effort, and specialized professionals to conduct.

![](/2024/09/bountyhunter_wernerherzog.png)

## Cyber Adversary Emulation Tools
In order to reduce the costs and increase the effectiveness of security assessments, adversary emulation tools can be used to automate the emulation of real-world attackers.
Also, such tools include built-in logging and reporting features that simplify documenting the assessment.
Thus, assessments become more accessible for less experienced personnel and more resource-efficient when using adversary emulation tools.
But the automation process also has drawbacks, e.g., they often depend on predefined playbooks resulting in limited scenario coverage, a lack of adaptability, and a high predictability.
As a consequence, simulated attacks fail more often and trainee personnel might recognize an attacker from previous scenarios, resulting in a lower quality in training experience.

### Introducing Caldera and its Decision Engine
[Caldera](https://github.com/mitre/caldera) is an open-source, plugin-based cybersecurity platform developed by MITRE that can be used to emulate cyber adversaries.
It does not depend on playbooks as strongly as other adversary emulation tools do - instead it uses adversary profiles and planners.
While adversary profiles contain attacks steps to execute, the planners are unique decision logics that decide if, when, and how a step should be executed.
Even though Caldera comes with several planners out-of-the-box, it still has some limitations: (1) Repeating a scenario results in the same behavior since the planners make deterministic decisions, (2) only post-compromise methods are supported, and (3) simulated attack behavior can be unrealistic due to planner limitations.
To overcome these limitations, we developed and implemented a new plugin for Caldera - the Bounty Hunter.

## The Bounty Hunter
[The Bounty Hunter](https://github.com/fkie-cad/bountyhunter) is a novel plugin for Caldera.
Its biggest asset is the Bounty Hunter Planner that allows the emulation of complete, realistic cyberattack chains.
Bounty Hunter's key features are:
- **Weighted-Random Attack Behavior.** The Bounty Hunter's attack behavior is goal-oriented and reward-driven, similar to Caldera's Look-Ahead Planner. But instead of picking the ability with the highest future reward value every time, it offers the possibility to pick the next ability weighted-randomly. This adds an uncertainty to the planner's behavior which allows repeated runs of the same operation with different results. This is especially useful in training environments.
- **Support for Initial Access and Privilege Escalation.** At the moment, no Caldera planner offers support for initial access or privilege escalation methods. The Bounty Hunter extends Caldera's capabilities by offering support for both in a fully autonomous manner. This enables it to emulate complete cyberattack chains.
- **Further Configurations for More Sophisticated and Realistic Attack Behavior.** The Bounty Hunter offers various configuration parameters, e.g., "locking" abilities, reward updates, and final abilities, to customize the emulated attack behavior.

The following two sections introduce two example scenarios to showcase the capabilities of the Bounty Hunter.
The first example describes how it emulates complete cyberattack chains, including initial access and privilege escalation.
In the second scenario, the Bounty Hunter is tasked to emulate a multistep attack based on an [APT29 campaign](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29) to demonstrate the level of complexity that it can achieve.

### Scenario #1 - Initial Access and Privilege Escalation
This example scenario demonstrates how the Bounty Hunter is able to perform initial access and privilege escalation autonomously.
The results of the demo operation using the Bounty Hunter and a demo adversary profile are shown in the picture below.
The operation is started with a Caldera agent (`yjjtqs`) running on the same machine as the Caldera server, i.e., a machine that is already controlled by the adversary.

As first step, the Bounty Hunter executes a Nmap host scan to find potential targets, followed by a Nmap port scan of found systems to gather information about them.
Depending on the gathered port as well as service and version information, an initial access agenda is chosen and executed.
In this scenario, the emulated adversary found an open SSH port and decides to try an SSH brute force attack.
It successfully gathers valid SSH credentials and uses them to copy and start a new Caldera agent on the target machine (`ycchap`).
Next, the Bounty Hunter detects that it needs elevated privileges for its chosen final ability (`Credential Dumping`) and decides to start a privilege escalation by running a UAC Bypass.
As a result of this step, a new elevated agent was started (`ebdwxy`) and the final ability can be executed, concluding the operation.

|                                                                               ![](/2024/09/bountyhunter_scenario1.png)                                                                                |
|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| *Example operation to demonstrate Initial Access and Privilege Escalation with the Bounty Hunter and a demo adversary profile. Note how three different agents are used during the different phases.* |


### Scenairo #2 - Emulating an APT29 Campaign
The level of complexity the Bounty Hunter supports was tested using the APT29 Day2 data from the [adversary emulation library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/) of the Center for Threat Informed Defense.
The resulting attack chain including fact-links between steps is shown in the figure below.
The test showed that the Bounty Hunter is able to initially access a Windows Workstation using SSH brute force, elevate its privileges automatically using a Windows UAC Bypass, and finally compromise the whole domain using a Kerberos Golden Ticket Attack.

To achieve its goal, the Bounty Hunter was only provided with a high reward of the final ability that executes a command using the Golden Ticket and the name of the interface to scan initially.
All other information needed for the successful execution, including the domain name, domain admin credentials, SID values, and NTLM hahses, were collected autonomously.

|                                                                                              ![](/2024/09/bountyhunter_scenario2.png)                                                                                               |
|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| *Example operation to demonstrate the level of complexity the Bounty Hunter supports based on an APT29 campaign. During the campaign, a Windows Active Directory Domain is compromised by running a Kerberos Golden Ticket Attack.* |

### Configuration of the Bounty Hunter
The Bounty Hunter can be configured in various ways to further customize the emulated attack behavior.
Possible configurations range from custom ability rewards, over final and locked abilities to custom ability reward updates.
For detailed information on the configuration possibilities, please refer to the [description in the GitHub repository](https://github.com/fkie-cad/bountyhunter?tab=readme-ov-file#advanced-information-and-configuration).

## Conclusion
Cyber adversary emulation is complicated and different approaches suffer from different drawbacks.
Common challenges of cyber adversary emulation tools (such as the well-known cybersecurity platform Caldera) are their predictability and limitations in their scope.
To overcome these challenges, we developed and implemented a new Caldera plugin - the Bounty Hunter.
The capabilities of the Bounty Hunter were demonstrated in two different scenarios, showing that it is capable of emulating initial access and privilege escalation methods as well as handling complex, multistep cyberattack chains, e.g., an attack based on an APT29 campaign.

The Bounty Hunter is [released open-source on GitHub](https://github.com/fkie-cad/bountyhunter) with (deliberately unsophisticated) proof-of-concept attacks for Windows and Linux targets.
