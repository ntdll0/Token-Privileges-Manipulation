# Token Privileges Manipulation
Implementation of process sandboxing in c++, elevates to SYSTEM via impersonation, if required and strips all privileges from process of your will.

Command Line parameters:<br>
\<pid\> - Represents process id you wanna strip privileges from.

Can be used to remove privileges from any kind of process, including AntiVirus service processes, making them unable to detect threats.<br>

Example of stripping privileges from powershell running under NTAUTHORITY\SYSTEM with highest possible privileges.<br>
![xVvv592Te0](https://github.com/ntdll0/Token-Privileges-Manipulation/assets/164230949/1456c8ea-a081-4fea-9385-173a37f4a495)<br><br>
> Usage strictly for adacemic & ethical purposes, developer shall not take any responsibility of possible damages caused by improper or unethical usage.
> Known vulnerable software tested: Windows Defender, Malwarebytes
