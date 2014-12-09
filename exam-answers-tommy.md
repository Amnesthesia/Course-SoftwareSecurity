Merged exams from past years
-----------------------------

### Design principles
1. Explain the principle of least privilege. What is the intention of this design principle?
	* **Answer**: With the principle of least privilege you will only grant the lowest needed privilege to a person or system which does not affect their job/work flow. For instance, a regular user on a linux computer, does not need root privileges. Basically the intention of this principle is to minimize the risk of a system compromize due to too high access level/privileges.
2. Choose two more of Saltzer's and Shroeder's design principles and explain them. Use an example if you'd like
	* **Answer**: Economy of mechanism: Keep the design as simple and easy to understand as possible. KISS (Keep It Simple Stupid). The principle of Open Design: Security through obscurity does not work, so there is no point in hiding you source code. Keys and password are one thing, men the main source code does not need to be kept a secret. Users should be able to inspect the source code, compile it them self, and decide wether this application is what they need. Secrecy != Security.
3. Explain the principle of complete mediation. What is the intention of this design principle and what do you need to be aware of when implementing access checks?
	* **Answer**: Every access to every object must be checked. Basically check everything, twice, and then some.
4. Explain the principle of fail-safe defaults. What is the intention of this design principle and what do you need to be aware of when implementing access checks?
	* **Answer**: Base access decisions on permission rather than exclusion. A bad example is blacklist ACL. A good example is a whitelist ACL. For example, the defaults in a firewall are configured to deny everything by-default. Only specific packets, based on rules by the administrator, are allowed to enter the network. This is a good example on a failsafe-default.

---------------------------

### Secure Agile Software Development Process (guest lecture)
5. Agile BSSD introduces 3 additional roles to Scrum. What are these roles and what is their purpose?
	* **Answer**: Team Security Champion -> This is the person responsible for tracking and coordinating security and privacy issuis in the dev. team. This responsibility is usually assigned to one of the team members (no prior knowledge necessary). 
	Security Advisors -> This is personall from a third party, helping the dev. team with expert knowledge of security concerns.
	Development Security Manager -> This person is respnsible for the implementation of security and privacy in the dev. team.
6. Agile BSSD emphasises threat analysis as an important tool to understand the security risk. How is threat analysis used in BSSD?
	* **Answer**: A threat analysis within the BSSD is basically a story registered in the sprint backlog. By doing this, the dev. team can look at the threat analysis/perform a threat analysis at the end of each sprint. This will obviously help detecting threats early on, and in the long run make sure the software is secure.

---------------------------


### Trusted path & UI security
7. What is a trusted path according to TCSEC?
	* **Answer**: Trusted Path is a mechanism in which a user can communicate securely and directly with the TCB (Trusted Computing Base).
8. How does the UAC User Account Control feature on Windows make use of a trusted path and why?
	* **Answer**: The UAC dialog will pop-up when a users is trying to run something with admin privileges, make changes to the system, or anything else that potentially may harm the computer. When the UAC dialog pops up, other programs/malware can't accept/click yes on the dialog on behalf of the user, since the UAC switches to a separate desktop.
9. What is the difference between a window station and a desktop?
	* **Answer**: The desktop contains a clipboard, atom table an one or more desktop objects. A desktop contains the UI objects; windows, menus, hooks.
10. Microsoft Windows uses sessions and window stations to isolate processes and desktops to protect UI access. Have a look at the diagram. Why is session 0 special?
	* **Answer**: Session 0 contains all system processes and are isolated from the user session. Users live in session 1, 2, 3 ... n. 
11. Winlogon is the desktop for the logon process, Disconnect is the desktop for screensaver and Default is the desktop created for the user's shell upon logon. How is malware running in the Default desktop prevented from interacting with the user when the Winlogon desktop is active and receives input?
	* **Answer**: There can only be one active desktop at a time. And messages can only be sent between threads on the same desktop.
12. How is the sending of Window messages regulated between threads on the same desktop, between threads attached to different desktops? What is the effect of UIPI User Interface Privilege Isolation?
	* **Answer**: Sending between threads on the same desktop is allowed. Between different desktops is not allowed. By using UIPI, processes with a lower integrity level is prevented from sending messages to processes with a higher integrity level. Basically this helps prevent privilege escalation attacks (shatter attack).

![Windows services](services.png)

---------------------------


### Code & design reviews
13. What is the purpose of a review and how does it differ from software testing?
	* **Answer**:
14. What strategies do you know to reduce the amount of information processed during a review?
	* **Answer**:
15. What can static analysis tools detect? What do they overlook?
	* **Answer**: They detect possible vulns in the source code, by just searching for common issues. Buffer overflows, off-by-one-errors, integer overflows/underflows, uninitilized variables etc. They do not discover insecure use of crypto, access control issues, authentication problemes.

---------------------------


### Concurrency
16. What is a race condition?
	* **Answer**:
17. Why are file race conditions a bigger problem in Unix software than in Windows software?
	* **Answer**: In Linux you have the functions access() and open(). access() checks if a user has access to a file, and open() opens the file. In Windows we don't have functions that behave exactly the same way as access() and open(), since file opening in Windows, by design, is made to be really secure.
18. Which trend in computing architectures makes programs more susceptible to race conditions, i.e increases parallel execution relating to shared resources
	* **Answer**: Multi-threaded programming? Multi-core programming? Stupid question...

---------------------------


### String representation
19. Describe how memory is used in different approaches to string representation pointer+null byte (e.g C) vs pointer+length (e.g Pascal). Use two sketches to show how the string "abcd" is stored in memory
	* **Answer**: In C strings are terminated by the null byte. Ex: T O M M Y \0
	In Pascal we don't have the concept of null bytes when talking about strings. Instead we use a length-prefixed approach. Ex: 5 T O M M Y
20. What precautions need to be applied to string handling when using C++?
	* **Answer**: Dont write past the boundary of the buffer you're writing to. Make sure you use safe functions when dealing with strings and characters....?

21. Consider a type-safe language like Java or C#. Will that prevent you from (accidentally) writing to memory past the boundary of a string? If so, why? If not, why not? Use an example if you like
	* **Answer**: Yes, this will prevent you from accidentally writing to memory past the boundary of a string. This security mechanism is a part of the type safe languages Java or C#. If you try to write past the boundary of a string in either of these languages, the application will terminate with an exception/error message telling you you fucked up.

---------------------------


### Code signing
22. What is the added value of an Extended Validation code signing certificate?
	* **Answer**: The EV Code Signing offers a more secure process of signing code and allows for greater confidence in the integrity of an application.
23. How can signed code help users in investigating security incidents?
	* **Answer**:
24. How can signed code help to protect software vendors from liability claims?
	* **Answer**:

---------------------------


### Code inspection and analysis tools
25.	What is the purpose of an inspection and how does it differ from software testing?
	* **Answer**:
26. What strategies do you know how to approach an inspection? What tools support these strategies?
	* **Answer**:
27. What is a static analysis and how can it be used to improve software security?
	

---------------------------


### Maintenance
28. What is a patch and why are patches used in software maintenance?
	* **Answer**: A patch is basically a way for the manufacturer to "update" the application, fix problems, add new features etc. 
29. Can a patch increase vulnerability of an application? Why? Why not?
	* **Answer**: Yes, a patch may increase vulnerability of an application. First of all, a patch may introduce new vulns. Second, if a patch to fix a vuln is issued by the vendors, the bad guys knows that a vuln. exist, and will be on high-alert, and try to find this vuln.
30. How do the following three approaches to distribution of corrected software versions differ: Locally maintained installation, app store, externally hosted application? Discuss periods of vulnerability, single point of failure, backup and compatibility with dependent applications.
	* **Answer**: Locally maintained: You are responsible for the application. Maybe you have to compile the program from source, apply patches manually etc. Since you're in charge, you can make sure there's no single point of fauilure, you can go through the code, find vulns and patch them, and you can also take care of backups and compatibility yourself.
	App Store: You download the application and it's installed on your device. If the vendors find a vuln/issue, the will update the application and push the changes to the repo/store. When this happen you can just download the updated application and everything is up-and-running. You may have control of backup with this approach, but it does not necessarily introduce a single point of failure, since an app store usually is distrubuted among several servers. Patching/vulns. is up to the author of the app to fix.
	Externally hosted: You have no control of the application. Someone else is applying patches, and someone else makes sure the application is up-and-running. This may introduce a single point of failure, since you have no control of the servers hosting the application. If the service goes down, you no longer have access to the application. You also have no control on how long it takes for a vulnerable application to be patched.

---------------------------


### Buffer Overflows
31. Explain a buffer overflow attack using the figure. Describe the elements of the figure and present a situation where a buffer overflow occurs, how it functions and what its effects can be. If you want to use sample code to explain, please do so. If you can do it without using sample code, that is also fine.
	* **Answer**: EBP (Extended Base Pointer): points to the start of the current stack frame.
	EIP (Extended Instruction Pointer): Points to the next instruction the CPU shold perform.
	Stack base starts at a higher memory address and grows towards a lower memory address.
	Explanation of the figure: When the application is first started libc etc. is stored on the stack, and in turn call the main function (_libc_start_main()). Then every argument is stored to the stack (global variables, and main's variables).
	Whenever a new function is run, a new stack frame is created, arguments are stored in this stack frame (locally variables) and eventually the function is executed.
	Buffer overflow: If a BO occurs you can potentially overwrite the intruction pointer of the stack and redirect the flow of the program. If you have managed to put a shellcode onto the stack, you can redirect the program to that code, and potentially get shell access on a computer.
32. Which property of current memory architecture allows a buffer overflow to overwrite code during execution of a program?
	* **Answer**: What? That every application has it own stack? That the hardware does not check to see if "your stack" is being overwritten? That the hardware does not enfore strict boundaries when writing to a buffer? Bah, fuck off with this question
33. Choose a method to protect a program against buffer overflows and explain how it works, why it's a good choice and what its limits are
	* **Answer**: Address Space Layout Randomization: is a way of randomizing memory locations whenever a program runs. ALSR works by randomly offsetting memory addresses. So every time you run your application, the variables, functions etc. gets a new, random memory address.
	ALSR makes writing exploit code much harder since memory addresses is random every time. So the exploit code becomes more or less non-functional. It's however not 100% safe...
	Today there exists several methods to bypass ASLR. NOP Spray is one of them. If you can fill the stack with enough NOPs you increase the chances of getting the shellcode to run. If you can manage to JMP somewhere within this NOP Spray you can basically just slide down(up?) the stack (NOP Sled) and eventually hit the shellcode. Boom! Shell, motherfucker.

![Buffer overflows](memory.png)

