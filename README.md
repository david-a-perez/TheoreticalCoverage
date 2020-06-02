# Theoretical Coverage
This theoretical coverage mechanism was theorized by @gamozolabs. This system presented many edge cases, and I wanted to find them all before it’s implemented into Chocolate Milk (his hypervisor project).

# The Coverage Idea
The idea is to split pages into two main groups: execute-only pages filled with breakpoints (0xCC), and read-write pages filled with actual data. When execution hits a breakpoint, the bytes at the instruction pointer are replaced with the actual data, and execution is resumed. If the program tries to read or write to a page that is execute-only, the real data is copied in and the permission changes to read-write. If the program tries to execute a page that is execute-only, then the real data is hidden from the program and the program is given access to a page full of breakpoints.

For more details see his stream, 

# The Edge-Case Finder
As working in a hypervisor may not give as much visibility as a debugger, I wanted to first prove if this system is possible by using GDB. This GDB-based system will be much slower than a hypervisor-based system that this is intended for. In addition, it will likely not support resetting the program with different input to gain more coverage, and thus would have no purpose in fuzzing.

# Concerns with the original idea (Hypervisor)
One major concern that I have had is if an instruction in a page attempts to read or write to that same page. I would assume that such an instruction would fail to run even if the permissions were switched back and forth. I have been working on a way to safely implement RWX pages (See Section RWX). 

# Issues that restrict the GDB approach
Without a hypervisor, the only way to get true execute-only pages (no read) on x86 is to use Memory Protection Keys. Unfortunately, this feature is only available on Xeon "Skylake" Processors. To run this program I have been using c5.large instances from AWS. (I don't know why, but the Azure compute instances do not appear to support pkeys).
Another issue is that my mprotect permission modifications are visible to the program.
In summary, this GDB approach will fail if the program changes mprotect permissions or uses pkeys.
I'm considering hooking the mprotect call so that if the program calls it, it doesn't actually change the permissions.

# Edge Cases found so far
- I found the following situation, page 0x1000 is executable, page 0x2000 is read-write, code at offset 0x1fff shows 0xCC but is actually the beginning of a 2-byte instruction. The breakpoint hits. The remove_breakpoint function is called. Byte 0x1fff is replaced with the original instruction. The next page is not affected as there are no 0xCC bytes to remove. Execution continues. The instruction now occupies both pages and so a SIGSEGV is caused by the second page not being executable. The second page becomes execute-only. 0x1000 now contains 0xCC. Execution resumes, but the second-half of the instruction is now 0xCC. This edge case is quite easy to solve.

# RWX pages
The issue with having RWX pages is that as the length of the final instruction of the page could change, the following page can not be executable with breakpoints. I decided that there are multiple ways to handle a buffer page between RWX pages and executable tracked pages

## Page states required by RWX approach
`--x` tracked
- Filled with 0xCC bytes that gradually get removed every time they are hit
- Actual data must be stored elsewhere
`rw-`
- Uses the actual data
`rwx`
- Uses the actual data
- Cannot be followed by `--x`. Here are the options I have considered:
    - `rwx`, multiple rwx pages can be grouped together, but the last `rwx` page still cannot be followed by `--x` 
    - `rw-`, When execution hits this page, several options are possible:
        - Make the previous page(was `rwx`) into `rw-` and make the current page `--x` tracked
        - Make the current page `rwx` and make the next page `rw-`
    -  `--x` untracked followed by `--x` tracked page (assuming the last instruction of the `--x` untracked page has already executed and thus uncovered the first breakpoints of the `--x` tracked page
        -  This is quite complex to implement so I’m unsure if adding support for this page combination actually provides much benefit
