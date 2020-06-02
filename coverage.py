import capstone
print("Python loaded")


# TODO: Remove ability for tracee to mmprotect any memory that we have tracked
# TODO: Detect need for RWX pages

# __pages__ holds list of [Permission, State, DuplicatePageAddr]
__pages__ = {}

# Utils


def get_real_addr(addr):
    page = (addr >> 12) << 12
    if page not in __pages__:
        # We have never touched this page before, use the actual address
        return addr
    else:
        if __pages__[page][0] in ("rw", "untracked"):
            return addr
        elif __pages__[page][0] in ("exec_tracked"):
            return __pages__[page][1] | (addr & 0xfff)
        else:
            assert False, "Unknown state: {}".format(__pages__[page][0])


def get_real_data_within_page(addr, length):
    addr = get_real_addr(addr)
    assert (addr & 0xfff) + (length - 1) < 0x1000, "get_real_within_page " + \
        "called with length that extends past page boundary"
    return read_memory(addr, length)


def get_real_data(addr, length):
    res = b""
    while length > 0:
        within_page_length = min(length, (addr | 0xfff) + 1 - addr)
        res += get_real_data_within_page(addr, within_page_length)
        length -= within_page_length
        addr += within_page_length
    return res


def get_instruction_length(addr):
    # Largest possible x86 instruction is 15 bytes
    code = get_real_data(addr, 15)

    arch, mode = get_capstone_arch(arch=None, mode=None, endian=None)
    cs = capstone.Cs(arch, mode)
    cs.detail = True
    for (_, size, _, _) in cs.disasm_lite(code, addr):
        return size


def remove_breakpoint(addr):
    length = get_instruction_length(addr)
    page = (addr >> 12) << 12
    olength = length
    oaddr = addr
    within_page_length = min(length, (addr | 0xfff) + 1 - addr)

    write_memory(addr, get_real_data_within_page(
        addr, within_page_length), within_page_length)

    if length - within_page_length > 0:
        addr += within_page_length
        length -= within_page_length
        page = (addr >> 12) << 12
        if __pages__[page][0] in ("exec_tracked"):
            write_memory(addr, get_real_data_within_page(addr, length), length)
    gdb.execute("x/" + str(olength) + "c " + hex(oaddr))

# Functions


def memset(addr, char, length):
    write_memory(addr, bytes([char]) * length, length)


def memcpy(dest, src, length):
    write_memory(dest, read_memory(src, length), length)


def mprotect(addr, length, perm):
    assert addr & 0xfff == 0, "mprotect called with non-page-aligned address"
    pkey = 0
    if perm == 4:
        pkey = 1
    gdb.execute("call (int)pkey_mprotect(" + hex(addr) + ", " +
                hex(length) + ", " + str(perm) + ", " + str(pkey) + ")")
    reset_all_caches()
    ret = int(gdb.parse_and_eval("$"))
    assert ret == 0, "mprotect did not return 0: {}".format(ret)


def mmap(addr, length, perm, flags, fd, offset):
    assert addr & 0xfff == 0, "mmap called with non-page-aligned address"
    gdb.execute("call (void*)mmap({}, {}, {}, {}, {}, {})"
                .format(hex(addr), hex(length), str(perm), hex(flags),
                        str(fd), str(offset)))
    reset_all_caches()
    ret = int(gdb.parse_and_eval("$"))
    assert ret != 0, "mmap failed to allocate page"
    return ret

# State transitions


def rw_to_exec_tracked(addr):
    assert addr & 0xfff == 0, "rw_to_exec_tracked called with unaligned addr " + \
        hex(addr)

    # If we have never before encountered the page, treat it as though it was
    # "rw-"
    if addr not in __pages__:
        __pages__[addr] = ["untracked", None]

    if __pages__[addr][1] is None:
        # Page never before duplicated, create destination page
        ret = mmap(0, 0x1000, 3, 0x21, -1, 0)
        __pages__[addr][1] = ret

    (state, dup_addr) = __pages__[addr]

    assert state in (
        "untracked", "rw"), "rw_to_exec_tracked called on page with permission " + str(perm.value)

    # Copy over the page
    memcpy(dup_addr, addr, 0x1000)

    # Fill page with break points
    memset(addr, 0xCC, 0x1000)

    # Make page executable
    mprotect(addr, 0x1000, 4)

    __pages__[addr][0] = "exec_tracked"


def exec_tracked_to_rw(addr):
    assert addr & 0xfff == 0, "exec_tracked_to_rw called with unaligned addr " + \
        hex(addr)

    assert addr in __pages__ and __pages__[addr][1] is not None, \
        "exec_tracked_to_rw called on non-tracked page"

    (state, dup_addr) = __pages__[addr]

    assert state in (
        "exec_tracked"), "exec_tracked_to_rw called on page with permission " + str(perm.value)

    # Make page Read-Write
    mprotect(addr, 0x1000, 3)

    # Copy from the duplicate page
    memcpy(addr, dup_addr, 0x1000)

    __pages__[addr][0] = "rw"


class BreakpointPageCoverageCommand(GenericCommand):
    """Track coverage using breakpoints as shown by Gamozolabs."""
    _cmdline_ = "coveragestart"
    _syntax_ = "{:s}".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        global __pages__
        print(" = {}".format(current_arch))
        print("pc = {:#x}".format(current_arch.pc))

        gdb.execute("handle SIGTRAP stop nopass")
        gdb.execute("handle SIGSEGV stop nopass")
        gdb.execute("delete breakpoints")

        gdb.execute("call (int)pkey_alloc(0, 3)")
        __pkey__ = gdb.parse_and_eval("$")

        assert __pkey__ > 0, "CPU or OS does not support pkeys"

        maps = get_process_maps()
        name = get_filepath()
        for i in maps:
            if i.path != name and i.path != "[heap]":
                continue
            mprotect(i.page_start, i.size, 3)
            while i.page_start < i.page_end:
                __pages__[i.page_start] = ["rw", None]
                i.page_start += 0x1000

        gef_on_stop_hook(self.on_stop)
        gef_on_stop_hook(hook_stop_handler)
        return

    def on_stop(self, stop_event):
        print("Caught stop!")
        print(stop_event)
        signal = self.get_signal()
        if signal == "SIGTRAP":
            print("Handling breakpoint")
            gdb.execute("handlesigtrap")
        elif signal == "SIGSEGV":
            print("Handling pagefault")
            gdb.execute("handlesegfault")
        else:
            print("Received signal: ", signal)

    def get_signal(self):
        res = gdb.execute("info program", to_string=True).splitlines()

        for line in res:
            line = line.strip()
            if line.startswith("It stopped with signal "):
                return line.replace(
                    "It stopped with signal ", "").split(
                    ",", 1)[0]
        print("[-] Unknown reason for stop")
        print("\"\"\"")
        print(res)
        print("\"\"\"")

        return ""


class HandleSegFault(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "handlesegfault"
    _syntax_ = "{:s}".format(_cmdline_)

    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        print("segfault pc = {:#x}".format(current_arch.pc))
        address = int(gdb.parse_and_eval(
            '$_siginfo._sifields._sigfault.si_addr'))
        pc = int(gdb.parse_and_eval('$pc'))
        print(gdb.parse_and_eval('$_siginfo._sifields._sigfault'))

        page = (address >> 12) << 12

        assert page in __pages__, "Seg Fault on page we never touched: " + \
            hex(page)
        section = process_lookup_address(address)

        # If not, executable, set to execute and
        if not section.is_executable():
            assert pc <= address and pc + 15 >= address, "Execution did not occur at PC"
            rw_to_exec_tracked(page)
            pc_page = (pc >> 12) << 12
            if pc_page != page:
                assert __pages__[pc_page][0] in ("exec_tracked"), \
                    "Instruction that began in an untracked page caused the following page to " + \
                    "become tracked causing the later part of the instruction to be overwritten"
                write_memory(pc, b'\xCC', 1)
        elif section.is_executable():
            exec_tracked_to_rw(page)
        return


class HandleSigTrap(GenericCommand):
    """Handle breakpoints that were added by 'coveragestart'."""
    _cmdline_ = "handlesigtrap"
    _syntax_ = "{:s}".format(_cmdline_)

    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        print("sigtrap pc = {:#x}".format(current_arch.pc))
        pc = current_arch.pc - 1
        page = (pc >> 12) << 12
        if page in __pages__ and __pages__[page][0] in ("exec_tracked"):
            remove_breakpoint(pc)
            gdb.execute("set $pc-=1")
            print("#############################################", hex(pc))
        return


register_external_command(HandleSegFault())
register_external_command(HandleSigTrap())
register_external_command(BreakpointPageCoverageCommand())
