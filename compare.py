
class WritePC(GenericCommand):
    """Log the current Program Counter and registers."""
    _cmdline_ = "writepc"
    _syntax_  = "{:s}".format(_cmdline_)

    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        print("sigtrap pc = {:#x}".format(current_arch.pc))
        with open("pc.txt", 'w') as f:
            f.write(str(current_arch.pc))
        with open('reg.txt', 'w') as f:
            f.write(gdb.execute('info registers', to_string=True))
        return

class ReadPC(GenericCommand):
    """Set a temporary breakpoint at the Program Counter stored in pc.txt."""
    _cmdline_ = "readpc"
    _syntax_  = "{:s}".format(_cmdline_)

    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        print("sigtrap pc = {:#x}".format(current_arch.pc))
        with open("pc.txt", 'r') as f:
            pc = int(f.read().strip())
            gdb.execute("tbreak *" + hex(pc))

class ConfirmRegs(GenericCommand):
    """Confirm that the registers match that of reg.txt."""
    _cmdline_ = "confirmregs"
    _syntax_  = "{:s}".format(_cmdline_)

    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        print("sigtrap pc = {:#x}".format(current_arch.pc))
        with open("reg.txt", 'r') as f:
            expected_regs = f.read()
            regs = gdb.execute('info registers', to_string=True)

            if regs != expected_regs:
                print("Found difference in registers!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                print("Expected:")
                print(expected_regs)
                print("Found:")
                print(regs)
                print("Differences:")
                for (expected, found) in zip(expected_regs.split("\n"), regs.split('\n')):
                    if expected != found:
                        print(expected, RIGHT_ARROW, found)
                with open("diff.txt", "w") as d:
                    d.write("diff")

register_external_command(WritePC())
register_external_command(ReadPC())
register_external_command(ConfirmRegs())
