import r2pipe


class BinaryAnalysis:
    """
    This class consist of functionality and initialization
    required by any binary analysis
    """

    def __init__(self, binary_path):
        """

        :param binary_path: string, binary path
        """
        self.binary_path = binary_path
        self.command_pipe = r2pipe.open(self.binary_path)  # provide an API to interact with the binary by CLI commands
        self.command_pipe.cmd('aaa')  # Analyze the binary to enable further analysis on it

    def jmp_to_address(self, address):
        self.command_pipe.cmd('s 0x' + hex(address))

    def jmp_to_main(self):
        self.command_pipe.cmd('s main')

    def get_current_address(self):
        return int(self.command_pipe.cmd('s'), 16)

    def get_main_address(self):
        self.jmp_to_main()
        return self.get_current_address()
