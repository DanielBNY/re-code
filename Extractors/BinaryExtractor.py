import r2pipe
import json


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


class MultipleFunctionExtractor:
    """
    the class contain extracted data about functions in the binary
    """
    def __init__(self, binary_analysis):
        """

        :param binary_analysis: BinaryAnalysis object
        """
        self.binary_analysis = binary_analysis
        self.all_functions_info = self.get_all_functions_info()
        self.all_function_addresses = self.get_functions_addresses()

    def get_all_functions_info(self):
        return json.loads(self.binary_analysis.command_pipe.cmd('aflj'))

    def get_functions_addresses(self):
        functions_addresses = []
        for function in self.all_functions_info:
            functions_addresses.append(function['offset'])
        return functions_addresses


class FunctionExtractor:
    """
    The class consist of analysis functionality and data about a function in the binary
    """

    def __init__(self, function_offset, binary_analysis):
        """
        :param function_offset: int
        :param binary_analysis: BinaryAnalysis object
        """
        self.binary_analysis = binary_analysis
        self.function_offset = function_offset

    def decompile_function(self):
        """
        :return: string, c like code in text
        """
        self.binary_analysis.jmp_to_address(self.function_offset)
        decompile = self.binary_analysis.command_pipe.cmd('pdc')
        return decompile

    def disassemble_function(self):
        """
        :return: dictionary, assembly function code
        """
        self.binary_analysis.jmp_to_address(self.function_offset)
        disassemble = json.loads(self.binary_analysis.command_pipe.cmd('pdfj'))
        # pdj - disassemble to json
        return disassemble
