import os
import re
from Models import FunctionModel


class FunctionsDecompiler:
    def __init__(self, redis_session, tmp_file_path, binary_path, decompiler_path):
        self.redis_session = redis_session
        self.tmp_file_path = tmp_file_path
        self.binary_path = binary_path
        self.decompiler_path = decompiler_path

    def run(self):
        self.decompile_to_tmp_file()
        self.load_decompiled_functions()

    def decompile_to_tmp_file(self):
        stream = os.popen(f"{self.decompiler_path} --cleanup -o {self.tmp_file_path} {self.binary_path}")
        output = stream.read()
        return output

    def load_decompiled_functions(self):
        function_model = None
        with open(self.tmp_file_path) as file:
            decompiled_function = ""
            for line in file:
                if self.is_start_of_function(line):
                    decompiled_function = ""
                    function_model = FunctionModel(redis_session=self.redis_session,
                                                   address=str(self.get_function_address(line) + 1).encode())

                decompiled_function += line
                if self.is_end_of_function(line):
                    if function_model:
                        function_model.set_function_code(decompiled_function)
                        decompiled_function = ""
                        function_model = None

    @staticmethod
    def is_start_of_function(line):
        if line[0] != ' ' and line[0] != '\n' and line[0] != '/' and line[0] != '#' and line[0] != '}' and \
                line[-2] == '{':
            if "function" in line:
                return True
        return False

    @staticmethod
    def is_end_of_function(line):
        return line[0] == '}'

    @staticmethod
    def get_function_address(line):
        return int(re.search(r'function_([a-f0-9]+)\(', line).group(1), 16)


