import re
from Models import FunctionModel, Functions, LonelyModels


class LoadDecompiledFunctions:
    def __init__(self, redis_session, decompiled_file_path):
        self.redis_session = redis_session
        self.decompiled_file_path = decompiled_file_path

    def run(self):
        self.load_decompiled_functions()

    def load_decompiled_functions(self):
        function_model = None
        with open(self.decompiled_file_path) as file:
            decompiled_function = ""
            for line in file:
                if self.is_start_of_function(line):
                    decompiled_function = ""
                    address_in_line = self.get_function_address(line)
                    correct_address = None
                    functions_ids = Functions(redis_session=self.redis_session).get_functions_ids()
                    if b"function:" + str(address_in_line).encode() in functions_ids:
                        correct_address = address_in_line
                    if b"function:" + str(address_in_line + 1).encode() in functions_ids:
                        correct_address = address_in_line + 1
                    if correct_address:
                        function_model = FunctionModel(redis_session=self.redis_session,
                                                       address=str(correct_address).encode())
                    else:
                        function_model = FunctionModel(redis_session=self.redis_session,
                                                       address=str(address_in_line).encode())
                        LonelyModels(redis_session=self.redis_session).add_address(address_in_line)
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
