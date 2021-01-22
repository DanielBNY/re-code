import os
import re
from Models import FunctionModel, APIWrapperModel, ApiWrappers
from MongoImport import import_collection_from_json
import conf
from BinaryExtractor import BinaryExtractor
from pymongo import MongoClient


class ImportRetdecData:
    def __init__(self, redis_session, decompiled_file_path, mongodb_client: MongoClient,
                 binary_extractor: BinaryExtractor):
        self.redis_session = redis_session
        self.decompiled_file_path = decompiled_file_path
        self.mongodb_client = mongodb_client
        self.binary_extractor = binary_extractor

    def run(self, binary_path, binary_extractor: BinaryExtractor):
        binary_extractor.get_radare_functions_addresses()
        self.export_retdec_data(binary_path)
        self.import_decompiled_functions()

    def export_retdec_data(self, binary_path):
        stream = os.popen(f"{conf.retdec_decompiler['decompiler_path']} -o {self.decompiled_file_path} {binary_path}")
        output = stream.read()
        return output

    def import_decompiled_functions(self):
        function_model = None
        with open(self.decompiled_file_path) as file:
            decompiled_function = ""
            functions_lines = 0
            for line in file:
                if self.is_start_of_function(line):
                    decompiled_function = ""
                    functions_lines = 0
                    address_in_line = self.get_function_address(line)
                    self.redis_session.sadd('retdec_functions_addresses', address_in_line)
                    correct_address = None
                    if self.redis_session.sismember('r2_functions_addresses', address_in_line):
                        correct_address = address_in_line
                    if self.redis_session.sismember('r2_functions_addresses', address_in_line + 1):
                        correct_address = address_in_line + 1
                    if correct_address:
                        function_model = FunctionModel(redis_session=self.redis_session,
                                                       address=str(correct_address).encode())
                    else:
                        self.binary_extractor.analyze_function_in_address(address_in_line)
                        function_model = FunctionModel(redis_session=self.redis_session,
                                                       address=str(address_in_line).encode())
                decompiled_function += line
                functions_lines += 1
                if self.is_end_of_function(line):
                    if function_model:
                        wrapped_function_name = self.get_wrapped_function_name(decompiled_function)
                        if wrapped_function_name:
                            contained_address_minus_three = str(int(function_model.contained_address) - 3).encode()
                            wrapper_function_model = FunctionModel(redis_session=self.redis_session,
                                                                   address=contained_address_minus_three)
                            wrapper_function_model.set_function_code(decompiled_function)
                            APIWrapperModel(redis_session=self.redis_session,
                                            function_id=wrapper_function_model.model_id).set_api_name(
                                wrapped_function_name)
                            ApiWrappers(redis_session=self.redis_session).add_function(
                                model_id=wrapper_function_model.model_id)
                        else:
                            function_model.set_function_code(decompiled_function)
                        decompiled_function = ""
                        function_model = None
                        functions_lines = 0

    @staticmethod
    def get_wrapped_function_name(function_code):
        function_line_list = function_code.split('\n')
        last_line = None
        if len(function_line_list) <= 5:
            for function_line in reversed(function_line_list):
                if last_line == '}':
                    regex_match = re.search(r'(\w+)\(', function_line)
                    if regex_match:
                        wrapped_function_name = regex_match.group(1)
                        return wrapped_function_name
                last_line = function_line

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
