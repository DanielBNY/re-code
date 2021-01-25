import shutil, os.path
import os
import re
from Models import FunctionModel, APIWrapperModel, ApiWrappers
import conf
from BinaryExtractor import BinaryExtractor
from pymongo import MongoClient
from os import listdir
from os.path import isfile, join

JUMPS = 1024000


class ImportRetdecData:
    def __init__(self, redis_session, mongodb_client: MongoClient, binary_extractor: BinaryExtractor, analyzed_file):
        self.analyzed_file = analyzed_file
        self.redis_session = redis_session
        self.decompiled_file_path = conf.retdec_decompiler["decompiled_file_path"]
        self.mongodb_client = mongodb_client
        self.binary_extractor = binary_extractor

    def run(self, binary_extractor: BinaryExtractor):
        binary_extractor.get_radare_functions_addresses()
        self.decompile_to_multiple_files()
        decompiled_files = [f for f in listdir(self.decompiled_file_path) if isfile(join(self.decompiled_file_path, f))]
        for file in decompiled_files:
            self.import_decompiled_functions(file_name=file)

    def import_decompiled_functions(self, file_name):
        function_model = None
        with open(self.decompiled_file_path + '/' + file_name) as file:
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

    def decompile_to_multiple_files(self):
        tmp_decompiled_output = self.decompiled_file_path + '/tmp'
        if os.path.exists(self.decompiled_file_path):
            shutil.rmtree(self.decompiled_file_path)
        os.mkdir(self.decompiled_file_path)
        if os.path.exists(tmp_decompiled_output):
            shutil.rmtree(tmp_decompiled_output)
        os.mkdir(tmp_decompiled_output)

        file_size = os.stat(self.analyzed_file).st_size
        max_address = file_size
        for start_address in range(0, max_address, JUMPS):
            command = f"{conf.retdec_decompiler['decompiler_path']}  --select-ranges {hex(start_address)}-{hex(start_address + JUMPS)} -o {tmp_decompiled_output + '/file' + str(start_address)} {self.analyzed_file} --cleanup --select-decode-only"
            stream = os.popen(command)
            output = stream.read()
            print(output)
            with open(self.decompiled_file_path + '/file' + str(start_address), 'wb') as outfile:
                with open(tmp_decompiled_output + '/file' + str(start_address), "rb") as infile:
                    shutil.copyfileobj(infile, outfile, 1024 * 1024 * 10)
            shutil.rmtree(tmp_decompiled_output)
            os.mkdir(tmp_decompiled_output)
        shutil.rmtree(tmp_decompiled_output)
