import shutil, os.path
import os
import re
from Models import FunctionModel, APIWrapperModel, ApiWrappers
import conf
from BinaryExtractor import BinaryExtractor
from pymongo import MongoClient
from os import listdir
from os.path import isfile, join
import subprocess

JUMPS = 1024000


class ImportRetdecData:
    def __init__(self, redis_session, mongodb_client: MongoClient, binary_extractor: BinaryExtractor, analyzed_file,
                 number_of_processes):
        self.analyzed_file = analyzed_file
        self.redis_session = redis_session
        self.decompiled_file_path = conf.retdec_decompiler["decompiled_file_path"]
        self.mongodb_client = mongodb_client
        self.binary_extractor = binary_extractor
        self.number_of_processes = number_of_processes

    def run(self, binary_extractor: BinaryExtractor):
        binary_extractor.get_radare_functions_addresses()
        self.decompile_to_multiple_files()
        decompiled_files = [file for file in listdir(self.decompiled_file_path) if
                            isfile(join(self.decompiled_file_path, file)) and file.endswith(".c")]
        for file in decompiled_files:
            self.import_decompiled_functions(file_name=file)

    def import_decompiled_functions(self, file_name):
        with open(self.decompiled_file_path + '/' + file_name) as file:
            function_detector = FunctionDetector(redis_session=self.redis_session)
            for line in file:
                function_detector.analyze_code_line(code_line=line)
                if function_detector.is_function_detected():
                    self.redis_session.sadd('retdec_functions_addresses', function_detector.function_address)
                    radare_detected_address = None
                    if self.redis_session.sismember('r2_functions_addresses', function_detector.function_address):
                        radare_detected_address = function_detector.function_address
                    if self.redis_session.sismember('r2_functions_addresses',
                                                    function_detector.function_address + 1):
                        radare_detected_address = function_detector.function_address + 1
                    if radare_detected_address:
                        function_model = FunctionModel(redis_session=self.redis_session,
                                                       address=str(radare_detected_address).encode())
                    else:
                        function_model = FunctionModel(redis_session=self.redis_session,
                                                       address=str(function_detector.function_address).encode())
                    if function_detector.wrapped_function_name:
                        contained_address_minus_three = str(int(function_model.contained_address) - 3).encode()
                        wrapper_function_model = FunctionModel(redis_session=self.redis_session,
                                                               address=contained_address_minus_three)
                        wrapper_function_model.set_function_code(function_detector.function_code)
                        APIWrapperModel(redis_session=self.redis_session,
                                        function_id=wrapper_function_model.model_id).set_api_name(
                            function_detector.wrapped_function_name)
                        ApiWrappers(redis_session=self.redis_session).add_function(
                            model_id=wrapper_function_model.model_id)
                    else:
                        function_model.set_function_code(function_detector.function_code)
                        if not radare_detected_address:
                            self.binary_extractor.analyze_function_in_address(function_detector.function_address)

    def decompile_to_multiple_files(self):
        if os.path.exists(self.decompiled_file_path):
            shutil.rmtree(self.decompiled_file_path)
        os.mkdir(self.decompiled_file_path)

        file_size = os.stat(self.analyzed_file).st_size
        max_address = file_size
        decompilers_processes = []
        for start_address in range(0, max_address, JUMPS):
            decompiler_process = subprocess.Popen([conf.retdec_decompiler['decompiler_path'], "--select-ranges",
                                                   f"{hex(start_address)}-{hex(start_address + JUMPS)}", "-o",
                                                   f"{self.decompiled_file_path + '/file' + str(start_address)}.c",
                                                   self.analyzed_file,
                                                   "--cleanup", "--select-decode-only"])
            decompilers_processes.append(decompiler_process)
            if len(decompilers_processes) == self.number_of_processes:
                decompilers_processes[0].communicate()
                del decompilers_processes[0]

        for last_decompiler_process in decompilers_processes:
            last_decompiler_process.communicate()


class FunctionDetector:
    def __init__(self, redis_session):
        self.function_code = ""
        self.functions_lines = 0
        self.redis_session = redis_session
        self.function_address = None
        self.currently_analyzing_function = False
        self.finished_analyzing_function = False
        self.wrapped_function_name = None

    def reset_values(self):
        self.function_code = ""
        self.functions_lines = 0
        self.function_address = None
        self.wrapped_function_name = None

    def analyze_code_line(self, code_line):
        if self.is_start_of_function(code_line):
            self.reset_values()
            self.function_address = self.get_function_address(code_line)
            self.currently_analyzing_function = True
            self.finished_analyzing_function = False

        if self.currently_analyzing_function:
            self.functions_lines += 1
            self.function_code += code_line

        if self.is_end_of_function(code_line):
            self.currently_analyzing_function = False
            self.finished_analyzing_function = True
            self.set_wrapped_function_name()

    def is_function_detected(self):
        if self.finished_analyzing_function and self.function_code:
            return self

    def set_wrapped_function_name(self):
        function_line_list = self.function_code.split('\n')
        last_line = None
        if len(function_line_list) <= 5:
            for function_line in reversed(function_line_list):
                if last_line == '}':
                    regex_match = re.search(r'(\w+)\(', function_line)
                    if regex_match:
                        wrapped_function_name = regex_match.group(1)
                        self.wrapped_function_name = wrapped_function_name
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
