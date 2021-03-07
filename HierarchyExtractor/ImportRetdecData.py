import shutil, os.path
import os
import re
from Models import FunctionModel, APIWrapperModel, ApiWrappers, RadareDetectedModels, RetdecDetectedModels
import conf
from BinaryExtractor import BinaryExtractor
from os import listdir
from os.path import isfile, join
import subprocess
import psutil


class ImportRetdecData:
    def __init__(self, redis_session, binary_extractor: BinaryExtractor, analyzed_file, number_of_processes):
        self.analyzed_file = analyzed_file
        self.redis_session = redis_session
        self.decompiled_file_path = conf.retdec_decompiler["decompiled_file_path"]
        self.binary_extractor = binary_extractor
        self.number_of_processes = number_of_processes

    def run(self):
        self.binary_extractor.export_functions_addresses()
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
                    RetdecDetectedModels(redis_session=self.redis_session).add_address(
                        function_detector.function_address)
                    radare_detected_address = None
                    radare_detected_models = RadareDetectedModels(self.redis_session)
                    if radare_detected_models.is_member(function_detector.function_address):
                        radare_detected_address = function_detector.function_address
                    if radare_detected_models.is_member(function_detector.function_address + 1):
                        radare_detected_address = function_detector.function_address + 1
                    if radare_detected_address:
                        function_model = FunctionModel(redis_session=self.redis_session,
                                                       address=str(radare_detected_address).encode())
                    else:
                        function_model = FunctionModel(redis_session=self.redis_session,
                                                       address=str(function_detector.function_address).encode())
                    if function_detector.wrapped_function_name:
                        contained_address_minus_three = str(int(function_model.contained_function_address) - 3).encode()
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
                        if not radare_detected_address and not function_detector.empty_function:
                            self.binary_extractor.analyze_function_at_address(
                                address=function_detector.function_address)

    def decompile_to_multiple_files(self):
        if os.path.exists(self.decompiled_file_path):
            shutil.rmtree(self.decompiled_file_path)
        os.mkdir(self.decompiled_file_path)
        file_size = os.stat(self.analyzed_file).st_size
        decompilers_processes = []
        start_address = self.binary_extractor.start_virtual_address
        while start_address < self.binary_extractor.end_virtual_address:
            analyzed_chunks_size = self.calculate_analyzed_chunks_size(file_size)
            decompiler_process = subprocess.Popen([conf.retdec_decompiler['decompiler_path'], "--select-ranges",
                                                   f"{hex(start_address)}-{hex(start_address + analyzed_chunks_size)}",
                                                   "-o",
                                                   f"{self.decompiled_file_path + '/file' + str(start_address)}.c",
                                                   self.analyzed_file,
                                                   "--cleanup", "--select-decode-only"])
            decompilers_processes.append(decompiler_process)
            if len(decompilers_processes) == self.number_of_processes:
                decompilers_processes[0].communicate()
                del decompilers_processes[0]
            start_address += analyzed_chunks_size

        for last_decompiler_process in decompilers_processes:
            last_decompiler_process.communicate()

    def calculate_analyzed_chunks_size(self, file_size):
        available_memory_space_kb = psutil.virtual_memory().available
        minimized_chunk = int(available_memory_space_kb / (file_size * self.number_of_processes))
        return minimized_chunk


class FunctionDetector:
    def __init__(self, redis_session):
        self.function_code = ""
        self.functions_lines = 0
        self.redis_session = redis_session
        self.function_address = None
        self.currently_analyzing_function = False
        self.finished_analyzing_function = False
        self.wrapped_function_name = None
        self.empty_function = False

    def reset_values(self):
        self.function_code = ""
        self.functions_lines = 0
        self.function_address = None
        self.wrapped_function_name = None

    def analyze_code_line(self, code_line):
        if self.finished_analyzing_function:
            # If finished to analyze a function and analyzing a new line reset the values of the last function
            self.reset_values()
        function_address = self.get_function_address(line=code_line)
        if function_address:
            self.reset_values()
            self.function_address = function_address
            self.currently_analyzing_function = True
            self.finished_analyzing_function = False

        if self.currently_analyzing_function:
            self.functions_lines += 1
            self.function_code += code_line

        if self.is_end_of_function(code_line):
            self.currently_analyzing_function = False
            self.finished_analyzing_function = True
            self.set_wrapped_function_name()
            self.empty_function = self.is_empty_function()

    def is_function_detected(self):
        if self.finished_analyzing_function and self.function_code:
            return self

    def set_wrapped_function_name(self):
        function_line_list = self.function_code.split('\n')
        last_line = None
        if len(function_line_list) <= 6:
            for function_line in reversed(function_line_list):
                if last_line == '}':
                    regex_match = re.search(r'(\w+)\(', function_line)
                    if regex_match:
                        wrapped_function_name = regex_match.group(1)
                        self.wrapped_function_name = wrapped_function_name
                last_line = function_line

    def is_empty_function(self):
        """
        Example of an empty function:

        int64_t function_1d1f0(void) {
            // 0x1d1f0
            int64_t result; // 0x1d1f0
            return result;
        }
        """
        function_line_list = self.function_code.split('\n')
        if len(function_line_list) < 8:
            last_line = ""
            for function_line in reversed(function_line_list):
                if last_line == '}':
                    if "return result;" not in function_line:
                        return False
                if "return result;" in last_line:
                    if "int64_t result;" not in function_line:
                        return False
                last_line = function_line
            return True
        else:
            return False

    @staticmethod
    def is_start_of_function(line):
        if line[0] != ' ' and line[0] != '\n' and line[0] != '/' and line[0] != '#' and line[0] != '}' and \
                line[-2] == '{':
            if "function_" in line:
                return True
        return False

    @staticmethod
    def is_end_of_function(line):
        return line[0] == '}'

    @staticmethod
    def get_function_address(line):
        detected_regex = re.search(r'// Address range: (\S+)', line)
        if detected_regex:
            return int(detected_regex.group(1), 16)
