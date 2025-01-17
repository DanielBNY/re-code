import os.path

import redis
from os import listdir
from typing import List
from os.path import isfile, join

from src.ReCodeActions.Models import FunctionModel, APIWrapperModel, ApiWrappers, RadareDetectedModels, \
    RetdecDetectedModels
from src.ReCodeActions.ImportBinaryData.Radare2BinaryExtractor import Radare2BinaryExtractor
from src.ReCodeActions.ImportBinaryData.FunctionDetector import FunctionDetector
from src.ReCodeActions.ImportBinaryData.MultiProcessedDecompilation import MultiProcessedDecompilation
from src.ReCodeActions.AbstractClasses import Action
from PathSource import get_functions_info_file_path, get_file_to_analyze_directory_path, get_decompiled_files_path, \
    get_retdec_decompiler_path


class ImportBinaryData(Action):
    def __init__(self, redis_session: redis.Redis,
                 number_of_processes, imported_collection_name, mongo_db_name,
                 file_name_to_analyze, mongodb_host_name: str):

        self.redis_session = redis_session
        self.decompiled_files_path = get_decompiled_files_path()
        self.decompiler_path = get_retdec_decompiler_path()
        self.file_path_to_analyze = os.path.join(get_file_to_analyze_directory_path(), file_name_to_analyze)
        self.binary_extractor = Radare2BinaryExtractor(self.file_path_to_analyze, self.redis_session)
        self.number_of_processes = number_of_processes
        self.functions_info_file_path = get_functions_info_file_path()
        self.functions_info_collection_name = imported_collection_name
        self.mongo_db_name = mongo_db_name
        self.mongodb_host_name = mongodb_host_name

    def run(self):
        MultiProcessedDecompilation(number_of_processes=self.number_of_processes,
                                    decompiler_path=self.decompiler_path,
                                    analyzed_file=self.file_path_to_analyze,
                                    start_virtual_address=self.binary_extractor.start_virtual_address,
                                    end_virtual_address=self.binary_extractor.end_virtual_address,
                                    decompiled_files_path=self.decompiled_files_path).run()

        self.binary_extractor.analyze_all_functions_calls()

        self.binary_extractor.import_functions_addresses()
        self.import_decompiled_functions()
        self.binary_extractor.extract_functions_info(mongodb_host_name=self.mongodb_host_name,
                                                     output_path=self.functions_info_file_path,
                                                     imported_collection_name=self.functions_info_collection_name,
                                                     mongo_db_name=self.mongo_db_name)

    def get_decompiled_files_paths(self) -> List[str]:
        decompiled_files = []
        for file in listdir(self.decompiled_files_path):
            if isfile(join(self.decompiled_files_path, file)) and file.endswith(".c"):
                decompiled_files.append(join(self.decompiled_files_path, file))
        return decompiled_files

    def import_decompiled_functions(self):
        decompiled_files_paths = self.get_decompiled_files_paths()
        for file_path in decompiled_files_paths:
            self.import_file_functions(file_path=file_path)

    def import_file_functions(self, file_path):
        with open(file_path) as file:
            function_detector = FunctionDetector(redis_session=self.redis_session)
            for line in file:
                function_detector.analyze_code_line(code_line=line)
                if function_detector.is_function_detected():
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
                        APIWrapperModel(redis_session=self.redis_session,
                                        function_id=wrapper_function_model.model_id).set_api_name(
                            function_detector.wrapped_function_name)
                        ApiWrappers(redis_session=self.redis_session).add_function(
                            model_id=wrapper_function_model.model_id)
                    else:
                        if not radare_detected_address and not function_detector.empty_function:
                            self.binary_extractor.analyze_function_at_address(
                                address=function_detector.function_address)
                        function_model.set_function_code(function_detector.function_code)
                        function_model.set_size(size=function_detector.functions_lines)
                        RetdecDetectedModels(redis_session=self.redis_session).add_address(
                            function_detector.function_address)
