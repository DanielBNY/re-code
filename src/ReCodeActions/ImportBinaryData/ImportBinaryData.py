from src.ReCodeActions.Models import FunctionModel, APIWrapperModel, ApiWrappers, RadareDetectedModels, RetdecDetectedModels
from src.ReCodeActions.ImportBinaryData.Radare2BinaryExtractor import Radare2BinaryExtractor
from os import listdir
from os.path import isfile, join
import redis
from src.AbstractClasses import Action
from typing import List
from src.ReCodeActions.ImportBinaryData.Decompiler import Decompiler
from src.ReCodeActions.ImportBinaryData.FunctionDetector import FunctionDetector


class ImportBinaryData(Action):
    def __init__(self, redis_session: redis.Redis, analyzed_file,
                 number_of_processes, functions_info_file_path, imported_collection_name, mongo_db_name,
                 decompiler_path: str, decompiled_files_path: str, file_path_to_analyze):

        self.analyzed_file = analyzed_file
        self.redis_session = redis_session
        self.decompiled_files_path = decompiled_files_path
        self.decompiler_path = decompiler_path
        self.binary_extractor = Radare2BinaryExtractor(file_path_to_analyze, self.redis_session)
        self.number_of_processes = number_of_processes
        self.functions_info_file_path = functions_info_file_path
        self.functions_info_collection_name = imported_collection_name
        self.mongo_db_name = mongo_db_name

    def run(self):
        Decompiler(number_of_processes=self.number_of_processes,
                   decompiler_path=self.decompiler_path,
                   analyzed_file=self.analyzed_file,
                   start_virtual_address=self.binary_extractor.start_virtual_address,
                   end_virtual_address=self.binary_extractor.end_virtual_address,
                   decompiled_files_path=self.decompiled_files_path).run()

        self.binary_extractor.analyze_all_functions_calls()

        self.binary_extractor.import_functions_addresses()
        self.import_decompiled_functions()
        self.binary_extractor.extract_functions_info(output_path=self.functions_info_file_path,
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
