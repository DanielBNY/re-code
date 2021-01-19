import os
import re
from Models import FunctionModel
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
        self.import_retdec_functions_info()
        self.set_retdec_functions_address_set()
        self.import_decompiled_functions()

    def export_retdec_data(self, binary_path):
        stream = os.popen(f"{conf.retdec_decompiler['decompiler_path']} -o {self.decompiled_file_path} {binary_path}")
        output = stream.read()
        return output

    def import_retdec_functions_info(self):
        import_collection_from_json(collection_name=conf.retdec_decompiler['collection_name'],
                                    file_path=self.decompiled_file_path + '.config.json')

    def set_retdec_functions_address_set(self):
        db = self.mongodb_client[conf.mongo_db['db_name']]
        functions_retdec_info_collection = db['retdec_info']
        functions_retdec_info = functions_retdec_info_collection.distinct("functions")
        for function_info in functions_retdec_info:
            if function_info['fncType'] == 'decompilerDefined':
                self.redis_session.sadd('retdec_functions_addresses', int(function_info['startAddr'], 16))

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
                    correct_address = None
                    if self.redis_session.sismember('r2_functions_addresses', address_in_line):
                        correct_address = address_in_line
                    if self.redis_session.sismember('r2_functions_addresses', address_in_line + 1):
                        correct_address = address_in_line + 1
                    if correct_address:
                        function_model = FunctionModel(redis_session=self.redis_session,
                                                       address=str(correct_address).encode())
                    else:
                        if self.redis_session.sismember('retdec_functions_addresses', address_in_line):
                            self.binary_extractor.analyze_function_in_address(address_in_line)
                            function_model = FunctionModel(redis_session=self.redis_session,
                                                           address=str(address_in_line).encode())
                decompiled_function += line
                functions_lines += 1
                if self.is_end_of_function(line):
                    if function_model:
                        function_model.set_function_code(decompiled_function)
                        decompiled_function = ""
                        function_model = None
                        functions_lines = 0

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
