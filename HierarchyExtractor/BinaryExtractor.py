import r2pipe
import os
import json
from Models import RadareDetectedModels


class BinaryExtractor:
    def __init__(self, binary_path, redis_session):
        self.command_pipe = r2pipe.open(binary_path)
        self.redis_session = redis_session
        self.start_virtual_address = None
        self.end_virtual_address = None
        self.set_start_end_virtual_addresses()

    def set_start_end_virtual_addresses(self):
        file_sections_json = json.loads(self.command_pipe.cmd('iSj'))
        self.start_virtual_address = self.get_start_virtual_address(file_sections_json)
        self.end_virtual_address = self.get_end_virtual_address(file_sections_json)

    @staticmethod
    def get_start_virtual_address(file_sections):
        min_address = file_sections[0]["vaddr"]
        for section in file_sections:
            if min_address > section["vaddr"]:
                min_address = section["vaddr"]
        return min_address

    @staticmethod
    def get_end_virtual_address(file_sections):
        max_address = file_sections[0]["vaddr"] + file_sections[0]["vsize"]
        for section in file_sections:
            section_end_address = section["vaddr"] + section["vsize"]
            if max_address < section_end_address:
                max_address = section_end_address
        return max_address

    def analyze_all_functions_calls(self):
        self.command_pipe.cmd('aac')

    def finish_analysis(self):
        self.command_pipe.cmd('exit')
        self.command_pipe = None

    def export_functions_addresses(self):
        functions_addresses = self.command_pipe.cmd(f"s @@ fcn.*")
        functions_addresses_list = functions_addresses.split('\n')
        for address in functions_addresses_list:
            if address:
                RadareDetectedModels(redis_session=self.redis_session).add_address(int(address, 16))

    def extract_functions_info(self, output_path: str, imported_collection_name: str, mongo_db_name: str):
        self.export_functions_info(output_json_path=output_path)
        self.import_functions_info(input_json_path=output_path, imported_collection_name=imported_collection_name,
                                   mongo_db_name=mongo_db_name)
        os.remove(output_path)

    def export_functions_info(self, output_json_path):
        self.command_pipe.cmd(f"aflj > {output_json_path}")

    @staticmethod
    def import_functions_info(mongo_db_name: str, input_json_path: str, imported_collection_name: str):
        stream = os.popen(
            f"mongoimport --db {mongo_db_name} --collection {imported_collection_name} --file {input_json_path} --jsonArray")
        output = stream.read()
        return output

    def analyze_function_at_address(self, address):
        self.command_pipe.cmd(f"s {address}; af")
