import r2pipe
import os
import json
from Models import RadareDetectedModels
import redis
from typing import List


class BinaryExtractor:
    def __init__(self, binary_path: str, redis_session: redis.Redis):
        self.command_pipe = r2pipe.open(binary_path)
        self.redis_session = redis_session
        self.start_virtual_address = None
        self.end_virtual_address = None
        self.set_start_end_virtual_addresses()

    def set_start_end_virtual_addresses(self):
        """
        Sets the minimum and maximum virtual addresses in file.
        """
        file_sections_info = self.get_file_sections_info()
        self.start_virtual_address = self.get_min_virtual_address(file_sections_info)
        self.end_virtual_address = self.get_max_virtual_address(file_sections_info)

    def get_file_sections_info(self) -> List:
        """
        Returns the binary sections info.
        Radare2 'iSj' command returns info about the binary sections in a json format.
        """
        return json.loads(self.command_pipe.cmd('iSj'))

    @staticmethod
    def get_min_virtual_address(file_sections: List):
        """
        :param file_sections: list, list of file sections

        Returns the minimum virtual file section address.
        """
        min_address = file_sections[0]["vaddr"]
        for section in file_sections:
            if min_address > section["vaddr"]:
                min_address = section["vaddr"]
        return min_address

    @staticmethod
    def get_max_virtual_address(file_sections: List):
        """
        :param file_sections: list, list of file sections

        Returns the max virtual file section address.
        """
        max_address = file_sections[0]["vaddr"] + file_sections[0]["vsize"]
        for section in file_sections:
            section_end_address = section["vaddr"] + section["vsize"]
            if max_address < section_end_address:
                max_address = section_end_address
        return max_address

    def analyze_all_functions_calls(self):
        """
        Radare2 'aac' command analyze all functions calls
        """
        self.command_pipe.cmd('aac')

    def import_functions_addresses(self):
        """
        Import all radare2 detected functions addresses into redis models.
        Radare2 's @@ fcn.*' command goes over all detected functions and prints their addresses.
        """
        functions_addresses = self.command_pipe.cmd(f"s @@ fcn.*")
        functions_addresses_list = functions_addresses.split('\n')
        for address in functions_addresses_list:
            if address:
                RadareDetectedModels(redis_session=self.redis_session).add_address(int(address, 16))

    def extract_functions_info(self, output_path: str, imported_collection_name: str, mongo_db_name: str):
        """
        :param output_path:
        :param imported_collection_name:
        :param mongo_db_name:

        Export the functions info into a json file and then import it into mongodb for fast function info read time.
        """
        self.export_functions_info(output_json_path=output_path)
        self.import_functions_info(input_json_path=output_path, imported_collection_name=imported_collection_name,
                                   mongo_db_name=mongo_db_name)

    def export_functions_info(self, output_json_path: str):
        """
        :param output_json_path: str, json file path

        Radare2 'aflj' command list the functions info in a json format.
        The command output is written into the output json path.
        """
        self.command_pipe.cmd(f"aflj > {output_json_path}")

    @staticmethod
    def import_functions_info(mongo_db_name: str, input_json_path: str, imported_collection_name: str):
        """
        :param mongo_db_name: str, mongodb name.
        :param input_json_path: str, json array file path.
        :param imported_collection_name: str, collection name to import the json array.

        Import a json array file with the mongoimport cli tool to a mongo DB collection.
        """
        stream = os.popen(
            f"mongoimport --db {mongo_db_name} --collection {imported_collection_name} --file {input_json_path} --jsonArray")
        output = stream.read()
        return output

    def analyze_function_at_address(self, address: int):
        """
        :param address: int, address inside the binary file.

        Radare2 's address' command jump to the address in the binary.
        Radare2 'af' analyze the function in the current address.
        """
        self.command_pipe.cmd(f"s {address}; af")
