import r2pipe
import os
from MongoImport import import_collection_from_json_array


class BinaryExtractor:
    def __init__(self, binary_path, redis_session):
        self.command_pipe = r2pipe.open(binary_path)
        self.redis_session = redis_session

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
                self.redis_session.sadd('r2_functions_addresses', int(address, 16))

    def extract_functions_info(self, output_path, imported_collection_name):
        self.export_functions_info(output_json_path=output_path)
        self.import_functions_info(input_json_path=output_path, imported_collection_name=imported_collection_name)
        os.remove(output_path)

    def export_functions_info(self, output_json_path):
        self.command_pipe.cmd(f"aflj > {output_json_path}")

    @staticmethod
    def import_functions_info(input_json_path, imported_collection_name):
        import_collection_from_json_array(file_path=input_json_path, collection_name=imported_collection_name)

    def analyze_function_at_address(self, address):
        self.command_pipe.cmd(f"s {address}; af")
