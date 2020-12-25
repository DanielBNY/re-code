from BinaryExtractor import BinaryExtractor
import os


class FunctionsInfoExtractor:
    def __init__(self, binary_extractor_session: BinaryExtractor, db_name: str):
        self.binary_extractor_session = binary_extractor_session
        self.collection_name = "FunctionsInfo"
        self.db_name = db_name

    def run(self):
        all_functions_info = self.binary_extractor_session.get_all_functions_info()
        file_path = '/tmp/all_functions_info.json'
        with open(file_path, 'w') as file:
            file.write(all_functions_info)
        stream = os.popen(
            f"mongoimport --db {self.db_name} --collection {self.collection_name} --file {file_path} --jsonArray")
        output = stream.read()
        os.remove(file_path)
        return output
