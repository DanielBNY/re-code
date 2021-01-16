from BinaryExtractor import BinaryExtractor
import os
from MongoImport import MongoImport


class FunctionsInfoExtractor:
    def __init__(self, binary_extractor_session: BinaryExtractor, db_name: str):
        self.binary_extractor_session = binary_extractor_session
        self.mongo_import = MongoImport(db_name=db_name)
        self.collection_name = "FunctionsInfo"
        self.db_name = db_name

    def run(self):
        file_path = f"/tmp/all_functions_info.json"
        self.binary_extractor_session.get_all_functions_info(file_path)
        self.mongo_import.import_collection_from_json_array(file_path=file_path, collection_name=self.collection_name)
        os.remove(file_path)
