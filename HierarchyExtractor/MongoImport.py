import os


class MongoImport:
    def __init__(self, db_name: str):
        self.db_name = db_name

    def import_collection_from_json_array(self, collection_name, file_path):
        stream = os.popen(
            f"mongoimport --db {self.db_name} --collection {collection_name} --file {file_path} --jsonArray")
        output = stream.read()
        return output
