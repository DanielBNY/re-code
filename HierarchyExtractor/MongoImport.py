import os
import conf


def import_collection_from_json_array(collection_name, file_path):
    stream = os.popen(
        f"mongoimport --db {conf.mongo_db['db_name']} --collection {collection_name} --file {file_path} --jsonArray")
    output = stream.read()
    return output


def import_collection_from_json(collection_name, file_path):
    stream = os.popen(
        f"mongoimport --db {conf.mongo_db['db_name']} --collection {collection_name} --file {file_path}")
    output = stream.read()
    return output
