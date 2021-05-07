from src.AbstractClasses import Action
from pymongo import MongoClient
from os.path import exists
from os import mkdir
import shutil
import redis


class Cleanup(Action):
    def __init__(self, redis_session: redis.Redis, mongo_client: MongoClient, file_path_to_analyze: str,
                 functions_info_file_path: str, temporary_sample_data_directory: str, mongo_db_name: str,
                 decompiled_files_path: str, recovered_project_path: str, decompiler_path: str):
        self.redis_session = redis_session
        self.mongo_client = mongo_client
        self.file_path_to_analyze = file_path_to_analyze
        self.recovered_project_path = recovered_project_path
        self.decompiler_path = decompiler_path
        self.temporary_sample_data_directory = temporary_sample_data_directory
        self.functions_info_file_path = functions_info_file_path
        self.decompiled_files_path = decompiled_files_path
        self.mongo_db_name = mongo_db_name

    def run(self):
        self.remove_and_recreate(self.recovered_project_path)
        self.remove_and_recreate(self.temporary_sample_data_directory)
        self.remove_and_recreate(self.decompiled_files_path)
        self.redis_session.flushdb()
        self.mongo_client.drop_database(self.mongo_db_name)

    @staticmethod
    def remove_and_recreate(path):
        if exists(path):
            shutil.rmtree(path)
        mkdir(path)
