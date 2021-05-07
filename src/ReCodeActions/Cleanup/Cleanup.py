from src.AbstractClasses import Action
from pymongo import MongoClient
from os.path import exists
import os.path
import shutil
import redis


class Cleanup(Action):
    def __init__(self, redis_session: redis.Redis, mongo_client: MongoClient, file_path_to_analyze: str,
                 functions_info_file_path: str, temporary_sample_data_directory: str, mongo_db_name: str,
                 decompiled_files_path: str, recovered_project_path: str,
                 decompiler_path: str):

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
        self.re_create_recovered_project_path()
        self.re_create_temporary_sample_directories()
        self.decompiled_files_cleanup()
        self.redis_session.flushdb()
        self.mongo_client.drop_database(self.mongo_db_name)

    def re_create_recovered_project_path(self):
        if os.path.exists(self.recovered_project_path):
            shutil.rmtree(self.recovered_project_path)
        os.mkdir(self.recovered_project_path)

    def re_create_temporary_sample_directories(self):
        if os.path.exists(self.temporary_sample_data_directory):
            shutil.rmtree(self.temporary_sample_data_directory)
        os.mkdir(self.temporary_sample_data_directory)
        os.mkdir(self.decompiled_files_path)

    def decompiled_files_cleanup(self):
        if exists(self.decompiled_files_path):
            shutil.rmtree(self.decompiled_files_path)
        os.mkdir(self.decompiled_files_path)
