from src.AbstractClasses import Action
from pymongo import MongoClient
from os.path import exists
from os import mkdir
import shutil
import redis


class Cleanup(Action):
    def __init__(self, redis_session: redis.Redis, mongo_client: MongoClient,
                 temporary_sample_data_directory: str, mongo_db_name: str,
                 decompiled_files_path: str, recovered_project_path: str):
        self.redis_session = redis_session
        self.mongo_client = mongo_client
        self.recovered_project_path = recovered_project_path
        self.temporary_sample_data_directory = temporary_sample_data_directory
        self.decompiled_files_path = decompiled_files_path
        self.mongo_db_name = mongo_db_name

    def run(self):
        """
        Remove and recreate the recovered project folder.
        Remove and recreate the temporary sample data folder.
        Remove and recreate the decompiled files folder.
        Flush the redisDB.
        Drop the mongoDB.
        """
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
