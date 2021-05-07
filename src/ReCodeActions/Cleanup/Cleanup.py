from src.AbstractClasses import Action
from pymongo import MongoClient
from os.path import exists
from os import mkdir
import shutil
import redis

from PathSource import get_temporary_sample_data_directory_path, get_decompiled_files_path, \
    get_recovered_code_directory_path


class Cleanup(Action):
    def __init__(self, redis_session: redis.Redis, mongo_client: MongoClient,
                 mongo_db_name: str):
        self.redis_session = redis_session
        self.mongo_client = mongo_client
        self.recovered_project_path = get_recovered_code_directory_path()
        self.temporary_sample_data_directory = get_temporary_sample_data_directory_path()
        self.decompiled_files_path = get_decompiled_files_path()
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
