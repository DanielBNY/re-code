from pymongo import MongoClient
from os.path import exists
from os import mkdir
import shutil
import redis

from PathSource import get_temporary_sample_data_directory_path, get_decompiled_files_path, \
    get_recovered_code_directory_path, get_out_directory_path, get_file_to_analyze_directory_path


def db_cleanup(redis_session: redis.Redis, mongo_client: MongoClient, mongo_db_name):
    """
    Flush the redisDB.
    Drop the mongoDB.
    """
    redis_session.flushdb()
    mongo_client.drop_database(mongo_db_name)


def folders_recreation():
    """
    Remove and recreate the general output folder where the recovered zip and code.
    Remove and recreate the recovered project folder.
    Remove and recreate the temporary sample data folder.
    Remove and recreate the decompiled files folder.
    Remove and recreate the analyzed binary directory.
    """
    remove_and_recreate(get_out_directory_path())
    remove_and_recreate(get_recovered_code_directory_path())
    remove_and_recreate(get_temporary_sample_data_directory_path())
    remove_and_recreate(get_decompiled_files_path())
    remove_and_recreate(get_file_to_analyze_directory_path())


def remove_and_recreate(path):
    if exists(path):
        shutil.rmtree(path)
    mkdir(path)
