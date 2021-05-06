import redis
from src.ReCodeActions.FunctionsGraphExtractor import FunctionsGraphExtractor
from src.ReCodeActions.DirectedTreeExtractor import DirectedTreeExtractor
from src.ReCodeActions.ClusterFilesAndFolders import ClusterFilesAndFolders
from pymongo import MongoClient
from src.ReCodeActions.RecoveredCodeBuild import ReCodeBuild
import shutil, os.path
from src.ReCodeActions.ImportBinaryData import ImportBinaryData
from src.ReCodeActions.ConnectTrees import ConnectTrees
import multiprocessing
import time
from src.ReCodeActions.AbstractClasses import Action
from os.path import exists

RECOVERED_CODE_DIRECTORY_NAME = "RecoveredCodeOutput"
FUNCTIONS_INFO_COLLECTION_NAME = "FunctionsInfo"
MONGO_DB_NAME = "re-code"
TEMPORARY_SAMPLE_DATA_DIRECTORY = ".SampleData"
MULTIPLE_DECOMPILED_FILES_DIRECTORY = "MultipleDecompiledFiles"
FUNCTIONS_INFO_FILE_NAME = 'functions_info.json'
SAMPLES_DIR_NAME = "Samples"
RETDEC_DECOMPILER_FOLDER_NAME = "RetdecDecompiler"


class ReCodeActionsRunner(Action):
    def __init__(self, redis_ip: str, mongo_ip: str, file_name_to_analyze: str, max_number_of_max_files_in_folder=4,
                 max_file_size=200,
                 mongo_db_port=27017, number_of_processes=None):
        self.functions_info_collection_name = FUNCTIONS_INFO_COLLECTION_NAME
        self.max_number_of_max_files_in_folder = max_number_of_max_files_in_folder
        self.max_file_size = max_file_size
        if not number_of_processes:
            self.number_of_processes = multiprocessing.cpu_count()
        else:
            self.number_of_processes = number_of_processes
        self.redis_session = redis.Redis(redis_ip)
        self.mongo_client = MongoClient(mongo_ip, mongo_db_port)
        current_working_directory = os.getcwd()
        self.file_path_to_analyze = os.path.join(current_working_directory, SAMPLES_DIR_NAME, file_name_to_analyze)
        self.recovered_project_path = os.path.join(current_working_directory, RECOVERED_CODE_DIRECTORY_NAME)
        self.decompiler_path = os.path.join(current_working_directory, RETDEC_DECOMPILER_FOLDER_NAME, "bin",
                                            "retdec-decompiler.py")
        self.temporary_sample_data_directory = os.path.join(current_working_directory, TEMPORARY_SAMPLE_DATA_DIRECTORY)
        self.functions_info_file_path = os.path.join(self.temporary_sample_data_directory,
                                                     FUNCTIONS_INFO_FILE_NAME)
        self.decompiled_files_path = os.path.join(self.temporary_sample_data_directory,
                                                  MULTIPLE_DECOMPILED_FILES_DIRECTORY)
        self.mongo_db_name = MONGO_DB_NAME

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

    def cleanup(self):
        self.re_create_recovered_project_path()
        self.re_create_temporary_sample_directories()
        self.decompiled_files_cleanup()
        self.redis_session.flushdb()
        self.mongo_client.drop_database(self.mongo_db_name)

    def run(self):
        self.cleanup()
        ImportBinaryData(redis_session=self.redis_session,
                         file_path_to_analyze=self.file_path_to_analyze, analyzed_file=self.file_path_to_analyze,
                         number_of_processes=self.number_of_processes,
                         decompiler_path=self.decompiler_path,
                         decompiled_files_path=self.decompiled_files_path,
                         functions_info_file_path=self.functions_info_file_path,
                         imported_collection_name=self.functions_info_collection_name,
                         mongo_db_name=self.mongo_db_name).run()

        FunctionsGraphExtractor(redis_session=self.redis_session, mongodb_client=self.mongo_client,
                                functions_info_collection_name=self.functions_info_collection_name,
                                mongo_db_name=self.mongo_db_name).run()

        DirectedTreeExtractor(self.redis_session).run()

        ConnectTrees(redis_session=self.redis_session).run()

        ClusterFilesAndFolders(redis_session=self.redis_session, max_file_size=self.max_file_size,
                               max_number_of_max_files_in_folder=self.max_number_of_max_files_in_folder).run()

        ReCodeBuild(recovered_project_path=self.recovered_project_path.encode(),
                    redis_session=self.redis_session).run()


if __name__ == "__main__":
    # Basic run
    file_name = input("Please Enter the Samples/{file name} to analyze:    (try bin_ls for test)\n")
    start_flow_time = time.time()
    ReCodeActionsRunner(redis_ip='localhost', mongo_ip='localhost',
                        file_name_to_analyze=file_name).run()
    end_flow_time = time.time()
    print(f"total time    {end_flow_time - start_flow_time}")
