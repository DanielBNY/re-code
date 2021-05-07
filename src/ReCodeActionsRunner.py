from pymongo import MongoClient
from os.path import exists
from pathlib import Path
import multiprocessing
import os.path
import shutil
import redis
import time

from src.ReCodeActions.FunctionsGraphExtractor.FunctionsGraphExtractor import FunctionsGraphExtractor
from src.ReCodeActions.ClusterFilesAndFolders.ClusterFilesAndFolders import ClusterFilesAndFolders
from src.ReCodeActions.DirectedTreeExtractor.DirectedTreeExtractor import DirectedTreeExtractor
from src.ReCodeActions.RecoveredCodeBuild.RecoveredCodeBuild import RecoveredCodeBuild
from src.ReCodeActions.ImportBinaryData.ImportBinaryData import ImportBinaryData
from src.ReCodeActions.ConnectTrees.ConnectTrees import ConnectTrees
from src.ReCodeActions.Cleanup.Cleanup import Cleanup
from src.AbstractClasses import Action

MULTIPLE_DECOMPILED_FILES_DIRECTORY = "MultipleDecompiledFiles"
RECOVERED_CODE_DIRECTORY_NAME = "RecoveredCodeOutput"
RETDEC_DECOMPILER_FOLDER_NAME = "RetdecDecompiler"
FUNCTIONS_INFO_COLLECTION_NAME = "FunctionsInfo"
FUNCTIONS_INFO_FILE_NAME = 'functions_info.json'
TEMPORARY_SAMPLE_DATA_DIRECTORY = ".SampleData"
SAMPLES_DIR_NAME = "Samples"
MONGO_DB_NAME = "re-code"


class ReCodeActionsRunner(Action):
    def __init__(self, redis_ip: str, mongo_ip: str, file_name_to_analyze: str, max_number_of_max_files_in_folder=4,
                 max_file_size=200, mongo_db_port=27017, number_of_processes=None):
        self.functions_info_collection_name = FUNCTIONS_INFO_COLLECTION_NAME
        self.max_number_of_max_files_in_folder = max_number_of_max_files_in_folder
        self.max_file_size = max_file_size
        if not number_of_processes:
            self.number_of_processes = multiprocessing.cpu_count()
        else:
            self.number_of_processes = number_of_processes
        self.redis_session = redis.Redis(redis_ip)
        self.mongo_client = MongoClient(mongo_ip, mongo_db_port)
        current_working_directory = Path(os.getcwd())
        parent_cwd = current_working_directory.parent.absolute()
        self.file_path_to_analyze = os.path.join(parent_cwd, SAMPLES_DIR_NAME, file_name_to_analyze)
        self.recovered_project_path = os.path.join(parent_cwd, RECOVERED_CODE_DIRECTORY_NAME)
        self.decompiler_path = os.path.join(parent_cwd, RETDEC_DECOMPILER_FOLDER_NAME, "bin",
                                            "retdec-decompiler.py")
        self.temporary_sample_data_directory = os.path.join(parent_cwd, TEMPORARY_SAMPLE_DATA_DIRECTORY)
        self.functions_info_file_path = os.path.join(self.temporary_sample_data_directory,
                                                     FUNCTIONS_INFO_FILE_NAME)
        self.decompiled_files_path = os.path.join(self.temporary_sample_data_directory,
                                                  MULTIPLE_DECOMPILED_FILES_DIRECTORY)
        self.mongo_db_name = MONGO_DB_NAME

    def run(self):
        Cleanup(redis_session=self.redis_session, mongo_client=self.mongo_client,
                file_path_to_analyze=self.file_path_to_analyze,
                functions_info_file_path=self.functions_info_file_path,
                temporary_sample_data_directory=self.temporary_sample_data_directory,
                decompiled_files_path=self.decompiled_files_path,
                decompiler_path=self.decompiler_path,
                mongo_db_name=self.mongo_db_name,
                recovered_project_path=self.recovered_project_path).run()

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

        RecoveredCodeBuild(recovered_project_path=self.recovered_project_path.encode(),
                           redis_session=self.redis_session).run()


if __name__ == "__main__":
    # Basic run
    file_name = input("Please Enter the Samples/{file name} to analyze:    (try bin_ls for test)\n")
    start_flow_time = time.time()
    ReCodeActionsRunner(redis_ip='localhost', mongo_ip='localhost',
                        file_name_to_analyze=file_name).run()
    end_flow_time = time.time()
    print(f"total time    {end_flow_time - start_flow_time}")
