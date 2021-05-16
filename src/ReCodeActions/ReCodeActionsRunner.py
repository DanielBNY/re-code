from pymongo import MongoClient
import multiprocessing
import redis
import time

from src.ReCodeActions.FunctionsGraphExtractor.FunctionsGraphExtractor import FunctionsGraphExtractor
from src.ReCodeActions.ClusterFilesAndFolders.ClusterFilesAndFolders import ClusterFilesAndFolders
from src.ReCodeActions.DirectedTreeExtractor.DirectedTreeExtractor import DirectedTreeExtractor
from src.ReCodeActions.RecoveredCodeBuild.RecoveredCodeBuild import RecoveredCodeBuild
from src.ReCodeActions.ImportBinaryData.ImportBinaryData import ImportBinaryData
from src.ReCodeActions.ConnectTrees.ConnectTrees import ConnectTrees
from src.Cleanup import db_cleanup
from src.ReCodeActions.AbstractClasses import Action

FUNCTIONS_INFO_COLLECTION_NAME = "FunctionsInfo"
MONGO_DB_NAME = "re-code"


class ReCodeActionsRunner(Action):
    def __init__(self, redis_host: str, mongo_host: str, file_name_to_analyze: str, max_number_of_max_files_in_folder=4,
                 max_file_size=200, mongo_db_port=27017, number_of_processes=None):
        self.functions_info_collection_name = FUNCTIONS_INFO_COLLECTION_NAME
        self.max_number_of_max_files_in_folder = max_number_of_max_files_in_folder
        self.max_file_size = max_file_size
        if not number_of_processes:
            self.number_of_processes = multiprocessing.cpu_count()
        else:
            self.number_of_processes = number_of_processes
        self.redis_session = redis.Redis(host=redis_host)
        self.mongo_client = MongoClient(host=mongo_host, port=mongo_db_port)
        self.mongo_db_name = MONGO_DB_NAME
        self.file_name_to_analyze = file_name_to_analyze

    def run(self):
        db_cleanup(redis_session=self.redis_session, mongo_client=self.mongo_client,
                   mongo_db_name=self.mongo_db_name)

        ImportBinaryData(redis_session=self.redis_session,
                         number_of_processes=self.number_of_processes,
                         imported_collection_name=self.functions_info_collection_name,
                         mongo_db_name=self.mongo_db_name, file_name_to_analyze=self.file_name_to_analyze).run()

        FunctionsGraphExtractor(redis_session=self.redis_session, mongodb_client=self.mongo_client,
                                functions_info_collection_name=self.functions_info_collection_name,
                                mongo_db_name=self.mongo_db_name).run()

        DirectedTreeExtractor(self.redis_session).run()

        ConnectTrees(redis_session=self.redis_session).run()

        ClusterFilesAndFolders(redis_session=self.redis_session, max_file_size=self.max_file_size,
                               max_number_of_max_files_in_folder=self.max_number_of_max_files_in_folder).run()

        RecoveredCodeBuild(redis_session=self.redis_session).run()


if __name__ == "__main__":
    # Basic run
    file_name = input("Please Enter the Samples/{file name} to analyze:    (try bin_ls for test)\n")
    start_flow_time = time.time()
    ReCodeActionsRunner(redis_ip='localhost', mongo_ip='localhost',
                        file_name_to_analyze=file_name).run()
    end_flow_time = time.time()
    print(f"total time    {end_flow_time - start_flow_time}")
