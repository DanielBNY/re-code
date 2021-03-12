import redis
from FunctionsGraphExtractor import FunctionsGraphExtractor
from CallTreeExtractor import CallTreeExtractor
from ClusterFilesAndFolders import ClusterFilesAndFolders
from BinaryExtractor import BinaryExtractor
from pymongo import MongoClient
from BuildSampleStructure import BuildSampleStructure
import shutil, os.path
from ImportRetdecData import ImportRetdecData
from ClusterTrees import ClusterTrees
import multiprocessing

RECOVERED_CODE_DIRECTORY_NAME = "RecoveredCodeOutput"
FUNCTIONS_INFO_COLLECTION_NAME = "FunctionsInfo"
MONGO_DB_NAME = "re-code"


class ExtractorsManager:
    def __init__(self, redis_ip: str, mongo_ip: str, decompiler_path: str,
                 file_path_to_analyze: str, max_number_of_max_files_in_folder: int, max_file_size: int,
                 functions_info_file_path: str, decompiled_files_path: str, mongo_db_port=27017,
                 number_of_processes=None):
        self.functions_info_collection_name = FUNCTIONS_INFO_COLLECTION_NAME
        self.file_path_to_analyze = file_path_to_analyze
        self.max_number_of_max_files_in_folder = max_number_of_max_files_in_folder
        self.max_file_size = max_file_size
        if not number_of_processes:
            self.number_of_processes = multiprocessing.cpu_count()
        else:
            self.number_of_processes = number_of_processes
        self.redis_session = redis.Redis(redis_ip)
        self.mongo_client = MongoClient(mongo_ip, mongo_db_port)
        self.recovered_project_path = os.path.join(os.getcwd(), RECOVERED_CODE_DIRECTORY_NAME)
        self.decompiler_path = decompiler_path
        self.functions_info_file_path = functions_info_file_path
        self.decompiled_files_path = decompiled_files_path
        self.mongo_db_name = MONGO_DB_NAME

    def cleanup(self):
        if os.path.exists(self.recovered_project_path):
            shutil.rmtree(self.recovered_project_path)
        os.mkdir(self.recovered_project_path)
        self.redis_session.flushdb()
        self.mongo_client.drop_database(self.mongo_db_name)

    def flow(self):
        self.cleanup()
        bin_ex = BinaryExtractor(self.file_path_to_analyze, self.redis_session)
        bin_ex.analyze_all_functions_calls()
        import_retdec_data = ImportRetdecData(redis_session=self.redis_session,
                                              binary_extractor=bin_ex, analyzed_file=self.file_path_to_analyze,
                                              number_of_processes=self.number_of_processes,
                                              decompiler_path=self.decompiler_path,
                                              decompiled_files_path=self.decompiled_files_path)
        import_retdec_data.run()
        bin_ex.extract_functions_info(self.functions_info_file_path,
                                      imported_collection_name=self.functions_info_collection_name,
                                      mongo_db_name=self.mongo_db_name)
        FunctionsGraphExtractor(redis_session=self.redis_session, mongodb_client=self.mongo_client,
                                functions_info_collection_name=self.functions_info_collection_name,
                                mongo_db_name=self.mongo_db_name).run()
        CallTreeExtractor(self.redis_session).run()
        ClusterTrees(redis_session=self.redis_session).run()
        ClusterFilesAndFolders(redis_session=self.redis_session, max_file_size=self.max_file_size,
                               max_number_of_max_files_in_folder=self.max_number_of_max_files_in_folder).run()
        BuildSampleStructure(recovered_project_path=self.recovered_project_path.encode(),
                             redis_session=self.redis_session).run()
