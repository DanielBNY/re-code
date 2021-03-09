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
import conf


class ExtractorsManager:
    def __init__(self, recovered_project_path: str, redis_ip: str, mongo_ip: str, decompiler_path: str,
                 mongo_db_port=27017):
        self.redis_session = redis.Redis(redis_ip)
        self.mongo_client = MongoClient(mongo_ip, mongo_db_port)
        self.recovered_project_path = recovered_project_path
        self.decompiler_path = decompiler_path

    def cleanup(self):
        if os.path.exists(self.recovered_project_path):
            shutil.rmtree(self.recovered_project_path)
        os.mkdir(self.recovered_project_path)
        self.redis_session.flushdb()
        self.mongo_client.drop_database(conf.mongo_db["db_name"])

    def flow(self, file_path_to_analyze, max_number_of_max_files_in_folder, max_file_size, number_of_processes):
        self.cleanup()
        bin_ex = BinaryExtractor(file_path_to_analyze, self.redis_session)
        bin_ex.analyze_all_functions_calls()
        import_retdec_data = ImportRetdecData(redis_session=self.redis_session,
                                              binary_extractor=bin_ex, analyzed_file=file_path_to_analyze,
                                              number_of_processes=number_of_processes,
                                              decompiler_path=self.decompiler_path,
                                              decompiled_files_path=conf.retdec_decompiler["decompiled_file_path"])
        import_retdec_data.run()
        bin_ex.extract_functions_info('/tmp/analyzed', imported_collection_name="FunctionsInfo")
        FunctionsGraphExtractor(self.redis_session, self.mongo_client).run()
        CallTreeExtractor(self.redis_session).run()
        ClusterTrees(redis_session=self.redis_session).run()
        ClusterFilesAndFolders(redis_session=self.redis_session, max_file_size=max_file_size,
                               max_number_of_max_files_in_folder=max_number_of_max_files_in_folder).run()
        BuildSampleStructure(recovered_project_path=self.recovered_project_path.encode(),
                             redis_session=self.redis_session).run()
