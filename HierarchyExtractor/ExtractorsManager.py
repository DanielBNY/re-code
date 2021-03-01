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
    def __init__(self, output_directory):
        self.redis_session = redis.Redis('localhost')
        self.mongo_client = MongoClient("localhost", 27017)
        self.output_directory = output_directory

    def cleanup(self):
        if os.path.exists(self.output_directory):
            shutil.rmtree(self.output_directory)
        os.mkdir(self.output_directory)
        self.redis_session.flushdb()
        self.mongo_client.drop_database(conf.mongo_db["db_name"])

    def flow(self, file_path_to_analyze, max_number_of_max_files_in_folder, max_file_size, number_of_processes):
        self.cleanup()
        bin_ex = BinaryExtractor(file_path_to_analyze, self.redis_session)
        bin_ex.analyze_all_functions_calls()
        import_retdec_data = ImportRetdecData(redis_session=self.redis_session,
                                              binary_extractor=bin_ex, analyzed_file=file_path_to_analyze,
                                              number_of_processes=number_of_processes)
        import_retdec_data.run()
        bin_ex.extract_functions_info('/tmp/analyzed', imported_collection_name="FunctionsInfo")
        FunctionsGraphExtractor(self.redis_session, self.mongo_client).run()
        CallTreeExtractor(self.redis_session).run()
        ClusterTrees(redis_session=self.redis_session).run()
        ClusterFilesAndFolders(redis_session=redis.Redis('localhost'), max_file_size=max_file_size,
                               max_number_of_max_files_in_folder=max_number_of_max_files_in_folder).run()
        BuildSampleStructure(self.output_directory.encode(), self.redis_session).run()
