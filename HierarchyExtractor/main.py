import redis
from FunctionsGraphExtractor import FunctionsGraphExtractor
from CallTreeExtractor import CallTreeExtractor
from ClusterFilesAndFolders import ClusterFilesAndFolders
from BinaryExtractor import BinaryExtractor
from FunctionsInfoExtractor import FunctionsInfoExtractor
from pymongo import MongoClient

r = redis.Redis('localhost')
r.flushdb()
path_to_analyze = ''
bin_ex = BinaryExtractor(path_to_analyze)
FunctionsInfoExtractor(bin_ex, 'Rinu').run()
client = MongoClient("localhost", 27017)
FunctionsGraphExtractor(r, client).run()
CallTreeExtractor(r).run()
ClusterFilesAndFolders(redis_session=redis.Redis('localhost'), max_file_size=700,
                       max_number_of_max_files_in_folder=10).run()
