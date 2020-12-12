from models import FunctionInfo, FileInfo, FolderInfo


class RepoActions:
    def __init__(self, redis_session):
        self.redis_session = redis_session

    def models_initialization(self, size, address):
        """
        At the start each function is contained in her file and her folder and in the process of clustering
        files and folders are joined o create the recovered file structure
        """
        fnc_info = FunctionInfo(size, address)
        file_info = FileInfo(size, address)
        folder_info = FolderInfo(size, address)
        self.redis_session.hset(f"function:{address}", "file_id", fnc_info.file_id)
        self.redis_session.hset(fnc_info.file_id, "contained_functions_set_id", file_info.contained_functions_set_id)
        self.redis_session.hset(fnc_info.file_id, "folder_id", file_info.folder_id)
        self.redis_session.hset(file_info.folder_id, "contained_files_set_id", folder_info.contained_files_set_id)
        self.redis_session.sadd("functions", f"function:{address}")
        self.redis_session.sadd("files", fnc_info.file_id)
        self.redis_session.sadd("folders", file_info.folder_id)
        self.initialize_calls_sets_ids(address)
        self.initialize_models_size(address, size)

    def initialize_calls_sets_ids(self, address):
        """

        """
        names = ["function", "file", "folder"]
        for name in names:
            self.redis_session.hset(f"{name}:{address}", "calls_out_set_id", f"{name}:{address}:calls_out")
            self.redis_session.hset(f"{name}:{address}", "calls_in_set_id", f"{name}:{address}:calls_out")

    def initialize_models_size(self, address, size):
        """
        Set the function, file and folder size
        """
        names = ["function", "file", "folder"]
        for name in names:
            self.redis_session.hset(f"{name}:{address}", "size", size)
