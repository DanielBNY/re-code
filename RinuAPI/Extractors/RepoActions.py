from models import FunctionInfo, FileInfo, FolderInfo


class FolderRepoActions:
    def __init__(self, contained_address, redis_session):
        self.redis_session = redis_session
        self.folder_info = FolderInfo(contained_address)

    def add_init_folder_info(self, size):
        self.redis_session.hset(self.folder_info.id, "size", size)
        self.redis_session.hset(self.folder_info.id, "calls_out_set_id", self.folder_info.calls_out_set_id)
        self.redis_session.hset(self.folder_info.id, "calls_in_set_id", self.folder_info.calls_in_set_id)
        self.redis_session.hset(self.folder_info.id, "contained_files_set_id", self.folder_info.contained_files_set_id)
        self.redis_session.sadd("folders", self.folder_info.id)

    def recursion_init(self, size):
        self.add_init_folder_info(size)


class FileRepoActions:
    def __init__(self, contained_address, redis_session):
        self.redis_session = redis_session
        self.file_info = FileInfo(contained_address)

    def add_init_file_info(self, size):
        self.redis_session.hset(self.file_info.id, "size", size)
        self.redis_session.hset(self.file_info.id, "calls_out_set_id", self.file_info.calls_out_set_id)
        self.redis_session.hset(self.file_info.id, "calls_in_set_id", self.file_info.calls_in_set_id)
        self.redis_session.hset(self.file_info.id, "contained_functions_set_id",
                                self.file_info.contained_functions_set_id)
        self.redis_session.hset(self.file_info.id, "folder_id", self.file_info.folder_id)
        self.redis_session.sadd("files", self.file_info.id)

    def recursion_init(self, size):
        self.add_init_file_info(size)
        folder_repo_actions = FolderRepoActions(self.file_info.id, self.redis_session)
        folder_repo_actions.recursion_init(size)


class FunctionRepoActions:
    def __init__(self, address, redis_session):
        self.redis_session = redis_session
        self.function_info = FunctionInfo(address)

    def add_init_function_info(self, size):
        self.redis_session.hset(self.function_info.id, "size", size)
        self.redis_session.hset(self.function_info.id, "calls_out_set_id", self.function_info.calls_out_set_id)
        self.redis_session.hset(self.function_info.id, "calls_in_set_id", self.function_info.calls_in_set_id)
        self.redis_session.hset(self.function_info.id, "file_id", self.function_info.file_id)
        self.redis_session.sadd("functions", self.function_info.id)

    def recursion_init(self, size):
        self.add_init_function_info(size)
        file_repo_actions = FileRepoActions(self.function_info.id, self.redis_session)
        file_repo_actions.recursion_init(size)
