from models import FunctionInfo, FileInfo, FolderInfo


class FolderRepoActions:
    def __init__(self, contained_address, redis_session):
        self.redis_session = redis_session
        self.folder_info = FolderInfo(contained_address)

    def add_init_folder_info(self, size):
        """
        Saves to the DB the initialized folder metadata: size of the folder, the id for the folders calls out set,
        the id for the folders calls in set, contained files set id,and contained address.
        Add the folder id to the set of folders ids.
        Add the first file into the set of contained files in the folder.
        """
        self.redis_session.hset(self.folder_info.id, "size", size)
        self.redis_session.hset(self.folder_info.id, "calls_out_set_id", self.folder_info.calls_out_set_id)
        self.redis_session.hset(self.folder_info.id, "calls_in_set_id", self.folder_info.calls_in_set_id)
        self.redis_session.hset(self.folder_info.id, "contained_files_set_id", self.folder_info.contained_files_set_id)
        self.redis_session.hset(self.folder_info.id, "contained_address",
                                self.folder_info.contained_address)
        self.redis_session.sadd("folders", self.folder_info.id)
        self.redis_session.sadd(self.folder_info.contained_files_set_id,
                                FileInfo(self.folder_info.contained_address).id)

    def recursion_init(self, size):
        self.add_init_folder_info(size)

    def add_edge(self, called_function_address):
        """
        Add to the calls out set the called folder id,
        Add to the calls in set of the called folder the calling folder id.
        """
        called_folder_info = FolderInfo(called_function_address)
        self.redis_session.sadd(self.folder_info.calls_out_set_id, called_folder_info.id)
        self.redis_session.sadd(called_folder_info.calls_in_set_id, self.folder_info.id)


class FileRepoActions:
    def __init__(self, contained_address, redis_session):
        self.redis_session = redis_session
        self.file_info = FileInfo(contained_address)

    def add_init_file_info(self, size):
        """
        Saves to the DB the initialized file metadata: size of the file, the id for the files calls out set,
        the id for the files calls in set, folder id, contained functions set id,and contained address.
        Add the file id to the set of file ids.
        Add the first function into the set of contained functions in the file.
        """
        self.redis_session.hset(self.file_info.id, "size", size)
        self.redis_session.hset(self.file_info.id, "calls_out_set_id", self.file_info.calls_out_set_id)
        self.redis_session.hset(self.file_info.id, "calls_in_set_id", self.file_info.calls_in_set_id)
        self.redis_session.hset(self.file_info.id, "contained_functions_set_id",
                                self.file_info.contained_functions_set_id)
        self.redis_session.hset(self.file_info.id, "contained_address",
                                self.file_info.contained_address)
        self.redis_session.hset(self.file_info.id, "folder_id", self.file_info.folder_id)
        self.redis_session.sadd("files", self.file_info.id)
        self.redis_session.sadd(self.file_info.contained_functions_set_id,
                                FunctionInfo(self.file_info.contained_address).id)

    def recursion_init(self, size):
        """
        Init the files metadata and initialize folders nodes.
        """
        self.add_init_file_info(size)
        folder_repo_actions = FolderRepoActions(self.file_info.contained_address, self.redis_session)
        folder_repo_actions.recursion_init(size)

    def add_edge(self, called_function_address):
        """
        Add to the calls out set the called file id,
        Add to the calls in set of the called file the calling file id.
        """
        called_file_info = FileInfo(called_function_address)
        self.redis_session.sadd(self.file_info.calls_out_set_id, called_file_info.id)
        self.redis_session.sadd(called_file_info.calls_in_set_id, self.file_info.id)

    def recursion_add_edge(self, called_function_address):
        """
        Add edge to the called file and call add edge for folder
        The edged contained in the files relations need to exist inside the folder relations
        """
        self.add_edge(called_function_address)
        folder_repo_actions = FolderRepoActions(self.file_info.contained_address, self.redis_session)
        folder_repo_actions.add_edge(called_function_address)


class FunctionRepoActions:
    def __init__(self, address, redis_session):
        self.redis_session = redis_session
        self.function_info = FunctionInfo(address)

    def add_init_function_info(self, size):
        """
        Saves to the DB the initialized function metadata: size of the function, the id for the functions calls out set,
        the id for the functions calls in set, file id and contained address.
        Add the function id to the set of functions ids in the DB.
        """
        self.redis_session.hset(self.function_info.id, "size", size)
        self.redis_session.hset(self.function_info.id, "calls_out_set_id", self.function_info.calls_out_set_id)
        self.redis_session.hset(self.function_info.id, "calls_in_set_id", self.function_info.calls_in_set_id)
        self.redis_session.hset(self.function_info.id, "file_id", self.function_info.file_id)
        self.redis_session.hset(self.function_info.id, "contained_address", self.function_info.contained_address)
        self.redis_session.sadd("functions", self.function_info.id)

    def recursion_init(self, size):
        """
        Init the function metadata and initialize files nodes.
        """
        self.add_init_function_info(size)
        file_repo_actions = FileRepoActions(self.function_info.contained_address, self.redis_session)
        file_repo_actions.recursion_init(size)

    def add_edge(self, called_function_address):
        """
        Add to the calls out set the called function id,
        Add to the calls in set of the called function the calling function id.
        """
        called_function_info = FunctionInfo(called_function_address)
        self.redis_session.sadd(self.function_info.calls_out_set_id, called_function_info.id)
        self.redis_session.sadd(called_function_info.calls_in_set_id, self.function_info.id)
