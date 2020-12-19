class Folders:
    def __init__(self, redis_session):
        self.redis_session = redis_session
        self.key = 'folders'

    def get_folder_models(self):
        folders_ids = self.redis_session.smembers(self.key)
        folders_models = []
        for folder_id in folders_ids:
            folders_models.append(FolderModel(folder_id=folder_id, redis_session=self.redis_session))
        return folders_models

    def add_folder_id(self, folder_id):
        self.redis_session.sadd(self.key, folder_id)


class Files:
    def __init__(self, redis_session):
        self.redis_session = redis_session
        self.key = 'files'

    def get_files_models(self):
        files_ids = self.redis_session.smembers(self.key)
        files_models = []
        for file_id in files_ids:
            files_models.append(FileModel(file_id=file_id, redis_session=self.redis_session))
        return files_models

    def add_file_id(self, file_id):
        self.redis_session.sadd(self.key, file_id)


class Functions:
    def __init__(self, redis_session):
        self.redis_session = redis_session
        self.key = 'functions'

    def get_functions_models(self):
        functions_ids = self.redis_session.smembers(self.key)
        functions_models = []
        for function_id in functions_ids:
            functions_models.append(FunctionModel(function_id=function_id, redis_session=self.redis_session))
        return functions_models

    def add_function_id(self, function_id):
        self.redis_session.sadd(self.key, function_id)


class FolderModel:
    def __init__(self, redis_session=None, contained_address=None, folder_id=None):
        self.redis_session = redis_session
        if folder_id:
            self.id = folder_id
            self.contained_address = folder_id.split(b':')[1]
        elif contained_address:
            self.id = b'folder:' + contained_address
            self.contained_address = contained_address
        self.contained_files_set_id = self.id + b':contained_files'
        self.calls_out_set_id = self.id + b':calls_out'
        self.calls_in_set_id = self.id + b':calls_in'

    def get_calls_out_folders_ids(self):
        return self.redis_session.smembers(self.calls_out_set_id)

    def get_calls_in_folders_ids(self):
        return self.redis_session.smembers(self.calls_in_set_id)

    def get_call_out_folders_models(self):
        called_folders_ids = self.get_calls_out_folders_ids()
        called_folders_models = []
        for folder_id in called_folders_ids:
            called_folders_models.append(FolderModel(folder_id=folder_id, redis_session=self.redis_session))
        return called_folders_models

    def get_call_in_folders_models(self):
        calling_folders_ids = self.get_calls_in_folders_ids()
        calling_folders_models = []
        for folder_id in calling_folders_ids:
            calling_folders_models.append(FolderModel(folder_id=folder_id, redis_session=self.redis_session))
        return calling_folders_models

    def add_init_folder_info(self, size):
        """
        Saves to the DB the initialized folder metadata: size of the folder, the id for the folders calls out set,
        the id for the folders calls in set, contained files set id,and contained address.
        Add the folder id to the set of folders ids.
        Add the first file into the set of contained files in the folder.
        """
        self.redis_session.hset(self.id, b'size', size)
        self.redis_session.hset(self.id, b'calls_out_set_id', self.calls_out_set_id)
        self.redis_session.hset(self.id, b'calls_in_set_id', self.calls_in_set_id)
        self.redis_session.hset(self.id, b'contained_files_set_id', self.contained_files_set_id)
        self.redis_session.hset(self.id, b'contained_address', self.contained_address)
        Folders(self.redis_session).add_folder_id(self.id)
        self.redis_session.sadd(self.contained_files_set_id, FileModel(contained_address=self.contained_address).id)

    def remove(self):
        self.redis_session.delete(self.calls_out_set_id)
        self.redis_session.delete(self.calls_in_set_id)
        self.redis_session.delete(self.contained_files_set_id)
        self.redis_session.srem('folders', self.id)
        self.redis_session.delete(self.id)

    def recursion_init(self, size):
        self.add_init_folder_info(size)

    def add_edge(self, called_function_address):
        """
        Add to the calls out set the called folder id,
        Add to the calls in set of the called folder the calling folder id.
        """
        called_folder_model = FolderModel(contained_address=called_function_address)
        self.redis_session.sadd(self.calls_out_set_id, called_folder_model.id)
        self.redis_session.sadd(called_folder_model.calls_in_set_id, self.id)


class FileModel:
    def __init__(self, redis_session=None, contained_address=None, file_id=None):
        self.redis_session = redis_session
        if file_id:
            self.id = file_id
            self.contained_address = file_id.split(b':')[1]
        elif contained_address:
            self.id = b'file:' + contained_address
            self.contained_address = contained_address
        self.folder_id = b'folder:' + self.contained_address
        self.contained_functions_set_id = self.id + b':contained_functions'
        self.calls_out_set_id = self.id + b':calls_out'
        self.calls_in_set_id = self.id + b':calls_in'

    def get_calls_out_files_ids(self):
        return self.redis_session.smembers(self.calls_out_set_id)

    def get_calls_in_files_ids(self):
        return self.redis_session.smembers(self.calls_in_set_id)

    def get_call_out_files_models(self):
        called_files_ids = self.get_calls_out_files_ids()
        called_files_models = []
        for file_id in called_files_ids:
            called_files_models.append(FileModel(file_id=file_id, redis_session=self.redis_session))
        return called_files_models

    def get_call_in_files_models(self):
        calling_files_ids = self.get_calls_in_files_ids()
        calling_files_models = []
        for file_id in calling_files_ids:
            calling_files_models.append(FileModel(file_id=file_id, redis_session=self.redis_session))
        return calling_files_models

    def get_parent_folder_model(self):
        return FolderModel(folder_id=self.folder_id, redis_session=self.redis_session)

    def add_init_file_info(self, size):
        """
        Saves to the DB the initialized file metadata: size of the file, the id for the files calls out set,
        the id for the files calls in set, folder id, contained functions set id,and contained address.
        Add the file id to the set of file ids.
        Add the first function into the set of contained functions in the file.
        """
        self.redis_session.hset(self.id, b'size', size)
        self.redis_session.hset(self.id, b'calls_out_set_id', self.calls_out_set_id)
        self.redis_session.hset(self.id, b'calls_in_set_id', self.calls_in_set_id)
        self.redis_session.hset(self.id, b'contained_functions_set_id', self.contained_functions_set_id)
        self.redis_session.hset(self.id, b'contained_address', self.contained_address)
        self.redis_session.hset(self.id, b'folder_id', self.folder_id)
        Files(self.redis_session).add_file_id(self.id)
        self.redis_session.sadd(self.contained_functions_set_id, FunctionModel(address=self.contained_address).id)

    def recursion_init(self, size):
        """
        Init the files metadata and initialize folders nodes.
        """
        self.add_init_file_info(size)
        folder_model = FolderModel(folder_id=self.folder_id, redis_session=self.redis_session)
        folder_model.recursion_init(size)

    def add_edge(self, called_function_address):
        """
        Add to the calls out set the called file id,
        Add to the calls in set of the called file the calling file id.
        """
        called_file_model = FileModel(contained_address=called_function_address)
        self.redis_session.sadd(self.calls_out_set_id, called_file_model.id)
        self.redis_session.sadd(called_file_model.calls_in_set_id, self.id)

    def recursion_add_edge(self, called_function_address):
        """
        Add edge to the called file and call add edge for folder
        The edged contained in the files relations need to exist inside the folder relations
        """
        self.add_edge(called_function_address)
        folder_model = FolderModel(folder_id=self.folder_id, redis_session=self.redis_session)
        folder_model.add_edge(called_function_address=called_function_address)

    def remove(self):
        self.redis_session.delete(self.calls_out_set_id)
        self.redis_session.delete(self.calls_in_set_id)
        self.redis_session.delete(self.contained_functions_set_id)
        self.redis_session.srem('files', self.id)
        self.redis_session.delete(self.id)

    def recursion_remove(self):
        folder_model = FolderModel(folder_id=self.folder_id, redis_session=self.redis_session)
        folder_model.remove()
        self.remove()


class FunctionModel:
    def __init__(self, redis_session=None, address=None, function_id=None):
        """
        id: string
        contained_address: string
        file_id: string (id to hashes)
        calls_out_set_id: string (set id)
        calls_in_set_id: string (set id)
        """
        self.redis_session = redis_session
        if function_id:
            self.id = function_id
            self.contained_address = function_id.split(b':')[1]
        elif address:
            self.id = b'function:' + address
            self.contained_address = address

        self.file_id = b'file:' + self.contained_address
        self.calls_out_set_id = self.id + b':calls_out'
        self.calls_in_set_id = self.id + b':calls_in'
        self.file_id = b'file:' + self.contained_address

    def get_calls_out_functions_ids(self):
        return self.redis_session.smembers(self.calls_out_set_id)

    def get_calls_in_functions_ids(self):
        return self.redis_session.smembers(self.calls_in_set_id)

    def get_call_out_functions_models(self):
        called_functions_ids = self.get_calls_out_functions_ids()
        called_functions_models = []
        for function_id in called_functions_ids:
            called_functions_models.append(FunctionModel(function_id=function_id, redis_session=self.redis_session))
        return called_functions_models

    def get_call_in_functions_models(self):
        calling_functions_ids = self.get_calls_in_functions_ids()
        calling_functions_models = []
        for function_id in calling_functions_ids:
            calling_functions_models.append(FunctionModel(function_id=function_id, redis_session=self.redis_session))
        return calling_functions_models

    def get_parent_file_model(self):
        return FileModel(file_id=self.file_id, redis_session=self.redis_session)

    def add_init_function_info(self, size):
        """
        Saves to the DB the initialized function metadata: size of the function, the id for the functions calls out set,
        the id for the functions calls in set, file id and contained address.
        Add the function id to the set of functions ids in the DB.
        """
        self.redis_session.hset(self.id, b'size', size)
        self.redis_session.hset(self.id, b'calls_out_set_id', self.calls_out_set_id)
        self.redis_session.hset(self.id, b'calls_in_set_id', self.calls_in_set_id)
        self.redis_session.hset(self.id, b'file_id', self.file_id)
        self.redis_session.hset(self.id, b'contained_address', self.contained_address)
        Functions(self.redis_session).add_function_id(self.id)

    def recursion_init(self, size):
        """
        Init the function metadata and initialize files nodes.
        """
        self.add_init_function_info(size)
        file_repo_actions = FileModel(file_id=self.file_id, redis_session=self.redis_session)
        file_repo_actions.recursion_init(size)

    def add_edge(self, called_function_address):
        """
        Add to the calls out set the called function id,
        Add to the calls in set of the called function the calling function id.
        """
        called_function_model = FunctionModel(address=called_function_address)
        self.redis_session.sadd(self.calls_out_set_id, called_function_model.id)
        self.redis_session.sadd(called_function_model.calls_in_set_id, self.id)


def add_values_to_set(redis_session, key, values):
    for value in values:
        redis_session.sadd(key, value)
