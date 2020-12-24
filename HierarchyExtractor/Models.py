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

    def get_average_file_size(self):
        files_models = self.get_files_models()
        size_sum = 0
        for file_model in files_models:
            size_sum += file_model.get_size()
        return size_sum / float(len(files_models))

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

    def get_average_file_size(self):
        functions_models = self.get_functions_models()
        size_sum = 0
        for function_model in functions_models:
            size_sum += function_model.get_size()
        return size_sum / float(len(functions_models))

    def add_function_id(self, function_id):
        self.redis_session.sadd(self.key, function_id)


class NodeModel:
    def __init__(self, model_name=None, redis_session=None, contained_address=None, model_id=None):
        self.redis_session = redis_session
        if model_id:
            self.model_id = model_id
            self.contained_address = model_id.split(b':')[1]
        elif contained_address and model_name:
            self.model_id = model_name + b':' + contained_address
            self.contained_address = contained_address
        self.calls_out_set_id = self.model_id + b':calls_out'
        self.calls_in_set_id = self.model_id + b':calls_in'

    def basic_init_save(self, size):
        self.redis_session.hset(self.model_id, b'size', size)
        self.redis_session.hset(self.model_id, b'calls_out_set_id', self.calls_out_set_id)
        self.redis_session.hset(self.model_id, b'calls_in_set_id', self.calls_in_set_id)
        self.redis_session.hset(self.model_id, b'contained_address', self.contained_address)

    def get_size(self):
        return int(self.redis_session.hget(self.model_id, b'size'))

    def get_call_out_models_ids(self):
        return self.get_calls_in_or_out_ids(b'out')

    def get_call_in_models_ids(self):
        return self.get_calls_in_or_out_ids(b'in')

    def get_calls_in_or_out_ids(self, in_or_out):
        return self.redis_session.smembers(self.model_id + b':calls_' + in_or_out)

    def add_edge(self, target_node):
        self.redis_session.sadd(self.calls_out_set_id, target_node.model_id)
        self.redis_session.sadd(target_node.calls_in_set_id, self.model_id)

    def remove_edge(self, target_node_model):
        self.redis_session.srem(self.calls_out_set_id, target_node_model.model_id)
        self.redis_session.srem(target_node_model.calls_in_set_id, self.model_id)

    def change_edge_target(self, last_target_node, new_target_node):
        self.remove_edge(last_target_node)
        self.add_edge(new_target_node)


class ClusteredNodes(NodeModel):
    def __init__(self, model_name, redis_session=None, contained_address=None, model_id=None):
        NodeModel.__init__(self, model_name, redis_session=redis_session, contained_address=contained_address,
                           model_id=model_id)
        self.contained_nodes_set_id = self.model_id + b':contained_nodes'

    def get_contained_nodes_ids(self):
        return self.redis_session.smembers(self.contained_nodes_set_id)

    def merge_edges_and_size(self, model_to_cluster: NodeModel):
        calls_in_files_ids = model_to_cluster.get_call_in_models_ids()
        calls_out_files_ids = model_to_cluster.get_call_out_models_ids()
        add_values_to_set(redis_session=self.redis_session, key=self.calls_in_set_id, values=calls_in_files_ids)
        add_values_to_set(redis_session=self.redis_session, key=self.calls_out_set_id, values=calls_out_files_ids)
        self.redis_session.srem(self.calls_in_set_id, self.model_id)
        self.redis_session.srem(self.calls_in_set_id, model_to_cluster.model_id)
        self.redis_session.srem(self.calls_out_set_id, self.model_id)
        self.redis_session.srem(self.calls_out_set_id, model_to_cluster.model_id)
        self.redis_session.hset(self.model_id, b'size', self.get_size() + model_to_cluster.get_size())

    def get_sum_of_sons(self):
        call_out_models_ids = self.get_call_out_models_ids()
        size_sum = 0
        for model_id in call_out_models_ids:
            size_sum += NodeModel(redis_session=self.redis_session, model_id=model_id).get_size()
        return size_sum

    def cluster(self, model_to_cluster):
        self.merge_edges_and_size(model_to_cluster)
        add_values_to_set(redis_session=self.redis_session, key=self.contained_nodes_set_id,
                          values=model_to_cluster.get_contained_nodes_ids())
        self.switch_edge_references(model_to_cluster)
        model_to_cluster.remove()

    def switch_edge_references(self, merging_node):
        """
        removing references to the old node and replacing them with references to the new node
        """
        call_out_models_ids = self.get_call_out_models_ids()
        call_out_models = get_models_by_ids(redis_session=self.redis_session, model_ids=call_out_models_ids)
        for call_out_model in call_out_models:
            merging_node.remove_edge(call_out_model)
            self.add_edge(call_out_model)

        call_in_models_ids = self.get_call_in_models_ids()
        call_in_models = get_models_by_ids(redis_session=self.redis_session, model_ids=call_in_models_ids)
        for call_in_model in call_in_models:
            call_in_model.change_edge_target(last_target_node=merging_node, new_target_node=self)


class FolderModel(ClusteredNodes):
    def __init__(self, redis_session=None, contained_address=None, folder_id=None):
        ClusteredNodes.__init__(self, model_name=b'folder', redis_session=redis_session,
                                contained_address=contained_address,
                                model_id=folder_id)

    def get_call_out_folders_models(self):
        called_folders_ids = self.get_call_out_models_ids()
        called_folders_models = []
        for folder_id in called_folders_ids:
            called_folders_models.append(FolderModel(folder_id=folder_id, redis_session=self.redis_session))
        return called_folders_models

    def get_call_in_folders_models(self):
        calling_folders_ids = self.get_call_in_models_ids()
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
        self.basic_init_save(size=size)
        self.redis_session.hset(self.model_id, b'contained_files_set_id', self.contained_nodes_set_id)
        Folders(self.redis_session).add_folder_id(self.model_id)
        self.redis_session.sadd(self.contained_nodes_set_id,
                                FileModel(contained_address=self.contained_address).model_id)

    def remove(self):
        self.redis_session.delete(self.calls_out_set_id)
        self.redis_session.delete(self.calls_in_set_id)
        self.redis_session.delete(self.contained_nodes_set_id)
        self.redis_session.srem('folders', self.model_id)
        self.redis_session.delete(self.model_id)

    def recursion_init(self, size):
        self.add_init_folder_info(size)

    def add_folder_edge(self, called_function_address):
        """
        Add to the calls out set the called folder id,
        Add to the calls in set of the called folder the calling folder id.
        """
        called_folder_model = FolderModel(contained_address=called_function_address)
        self.add_edge(called_folder_model)


class FileModel(ClusteredNodes):
    def __init__(self, redis_session=None, contained_address=None, file_id=None):
        ClusteredNodes.__init__(self, model_name=b'file', redis_session=redis_session,
                                contained_address=contained_address,
                                model_id=file_id)
        self.folder_id = b'folder:' + self.contained_address

    def get_call_out_files_models(self):
        called_files_ids = self.get_call_out_models_ids()
        called_files_models = []
        for file_id in called_files_ids:
            called_files_models.append(FileModel(file_id=file_id, redis_session=self.redis_session))
        return called_files_models

    def get_call_in_files_models(self):
        calling_files_ids = self.get_call_in_models_ids()
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
        self.basic_init_save(size=size)
        self.redis_session.hset(self.model_id, b'contained_functions_set_id', self.contained_nodes_set_id)
        self.redis_session.hset(self.model_id, b'folder_id', self.folder_id)
        Files(self.redis_session).add_file_id(self.model_id)
        self.redis_session.sadd(self.contained_nodes_set_id, FunctionModel(address=self.contained_address).model_id)

    def recursion_init(self, size):
        """
        Init the files metadata and initialize folders nodes.
        """
        self.add_init_file_info(size)
        folder_model = FolderModel(folder_id=self.folder_id, redis_session=self.redis_session)
        folder_model.recursion_init(size)

    def add_file_edge(self, called_function_address):
        """
        Add to the calls out set the called file id,
        Add to the calls in set of the called file the calling file id.
        """
        called_file_model = FileModel(contained_address=called_function_address)
        self.add_edge(called_file_model)

    def recursion_add_edge(self, called_function_address):
        """
        Add edge to the called file and call add edge for folder
        The edged contained in the files relations need to exist inside the folder relations
        """
        self.add_file_edge(called_function_address)
        folder_model = FolderModel(folder_id=self.folder_id, redis_session=self.redis_session)
        folder_model.add_folder_edge(called_function_address=called_function_address)

    def remove(self):
        self.redis_session.delete(self.calls_out_set_id)
        self.redis_session.delete(self.calls_in_set_id)
        self.redis_session.delete(self.contained_nodes_set_id)
        self.redis_session.srem('files', self.model_id)
        self.redis_session.delete(self.model_id)


class FunctionModel(NodeModel):
    def __init__(self, redis_session=None, address=None, function_id=None):
        NodeModel.__init__(self, model_name=b'function', redis_session=redis_session,
                           contained_address=address,
                           model_id=function_id)
        self.file_id = b'file:' + self.contained_address

    def get_call_out_functions_models(self):
        called_functions_ids = self.get_call_out_models_ids()
        called_functions_models = []
        for function_id in called_functions_ids:
            called_functions_models.append(FunctionModel(function_id=function_id, redis_session=self.redis_session))
        return called_functions_models

    def get_call_in_functions_models(self):
        calling_functions_ids = self.get_call_in_models_ids()
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
        self.basic_init_save(size=size)
        self.redis_session.hset(self.model_id, b'file_id', self.file_id)
        Functions(self.redis_session).add_function_id(self.model_id)

    def recursion_init(self, size):
        """
        Init the function metadata and initialize files nodes.
        """
        self.add_init_function_info(size)
        file_repo_actions = FileModel(file_id=self.file_id, redis_session=self.redis_session)
        file_repo_actions.recursion_init(size)

    def add_function_edge(self, called_function_address):
        """
        Add to the calls out set the called function id,
        Add to the calls in set of the called function the calling function id.
        """
        called_function_model = FunctionModel(address=called_function_address)
        self.add_edge(target_node=called_function_model)


def add_values_to_set(redis_session, key, values):
    for value in values:
        redis_session.sadd(key, value)


class LonelyModels:
    def __init__(self, redis_session):
        self.redis_session = redis_session

    def add_address(self, address):
        self.redis_session.sadd('lonely:addresses', address)

    def get_models(self, model_name):
        addresses = self.redis_session.smembers('lonely:addresses')
        return get_models_by_addresses(addresses, self.redis_session, model_name)


class EntryModels:
    def __init__(self, redis_session):
        self.redis_session = redis_session

    def add_address(self, address):
        self.redis_session.sadd('entry:addresses', address)

    def get_models(self, model_name):
        addresses = self.redis_session.smembers('entry:addresses')
        return get_models_by_addresses(addresses, self.redis_session, model_name)


def get_models_by_addresses(addresses, redis_session, model_name):
    """
    addresses: a set of addresses
    redis_session: redis session
    model_name: function / file / folder
    """
    models = []
    for address in addresses:
        if model_name == 'function':
            models.append(FunctionModel(address=address, redis_session=redis_session))
        elif model_name == 'file':
            models.append(FileModel(contained_address=address, redis_session=redis_session))
        elif model_name == 'folder':
            models.append(FolderModel(contained_address=address, redis_session=redis_session))
    return models


def get_models_by_ids(redis_session, model_ids):
    """
    redis_session: redis session
    model_ids: model ids
    """
    models = []
    for model_id in model_ids:
        if b'function' in model_id:
            models.append(FunctionModel(function_id=model_id, redis_session=redis_session))
        elif b'file' in model_id:
            models.append(FileModel(file_id=model_id, redis_session=redis_session))
        elif b'folder' in model_id:
            models.append(FolderModel(folder_id=model_id, redis_session=redis_session))
    return models
