from __future__ import annotations
from typing import Set, List, Union
import redis
import abc


class NodeModel:
    __slots__ = 'redis_session', 'model_id', 'contained_function_address', 'calls_out_set_id', 'calls_in_set_id'

    def __init__(self, redis_session: redis.Redis, model_id):
        self.redis_session = redis_session
        self.model_id = model_id
        self.contained_function_address = model_id.split(b':')[1]
        self.calls_out_set_id = self.model_id + b':calls_out'
        self.calls_in_set_id = self.model_id + b':calls_in'

    def get_name(self) -> bytes:
        return self.model_id.replace(b':', b'_')

    def set_size(self, size: int):
        self.redis_session.hset(self.model_id, b'size', size)

    def basic_init_save(self, size):
        self.set_size(size)
        self.redis_session.hset(self.model_id, b'calls_out_set_id', self.calls_out_set_id)
        self.redis_session.hset(self.model_id, b'calls_in_set_id', self.calls_in_set_id)
        self.redis_session.hset(self.model_id, b'contained_address', self.contained_function_address)

    def is_multiple_entries_models(self):
        return MultipleEntriesModels(redis_session=self.redis_session).is_member(self.contained_function_address)

    def get_size(self):
        return int(self.redis_session.hget(self.model_id, b'size'))

    def get_call_out_models_ids(self):
        return self.redis_session.smembers(self.model_id + b':calls_out')

    def get_call_in_models_ids(self):
        return self.redis_session.smembers(self.model_id + b':calls_in')

    def add_edge(self, target_node):
        self.redis_session.sadd(self.calls_out_set_id, target_node.model_id)
        self.redis_session.sadd(target_node.calls_in_set_id, self.model_id)

    def remove_edge(self, target_node_model):
        self.redis_session.srem(self.calls_out_set_id, target_node_model.model_id)
        self.redis_session.srem(target_node_model.calls_in_set_id, self.model_id)

    def change_edge_target(self, last_target_node, new_target_node):
        self.remove_edge(last_target_node)
        self.add_edge(new_target_node)

    def delete_model(self):
        self.redis_session.delete(self.model_id)


class TreeNodeModel(NodeModel):
    __slots__ = 'contained_nodes_set_id'

    def __init__(self, redis_session: redis.Redis, model_id):
        NodeModel.__init__(self, redis_session=redis_session, model_id=model_id)
        self.contained_nodes_set_id = self.model_id + b':contained_nodes'

    def set_folders_path(self, folders_path):
        self.redis_session.hset(self.model_id, b'folders_path', folders_path)

    def get_folders_path(self) -> bytes:
        return self.redis_session.hget(self.model_id, b'folders_path')

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
        call_out_models = get_tree_models_by_ids(redis_session=self.redis_session, model_ids=call_out_models_ids)
        for call_out_model in call_out_models:
            merging_node.remove_edge(call_out_model)
            self.add_edge(call_out_model)

        call_in_models_ids = self.get_call_in_models_ids()
        call_in_models = get_tree_models_by_ids(redis_session=self.redis_session, model_ids=call_in_models_ids)
        for call_in_model in call_in_models:
            call_in_model.change_edge_target(last_target_node=merging_node, new_target_node=self)

    @abc.abstractmethod
    def remove(self):
        pass

    @abc.abstractmethod
    def recursion_cluster(self, file_to_cluster: Union[FolderModel, FileModel]):
        pass

    @abc.abstractmethod
    def get_call_in_models(self):
        pass

    @abc.abstractmethod
    def get_call_out_models(self):
        pass


class FolderModel(TreeNodeModel):
    def __init__(self, redis_session: redis.Redis, folder_id):
        TreeNodeModel.__init__(self, redis_session=redis_session, model_id=folder_id)

    def get_call_in_models(self):
        call_in_folders_ids = self.get_call_in_models_ids()
        call_in_folders = get_folders_models_by_ids(redis_session=self.redis_session,
                                                    folders_models_ids=call_in_folders_ids)
        return call_in_folders

    def get_call_out_models(self):
        call_out_folders_ids = self.get_call_out_models_ids()
        call_out_folders_models = get_folders_models_by_ids(folders_models_ids=call_out_folders_ids,
                                                            redis_session=self.redis_session)
        return call_out_folders_models

    def get_contained_files_models(self):
        contained_files_models_ids = self.get_contained_nodes_ids()
        contained_files_models = get_files_models_by_ids(files_models_ids=contained_files_models_ids,
                                                         redis_session=self.redis_session)
        return contained_files_models

    def get_sons_models(self):
        call_out_models_ids = self.get_call_out_models_ids()
        node_model = []
        for model_id in call_out_models_ids:
            node_model += [FolderModel(redis_session=self.redis_session, folder_id=model_id)]
        return node_model

    def remove_contained_file(self, model_id):
        self.redis_session.srem(self.contained_nodes_set_id, model_id)

    def add_init_folder_info(self, size):
        """
        Saves to the DB the initialized folder metadata: size of the folder, the id for the folders calls out set,
        the id for the folders calls in set, contained files set id,and contained address.
        Add the folder id to the set of folders ids.
        Add the first file into the set of contained files in the folder.
        """
        self.basic_init_save(size=size)
        self.redis_session.hset(self.model_id, b'contained_files_set_id', self.contained_nodes_set_id)
        Folders(self.redis_session).add_model_id(self.model_id)

    def remove(self):
        self.redis_session.delete(self.calls_out_set_id)
        self.redis_session.delete(self.calls_in_set_id)
        self.redis_session.delete(self.contained_nodes_set_id)
        Folders(redis_session=self.redis_session).remove_model_id(self.model_id)
        self.delete_model()

    def recursion_init(self, size):
        self.add_init_folder_info(size)

    def add_folder_edge(self, called_file_model):
        """
        Add to the calls out set the called folder id,
        Add to the calls in set of the called folder the calling folder id.
        """
        called_folder_model = called_file_model.get_parent_folder_model()
        self.add_edge(called_folder_model)

    def recursion_cluster(self, model_to_cluster):
        self.cluster(model_to_cluster)


class FileModel(TreeNodeModel):
    def __init__(self, redis_session: redis.Redis, file_id):
        TreeNodeModel.__init__(self, redis_session=redis_session, model_id=file_id)

    def get_call_in_models(self):
        call_in_files_ids = self.get_call_in_models_ids()
        call_in_files_models = get_files_models_by_ids(redis_session=self.redis_session,
                                                       files_models_ids=call_in_files_ids)
        return call_in_files_models

    def get_call_out_models(self):
        call_out_files_ids = self.get_call_out_models_ids()
        call_out_files_models = get_files_models_by_ids(files_models_ids=call_out_files_ids,
                                                        redis_session=self.redis_session)
        return call_out_files_models

    def get_contained_functions_models(self):
        contained_functions_models_ids = self.get_contained_nodes_ids()
        contained_functions_models = get_functions_models_by_ids(functions_models_ids=contained_functions_models_ids,
                                                                 redis_session=self.redis_session)
        return contained_functions_models

    def get_parent_folder_id(self) -> bytes:
        return self.redis_session.hget(self.model_id, b'folder_id')

    def get_parent_folder_model(self):
        return FolderModel(folder_id=self.get_parent_folder_id(), redis_session=self.redis_session)

    def add_init_file_info(self, size, first_folder_id):
        """
        Saves to the DB the initialized file metadata: size of the file, the id for the files calls out set,
        the id for the files calls in set, folder id, contained functions set id,and contained address.
        Add the file id to the set of file ids.
        Add the first function into the set of contained functions in the file.
        """
        self.basic_init_save(size=size)
        self.redis_session.hset(self.model_id, b'contained_functions_set_id', self.contained_nodes_set_id)
        self.redis_session.hset(self.model_id, b'folder_id', first_folder_id)
        Files(self.redis_session).add_model_id(self.model_id)

    def recursion_init(self, size):
        """
        Init the files metadata and initialize folders nodes.
        """
        first_folder_id = b'folder:' + self.contained_function_address
        self.add_init_file_info(size, first_folder_id)
        folder_model = FolderModel(folder_id=first_folder_id, redis_session=self.redis_session)
        folder_model.recursion_init(size)
        self.add_file_id_to_folder_contained_files(folder_model=folder_model)

    def add_file_id_to_folder_contained_files(self, folder_model: FolderModel):
        self.redis_session.sadd(folder_model.contained_nodes_set_id, self.model_id)

    def recursion_add_edge(self, called_file_model):
        """
        Add edge to the called file and call add edge for folder
        The edged contained in the files relations need to exist inside the folder relations
        """
        self.add_edge(called_file_model)
        folder_model = FolderModel(folder_id=self.get_parent_folder_id(), redis_session=self.redis_session)
        folder_model.add_folder_edge(called_file_model=called_file_model)

    def remove(self):
        self.redis_session.delete(self.calls_out_set_id)
        self.redis_session.delete(self.calls_in_set_id)
        self.redis_session.delete(self.contained_nodes_set_id)
        Files(redis_session=self.redis_session).remove_model_id(self.model_id)
        father_folder_model = FolderModel(folder_id=self.get_parent_folder_id(), redis_session=self.redis_session)
        father_folder_model.remove_contained_file(self.model_id)
        self.delete_model()

    def recursion_cluster(self, file_to_cluster: FileModel):
        current_folder_model = self.get_parent_folder_model()
        folder_to_cluster = file_to_cluster.get_parent_folder_model()
        self.cluster(file_to_cluster)
        current_folder_model.cluster(folder_to_cluster)


class FunctionModel(NodeModel):
    __slots__ = 'model_id'

    def __init__(self, redis_session: redis.Redis, address=None, function_id=None):
        model_id = function_id
        if address:
            model_id = b'function:' + address
        NodeModel.__init__(self, redis_session=redis_session, model_id=model_id)

    def get_call_in_functions(self):
        call_in_functions_ids = self.get_call_in_models_ids()
        call_in_function = get_functions_models_by_ids(redis_session=self.redis_session,
                                                       functions_models_ids=call_in_functions_ids)
        return call_in_function

    def get_call_out_models(self) -> List[FunctionModel]:
        call_out_functions_ids = self.get_call_out_models_ids()
        call_out_functions_models = get_functions_models_by_ids(functions_models_ids=call_out_functions_ids,
                                                                redis_session=self.redis_session)
        return call_out_functions_models

    def set_tree_head_function_model_id(self, tree_head_model_id):
        self.redis_session.hset(self.model_id, b'tree_head_function_model_id', tree_head_model_id)

    def get_tree_head_function_model_id(self) -> bytes:
        return self.redis_session.hget(self.model_id, b'tree_head_function_model_id')

    def get_tree_head_function_model(self) -> FunctionModel:
        tree_head_function_model_id = self.redis_session.hget(self.model_id, b'tree_head_function_model_id')
        return FunctionModel(function_id=tree_head_function_model_id, redis_session=self.redis_session)

    def is_api_wrapper(self) -> bool:
        return bool(APIWrapperModel(redis_session=self.redis_session, function_id=self.model_id).get_api_name())

    def set_function_code(self, decompiled_code):
        self.redis_session.hset(self.model_id, b'decompiled_code', decompiled_code)

    def set_called_function_wrapper(self, function_model_id: bytes):
        self.redis_session.sadd(self.model_id + b':called_function_wrapper', function_model_id)

    def get_called_functions_wrapper(self) -> List[FunctionModel]:
        called_functions_ids = self.redis_session.smembers(self.model_id + b':called_function_wrapper')
        called_functions_models = []
        for function_model_id in called_functions_ids:
            called_functions_models.append(
                FunctionModel(function_id=function_model_id, redis_session=self.redis_session))
        return called_functions_models

    def get_function_code(self):
        return self.redis_session.hget(self.model_id, b'decompiled_code')

    def get_parent_file_id(self) -> bytes:
        return self.redis_session.hget(self.model_id, b'file_id')

    def get_parent_file_model(self) -> FileModel:
        return FileModel(file_id=self.get_parent_file_id(), redis_session=self.redis_session)

    def add_init_function_info(self, size, first_file_id):
        """
        Saves to the DB the initialized function metadata: size of the function, the id for the functions calls out set,
        the id for the functions calls in set, file id and contained address.
        Add the function id to the set of functions ids in the DB.
        """
        self.basic_init_save(size=size)
        self.redis_session.hset(self.model_id, b'file_id', first_file_id)
        Functions(self.redis_session).add_model_id(self.model_id)

    def recursion_init(self):
        """
        Init the function metadata and initialize files nodes.
        """
        first_file_id = b'file:' + self.contained_function_address
        function_size = self.get_size()
        self.add_init_function_info(size=function_size, first_file_id=first_file_id)
        first_file_model = FileModel(file_id=first_file_id, redis_session=self.redis_session)
        first_file_model.recursion_init(size=function_size)
        self.add_function_id_to_file_contained_functions(first_file_model=first_file_model)

    def add_function_id_to_file_contained_functions(self, first_file_model: FileModel):
        self.redis_session.sadd(first_file_model.contained_nodes_set_id, self.model_id)

    def add_function_edge(self, called_function_model):
        """
        Add to the calls out set the called function id,
        Add to the calls in set of the called function the calling function id.
        """
        self.add_edge(target_node=called_function_model)


class MultipleEntriesFunctionNode(FunctionModel):
    def __init__(self, redis_session: redis.Redis, address=None, function_id=None):
        FunctionModel.__init__(self, redis_session=redis_session, address=address, function_id=function_id)

    def add_called_tree_head_function_models_id(self, tree_head_function_models_id):
        self.redis_session.sadd(self.model_id + b':tree_head_function_models_ids', tree_head_function_models_id)

    def get_call_in_trees_heads_ids(self):
        return self.redis_session.smembers(self.model_id + b':tree_head_function_models_ids')

    def get_call_in_functions_trees_heads(self) -> List[FunctionModel]:
        functions_ids = self.get_call_in_trees_heads_ids()
        functions_models = get_functions_models_by_ids(functions_models_ids=functions_ids,
                                                       redis_session=self.redis_session)
        return functions_models

    def get_number_of_call_in_trees(self) -> int:
        return self.redis_session.scard(self.model_id + b':tree_head_function_models_ids')


class MultipleEntriesSortedSet:
    __slots__ = 'redis_session', 'key'

    def __init__(self, redis_session: redis.Redis):
        self.redis_session = redis_session
        self.key = b'sorted_set_multiple_entries'

    def add_element(self, number_of_calling_in_trees: int, function_model_id: bytes):
        """
        Add a multiple entry model id with the score (number of calling in trees)
        """
        self.redis_session.zadd(self.key, {function_model_id: number_of_calling_in_trees})

    def get_sorted_elements(self) -> List[bytes]:
        """
        Get the sorted list of multiple entries by the (number of calling in trees)
        """
        return self.redis_session.zrangebyscore(self.key, -1, 'inf')


class APIWrapperModel(FunctionModel):
    def __init__(self, redis_session: redis.Redis, address=None, function_id=None):
        FunctionModel.__init__(self, redis_session=redis_session, address=address, function_id=function_id)

    def set_api_name(self, api_name):
        self.redis_session.hset(self.model_id, b'api_name', api_name)

    def get_api_name(self) -> bytes:
        return self.redis_session.hget(self.model_id, b'api_name')


def add_values_to_set(redis_session: redis.Redis, key, values):
    for value in values:
        redis_session.sadd(key, value)


class SpecialModels:
    __slots__ = 'key_name', 'redis_session'

    def __init__(self, key_name: str, redis_session: redis.Redis):
        self.key_name = key_name
        self.redis_session = redis_session

    def get_functions_addresses(self) -> Set[bytes]:
        return self.redis_session.smembers(self.key_name)

    def add_address(self, address: int):
        self.redis_session.sadd(self.key_name, address)

    def is_member(self, address) -> bool:
        return self.redis_session.sismember(self.key_name, address)

    def remove_address(self, address: int):
        self.redis_session.srem(self.key_name, address)

    def get_functions_models(self) -> List[FunctionModel]:
        functions_addresses = self.get_functions_addresses()
        return get_functions_by_addresses(functions_addresses=functions_addresses, redis_session=self.redis_session)

    def get_files_models(self) -> List[FileModel]:
        functions_addresses = self.get_functions_addresses()
        models_files_ids = get_files_ids_by_functions_addresses(functions_addresses=functions_addresses,
                                                                redis_session=self.redis_session)
        files_models = get_files_models_by_ids(redis_session=self.redis_session, files_models_ids=models_files_ids)
        return files_models

    def get_folders_models(self) -> List[FolderModel]:
        functions_addresses = self.get_functions_addresses()
        models_folders_ids = get_folders_ids_by_functions_addresses(functions_addresses=functions_addresses,
                                                                    redis_session=self.redis_session)
        folders_models = get_folders_models_by_ids(redis_session=self.redis_session,
                                                   folders_models_ids=models_folders_ids)
        return folders_models

    def get_multiple_entries_functions(self) -> List[MultipleEntriesFunctionNode]:
        functions_addresses = self.get_functions_addresses()
        return get_multiple_entries_functions_by_addresses(functions_addresses=functions_addresses,
                                                           redis_session=self.redis_session)


class LonelyModels(SpecialModels):
    def __init__(self, redis_session: redis.Redis):
        SpecialModels.__init__(self, key_name='lonely:functions:addresses', redis_session=redis_session)


class EntryModels(SpecialModels):
    def __init__(self, redis_session: redis.Redis):
        SpecialModels.__init__(self, key_name='entry:functions:addresses', redis_session=redis_session)


class TreesEntriesFunctionsAddresses(SpecialModels):
    def __init__(self, redis_session: redis.Redis):
        SpecialModels.__init__(self, key_name='trees_entries:functions:addresses', redis_session=redis_session)


class MultipleEntriesModels(SpecialModels):
    def __init__(self, redis_session: redis.Redis):
        SpecialModels.__init__(self, key_name='multiple_entries:functions:addresses', redis_session=redis_session)


class RadareDetectedModels(SpecialModels):
    def __init__(self, redis_session: redis.Redis):
        SpecialModels.__init__(self, key_name='radare_detected:functions:addresses', redis_session=redis_session)


class RetdecDetectedModels(SpecialModels):
    def __init__(self, redis_session: redis.Redis):
        SpecialModels.__init__(self, key_name='retdec_detected:functions:addresses', redis_session=redis_session)


class ApiWrappers:
    __slots__ = 'key', 'redis_session'

    def __init__(self, redis_session: redis.Redis):
        self.redis_session = redis_session
        self.key = 'api-wrappers'

    def add_function(self, model_id):
        self.redis_session.sadd(self.key, model_id)

    def get_api_wrappers(self) -> Set[bytes]:
        return self.redis_session.smembers(self.key)

    def is_api_wrapper(self, model_id) -> bool:
        return self.redis_session.sismember(self.key, model_id)


class MultipleNodesModels:
    __slots__ = 'multiple_nodes_models_key', 'redis_session'

    def __init__(self, redis_session: redis.Redis, multiple_node_models_key):
        self.redis_session = redis_session
        self.multiple_nodes_models_key = multiple_node_models_key

    def is_member(self, model_id) -> bool:
        return self.redis_session.sismember(self.multiple_nodes_models_key, model_id)

    def get_average_model_size(self):
        models_ids = self.get_model_ids()
        nodes_models = get_node_models_by_ids(redis_session=self.redis_session, models_ids=models_ids)
        average_models_size = get_average_models_size(nodes_models=nodes_models)
        return average_models_size

    def get_model_ids(self) -> Set[bytes]:
        return self.redis_session.smembers(self.multiple_nodes_models_key)

    def add_model_id(self, model_id):
        self.redis_session.sadd(self.multiple_nodes_models_key, model_id)

    def remove_model_id(self, model_id):
        self.redis_session.srem(self.multiple_nodes_models_key, model_id)


class Folders(MultipleNodesModels):
    def __init__(self, redis_session):
        MultipleNodesModels.__init__(self, redis_session=redis_session, multiple_node_models_key=b'folder')

    def get_non_lonely_folders(self) -> List[FolderModel]:
        folders_models_ids = self.get_model_ids()
        lonely_functions_addresses = LonelyModels(redis_session=self.redis_session).get_functions_addresses()
        lonely_folders_ids = get_folders_ids_by_functions_addresses(functions_addresses=lonely_functions_addresses,
                                                                    redis_session=self.redis_session)
        non_lonely_folders_ids = folders_models_ids - lonely_folders_ids
        non_lonely_models = get_folders_models_by_ids(folders_models_ids=non_lonely_folders_ids,
                                                      redis_session=self.redis_session)
        return non_lonely_models

    def get_models(self) -> List[FolderModel]:
        folders_models_ids = self.get_model_ids()
        folders_models = get_folders_models_by_ids(redis_session=self.redis_session,
                                                   folders_models_ids=folders_models_ids)
        return folders_models


class Files(MultipleNodesModels):
    def __init__(self, redis_session):
        MultipleNodesModels.__init__(self, redis_session=redis_session, multiple_node_models_key=b'file')

    def get_non_lonely_files(self) -> List[FileModel]:
        files_models_ids = self.get_model_ids()
        lonely_functions_addresses = LonelyModels(redis_session=self.redis_session).get_functions_addresses()
        lonely_files_ids = get_files_ids_by_functions_addresses(functions_addresses=lonely_functions_addresses,
                                                                redis_session=self.redis_session)
        non_lonely_files_ids = files_models_ids - lonely_files_ids
        non_lonely_models = get_files_models_by_ids(files_models_ids=non_lonely_files_ids,
                                                    redis_session=self.redis_session)
        return non_lonely_models

    def get_models(self) -> List[FileModel]:
        files_models_ids = self.get_model_ids()
        files_models = get_files_models_by_ids(files_models_ids=files_models_ids, redis_session=self.redis_session)
        return files_models


class Functions(MultipleNodesModels):
    def __init__(self, redis_session):
        MultipleNodesModels.__init__(self, redis_session=redis_session, multiple_node_models_key=b'function')

    def get_models(self) -> List[FunctionModel]:
        functions_models_ids = self.get_model_ids()
        functions_models = get_functions_models_by_ids(functions_models_ids=functions_models_ids,
                                                       redis_session=self.redis_session)
        return functions_models


# ---------------------------------------------------------------------------------------------------------------------

# Models Utils:

def get_average_models_size(nodes_models: List[NodeModel]) -> float:
    size_sum = 0
    for node_model in nodes_models:
        size_sum += node_model.get_size()
    return size_sum / float(len(nodes_models))


def get_functions_models_by_ids(functions_models_ids: Set[bytes], redis_session: redis.Redis) -> List[FunctionModel]:
    function_models = []
    for function_id in functions_models_ids:
        function_models.append(FunctionModel(redis_session=redis_session, function_id=function_id))
    return function_models


def get_files_models_by_ids(files_models_ids: Set[bytes], redis_session: redis.Redis) -> List[FileModel]:
    files_models = []
    for file_id in files_models_ids:
        files_models.append(FileModel(redis_session=redis_session, file_id=file_id))
    return files_models


def get_folders_models_by_ids(folders_models_ids: Set[bytes], redis_session: redis.Redis) -> List[FolderModel]:
    folders_models = []
    for folder_id in folders_models_ids:
        folders_models.append(FolderModel(redis_session=redis_session, folder_id=folder_id))
    return folders_models


def get_functions_by_addresses(functions_addresses, redis_session: redis.Redis) -> List[FunctionModel]:
    functions_models = []
    for address in functions_addresses:
        functions_models.append(FunctionModel(address=address, redis_session=redis_session))
    return functions_models


def get_files_ids_by_functions_addresses(functions_addresses, redis_session: redis.Redis) -> Set[bytes]:
    files_models_ids = set()
    for address in functions_addresses:
        function_model = FunctionModel(address=address, redis_session=redis_session)
        file_model_id = function_model.get_parent_file_model().model_id
        files_models_ids.add(file_model_id)
    return files_models_ids


def get_folders_ids_by_functions_addresses(functions_addresses, redis_session: redis.Redis) -> Set[bytes]:
    folders_models_ids = set()
    for address in functions_addresses:
        function_model = FunctionModel(address=address, redis_session=redis_session)
        folder_model_id = function_model.get_parent_file_model().get_parent_folder_model().model_id
        folders_models_ids.add(folder_model_id)
    return folders_models_ids


def get_multiple_entries_functions_by_addresses(functions_addresses: Set[bytes], redis_session: redis.Redis) \
        -> List[MultipleEntriesFunctionNode]:
    """
    :param functions_addresses: A set of bytes.
    :param redis_session: Redis session.
    :returns: List of multiple entries functions nodes.
    """
    multiple_entries_functions = []
    for address in functions_addresses:
        multiple_entries_function = MultipleEntriesFunctionNode(address=address, redis_session=redis_session)
        multiple_entries_functions.append(multiple_entries_function)
    return multiple_entries_functions


def get_node_models_by_ids(redis_session: redis.Redis, models_ids: Set[bytes]) -> List[NodeModel]:
    """
    :param redis_session: Redis session.
    :param models_ids: A set of models ids in bytes type.
    :returns: List of node models.
    """
    node_models = []
    for model_id in models_ids:
        node_models.append(NodeModel(model_id=model_id, redis_session=redis_session))
    return node_models


def get_tree_models_by_ids(redis_session: redis.Redis, model_ids: Set[bytes]) -> List[Union[FileModel, FolderModel]]:
    """
    :param redis_session: Redis session.
    :param model_ids: A set of models ids in bytes type.
    :returns: List of file models or folder models
    """
    tree_models = []
    for model_id in model_ids:
        if b'file' in model_id:
            tree_models.append(FileModel(file_id=model_id, redis_session=redis_session))
        elif b'folder' in model_id:
            tree_models.append(FolderModel(folder_id=model_id, redis_session=redis_session))
    return tree_models
# ---------------------------------------------------------------------------------------------------------------------
