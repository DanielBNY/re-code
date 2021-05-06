import redis
from typing import List

from src.ReCodeActions.Models import MultipleEntriesModels, MultipleEntriesFunctionNode, MultipleEntriesSortedSet, \
    FileModel, FunctionModel, Files, TreesEntriesFunctionsAddresses
from src.AbstractClasses import Action


class ConnectTrees(Action):
    def __init__(self, redis_session: redis.Redis):
        self.redis_session = redis_session

    def run(self):
        """
        Add the multiple entries node into a sorted set by the number of calling trees heads.
        Connecting all trees with the multiple entries nodes while saving the hierarchy. Setting trees heads.
        """
        self.set_trees_heads_sets_and_sorted_set()
        self.connect_all_trees()
        self.set_trees_heads()

    def set_trees_heads_sets_and_sorted_set(self):
        """
        Set for the multiple entries models the calling trees and add the multiple entries node into a
        sorted set by the number of calling trees heads.
        """
        multiple_entries_models = MultipleEntriesModels(
            redis_session=self.redis_session).get_multiple_entries_functions()
        for multiple_entries_model in multiple_entries_models:
            self.set_connected_trees_heads(multiple_entries_model)
            MultipleEntriesSortedSet(redis_session=self.redis_session). \
                add_element(number_of_calling_in_trees=multiple_entries_model.get_number_of_call_in_trees(),
                            function_model_id=multiple_entries_model.model_id)

    def set_connected_trees_heads(self, multiple_entries_model: MultipleEntriesFunctionNode):
        """
        :param multiple_entries_model: Multiple entries model to set the connected trees heads

        Save the connected trees’ heads to a set of a multiple entries model.
        This step goes over the calling nodes for multiple entries nodes and
        get the tree heads that are connected to the multiple entries node.
        (each function model has the tree head saved as a metadata)
        """
        multi_entries_models = MultipleEntriesModels(redis_session=self.redis_session)
        call_in_functions = multiple_entries_model.get_call_in_functions()
        for function_model in call_in_functions:
            tree_head_function_model_id = function_model.get_tree_head_function_model_id()
            tree_head_function_model = FunctionModel(redis_session=self.redis_session,
                                                     function_id=tree_head_function_model_id)
            if function_model.contained_function_address \
                    and not multi_entries_models.is_member(address=tree_head_function_model.contained_function_address):
                multiple_entries_model.add_called_tree_head_function_models_id(
                    tree_head_function_models_id=tree_head_function_model_id)

    def connect_all_trees(self):
        """
        Connecting trees with the same multiple entries node by transforming
        the node to be the head of all of the previously calling trees.
        This process is done from the node with the lowest number of calling trees’ to the highest.
        If there is only one calling tree head connect an edge from the tree head to the multiple entries node.
        """
        sorted_multiple_entries_model_ids = MultipleEntriesSortedSet(
            redis_session=self.redis_session).get_sorted_elements()
        for multiple_entries_model_id in sorted_multiple_entries_model_ids:
            multiple_entries_model = MultipleEntriesFunctionNode(redis_session=self.redis_session,
                                                                 function_id=multiple_entries_model_id)
            function_call_in_trees_heads_models = multiple_entries_model.get_call_in_functions_trees_heads()
            self.connect_trees(function_call_in_trees_heads_models=function_call_in_trees_heads_models,
                               multiple_entries_model=multiple_entries_model)

    def connect_trees(self, function_call_in_trees_heads_models: List[FunctionModel],
                      multiple_entries_model: MultipleEntriesFunctionNode):
        """
        Connect the multiple entries tree head to the calling in trees or their last father.
        If there is only one calling tree head connect an edge from the tree head to the multiple entries node.
        """
        multiple_entries_file_model = multiple_entries_model.get_parent_file_model()
        if len(function_call_in_trees_heads_models) == 1:
            self.connect_multiple_entries_node_in_a_tree(multiple_entries_model)
        else:
            self.connect_multiple_entries_node_with_trees_heads(
                function_call_in_trees_heads_models=function_call_in_trees_heads_models,
                multiple_entries_file_model=multiple_entries_file_model)

    @staticmethod
    def connect_multiple_entries_node_in_a_tree(multiple_entries_model: MultipleEntriesFunctionNode):
        """
        Connect an edge from the tree head to the multiple entries node.
        """
        multiple_entries_file_model = multiple_entries_model.get_parent_file_model()
        called_function_models = multiple_entries_model.get_call_in_functions()
        first_called_function = called_function_models[0]
        first_called_file = first_called_function.get_parent_file_model()
        first_called_file.recursion_add_edge(called_file_model=multiple_entries_file_model)

    def connect_multiple_entries_node_with_trees_heads(self, multiple_entries_file_model: FileModel,
                                                       function_call_in_trees_heads_models: List[FunctionModel]):
        r"""
        :param function_call_in_trees_heads_models:
        :param multiple_entries_file_model:

        Connecting trees with the multiple entries node by transforming the node to be the head
        of all of his previously calling trees. Inverse the graph, for example:

        Before:
        node2 ---> node1 <--- node3

        After:
        node2 <--- node1 ---> node3
        """
        for function_model in function_call_in_trees_heads_models:
            parent_file_model = function_model.get_parent_file_model()
            last_father_file_model = self.get_tree_head(file_model=parent_file_model)
            if multiple_entries_file_model.model_id != last_father_file_model.model_id:
                multiple_entries_file_model.recursion_add_edge(called_file_model=last_father_file_model)

    @staticmethod
    def get_tree_head(file_model: FileModel) -> FileModel:
        """
        :param file_model: file model in a tree.
        :returns: Tree head.

        Get the tree head by traversing up from the file model until the last father is reached.
        """
        relative_distance = 0
        file_father = file_model.get_call_in_models()
        last_father = file_model
        while file_father:
            relative_distance += 1
            last_father = file_father[0]
            file_father = file_father[0].get_call_in_models()
        return last_father

    def set_trees_heads(self):
        """
        Sets the trees heads, tree head have no calls in and have calls out.
        """
        files_models = Files(self.redis_session).get_models()
        for file_model in files_models:
            call_in_files_ids = file_model.get_call_in_models_ids()
            call_out_files_ids = file_model.get_call_out_models_ids()
            if not bool(call_in_files_ids) and bool(call_out_files_ids):
                TreesEntriesFunctionsAddresses(redis_session=self.redis_session) \
                    .add_address(file_model.contained_function_address)
