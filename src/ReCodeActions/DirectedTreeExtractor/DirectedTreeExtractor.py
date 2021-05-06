from src.ReCodeActions.Models import FunctionModel, EntryModels, MultipleEntriesModels
import redis
from typing import List
from src.AbstractClasses import Action


class DirectedTreeExtractor(Action):
    r"""
    In a directed tree each node has one parent except the head. Example:
          (_)
         /   \
        /     \
     (_)      (_)
      \
      (_)
    The directed trees are created based on the function-graph.
    Re-creating any edge except edges to a node with multiple entries.
    The reason for skipping edges to multiple entries nodes is because directed tree nodes have up to one parent.
    A visual example:

    Before: (Functions Graph)
    Functions models

          (_)     (_)
         /  \    /  \
        /    \ /     \
     (_)     (_)     (_)

    After: (Directed Trees)
    Files models

          (_)     (_)
         /   .   .   \
        /      .      \
     (_)      (_)     (_)

                |
        Edges to this
        node are skipped
    """

    def __init__(self, redis_session: redis.Redis):
        self.redis_session = redis_session

    def run(self):
        """
        Creates directed trees in the file models based on the functions graph connections.
        """
        function_entries_models = EntryModels(self.redis_session).get_functions_models() + \
                                  MultipleEntriesModels(self.redis_session).get_functions_models()
        for function_entry_model in function_entries_models:
            function_entry_model.set_tree_head_function_model_id(function_entry_model.model_id)
            self.extract_tree_from_entry(tree_head_function=function_entry_model)

    def extract_tree_from_entry(self, tree_head_function: FunctionModel):
        """
        :param tree_head_function: Tree head function model.

        Extract a directed tree from the tree head by traversing the function
        graph and skipping nodes with multiple calls to.
        """
        neighbors_to_revisit = self.attach_nodes_sons(functions=[tree_head_function],
                                                      tree_head_function=tree_head_function)
        while neighbors_to_revisit:
            neighbors_to_revisit = self.attach_nodes_sons(functions=neighbors_to_revisit,
                                                          tree_head_function=tree_head_function)

    def attach_nodes_sons(self, functions: List[FunctionModel], tree_head_function: FunctionModel) \
            -> List[FunctionModel]:
        """
        :param functions: Functions models list to attach sons.
        :param tree_head_function: Tree head function model.
        :returns: List of neighbors functions models to revisit.

        Attach the given functions parent file to the called functions parent file that have only one call.
        """
        neighbors_to_revisit = []
        for function in functions:
            neighbors_to_revisit += self.attach_parent_to_one_entry_sons(parent_function=function,
                                                                         tree_head_function=tree_head_function)
        return neighbors_to_revisit

    def attach_parent_to_one_entry_sons(self, parent_function: FunctionModel, tree_head_function: FunctionModel) \
            -> List[FunctionModel]:
        """
        :param parent_function: Parent function model
        :param tree_head_function: Tree head function to save as metadata on the connected function model.
        :returns: List of neighbors function models to revisit and run this function on.

        Attach the parent file model to the sons that are only connected to the parent (no multiple entries).
        """
        neighbors_to_revisit = []
        functions_calls_out_models = parent_function.get_call_out_models()
        parent_file_model = parent_function.get_parent_file_model()
        for called_function_model in functions_calls_out_models:
            called_file_model = called_function_model.get_parent_file_model()
            if not called_file_model.is_multiple_entries_models():
                parent_file_model.recursion_add_edge(called_file_model)
                called_function_model.set_tree_head_function_model_id(tree_head_function.model_id)
                neighbors_to_revisit.append(FunctionModel(function_id=called_function_model.model_id,
                                                          redis_session=self.redis_session))

        return neighbors_to_revisit
