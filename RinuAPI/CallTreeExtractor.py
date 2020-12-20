from Models import FileModel, FunctionModel, Functions


class CallTreeExtractor:

    def __init__(self, redis_session):
        """
        :param redis_session
        """
        self.redis_session = redis_session

    def run(self):
        """
        Extract a call tree from the functions call graph.
        The call tree is used for the files and folders hierarchy recovering.
        Find entry points and start with them the process of recursively scans at the same level for nodes
        and connect to neighbors that do not have a father in the tree.
        At the tree a father to a node is at the highest level in the tree (related to the entry point).
        """
        self.find_code_entry_points()
        neighbors_to_revisit = self.attach_nodes_sons(self.redis_session.smembers('entry_functions'))
        while neighbors_to_revisit:
            neighbors_to_revisit = self.attach_nodes_sons(neighbors_to_revisit)

    def find_code_entry_points(self):
        """
        Find and saves the possible entry points (entry_functions, redis set key),
        saves functions that do not call any functions and are not called (lonely_functions, redis set key).
        Possible entry points are functions that functions do not call it
        """
        functions_models = Functions(self.redis_session).get_functions_models()
        for function_model in functions_models:
            call_in_functions = function_model.get_call_in_functions_models()
            call_out_functions = function_model.get_call_out_functions_models()
            if not bool(call_in_functions):
                if bool(call_out_functions):
                    self.redis_session.sadd('entry_functions', function_model.model_id)
                else:
                    self.redis_session.sadd('lonely_functions', function_model.model_id)

    def attach_nodes_sons(self, nodes):
        """
        :param nodes
        For each given node attach an edge to nodes that do not have already a parent and return the new attached nodes
        """
        neighbors_to_revisit = []
        for node in nodes:
            neighbors_to_revisit += self.attach_parent_node_to_sons(node)
        return neighbors_to_revisit

    def attach_parent_node_to_sons(self, origin_function_id):
        """
        :param origin_function_id
        Attach an edge to nodes that do not have already a parent
        """
        neighbors_to_revisit = []
        origin_function_model = FunctionModel(function_id=origin_function_id, redis_session=self.redis_session)
        functions_calls_out_models = origin_function_model.get_call_out_functions_models()
        for called_function_model in functions_calls_out_models:
            called_file_model = called_function_model.get_parent_file_model()
            file_calls_in_models = called_file_model.get_call_in_files_models()
            if not bool(file_calls_in_models):
                origin_file_repo = FileModel(contained_address=origin_function_model.contained_address,
                                             redis_session=self.redis_session)
                origin_file_repo.recursion_add_edge(called_file_model.contained_address)
                neighbors_to_revisit.append(called_function_model.model_id)
        return neighbors_to_revisit
