from Models import FileModel, FunctionModel, EntryModels


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
        neighbors_to_revisit = self.attach_nodes_sons(EntryModels(self.redis_session).get_models('function'))
        while neighbors_to_revisit:
            neighbors_to_revisit = self.attach_nodes_sons(neighbors_to_revisit)

    def attach_nodes_sons(self, models):
        """
        :param models
        For each given node attach an edge to nodes that do not have already a parent and return the new attached nodes
        """
        neighbors_to_revisit = []
        for model in models:
            neighbors_to_revisit += self.attach_parent_node_to_sons(model)
        return neighbors_to_revisit

    def attach_parent_node_to_sons(self, origin_function_model):
        """
        :param origin_function_model
        Attach an edge to nodes that do not have already a parent
        """
        neighbors_to_revisit = []
        functions_calls_out_models = origin_function_model.get_call_out_models()
        for called_function_model in functions_calls_out_models:
            called_file_model = called_function_model.get_parent_file_model()
            file_calls_in_models = called_file_model.get_call_in_models()
            origin_file_repo = FileModel(contained_address=origin_function_model.contained_address,
                                         redis_session=self.redis_session)
            if not bool(file_calls_in_models):
                origin_file_repo.recursion_add_edge(called_file_model.contained_address)
                neighbors_to_revisit.append(FunctionModel(function_id=called_function_model.model_id,
                                                          redis_session=self.redis_session))
            else:
                self.connect_two_trees(origin_file_repo, called_file_model)

        return neighbors_to_revisit

    def connect_two_trees(self, first_tree_file: FileModel, second_tree_file: FileModel):
        first_head_and_relative_distance = self.get_head_and_relative_distance(first_tree_file)
        second_head_and_relative_distance = self.get_head_and_relative_distance(second_tree_file)
        first_relative_distance = first_head_and_relative_distance["relative_distance"]
        second_relative_distance = second_head_and_relative_distance["relative_distance"]
        first_tree_head = first_head_and_relative_distance["last_father"]
        second_tree_head = second_head_and_relative_distance["last_father"]
        if first_tree_head.contained_address != second_tree_head.contained_address:
            if first_relative_distance > second_relative_distance:
                first_tree_head.recursion_add_edge(second_tree_head.contained_address)
                self.redis_session.srem('entry:addresses', second_tree_head.contained_address)
            else:
                second_tree_head.recursion_add_edge(first_tree_head.contained_address)
                self.redis_session.srem('entry:addresses', first_tree_head.contained_address)

    @staticmethod
    def get_head_and_relative_distance(file_model: FileModel):
        relative_distance = 0
        file_father = file_model.get_call_in_models()
        last_father = file_model
        while file_father:
            relative_distance += 1
            last_father = file_father[0]
            file_father = file_father[0].get_call_in_models()

        return {"last_father": last_father, "relative_distance": relative_distance}
