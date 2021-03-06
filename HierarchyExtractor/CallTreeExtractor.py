from Models import FileModel, FunctionModel, EntryModels, MultipleEntriesModels, TreeNodeModel, NodeModel


class CallTreeExtractor:

    def __init__(self, redis_session):
        """
        :param redis_session
        """
        self.redis_session = redis_session

    def run(self):
        function_entries_models = EntryModels(self.redis_session).get_functions_models() + \
                               MultipleEntriesModels(self.redis_session).get_functions_models()
        for function_entry_model in function_entries_models:
            function_entry_model.set_tree_head_function_model_id(function_entry_model.model_id)
            self.extract_tree_from_entry(tree_head_model=function_entry_model)

    def extract_tree_from_entry(self, tree_head_model: FunctionModel):
        neighbors_to_revisit = self.attach_nodes_sons([tree_head_model], tree_head_model=tree_head_model)
        while neighbors_to_revisit:
            neighbors_to_revisit = self.attach_nodes_sons(models=neighbors_to_revisit, tree_head_model=tree_head_model)

    def attach_nodes_sons(self, models, tree_head_model: FunctionModel):
        neighbors_to_revisit = []
        for model in models:
            neighbors_to_revisit += self.attach_parent_node_to_sons(model, tree_head_model)
        return neighbors_to_revisit

    def attach_parent_node_to_sons(self, origin_function_model, tree_head_model: FunctionModel):
        neighbors_to_revisit = []
        functions_calls_out_models = origin_function_model.get_call_out_models()
        for called_function_model in functions_calls_out_models:
            called_file_model = called_function_model.get_parent_file_model()
            file_calls_in_models = called_file_model.get_call_in_files()
            origin_file_repo = FileModel(contained_address=origin_function_model.contained_function_address,
                                         redis_session=self.redis_session)
            if not bool(file_calls_in_models) and not called_file_model.is_multiple_entries_models():
                origin_file_repo.recursion_add_edge(called_file_model.contained_function_address)
                called_function_model.set_tree_head_function_model_id(tree_head_model.model_id)
                neighbors_to_revisit.append(FunctionModel(function_id=called_function_model.model_id,
                                                          redis_session=self.redis_session))

        return neighbors_to_revisit

    def connect_two_trees(self, first_tree_file: FileModel, second_tree_file: FileModel):
        first_head_and_relative_distance = self.get_head_and_relative_distance(first_tree_file)
        second_head_and_relative_distance = self.get_head_and_relative_distance(second_tree_file)
        first_relative_distance = first_head_and_relative_distance["relative_distance"]
        second_relative_distance = second_head_and_relative_distance["relative_distance"]
        first_tree_head = first_head_and_relative_distance["last_father"]
        second_tree_head = second_head_and_relative_distance["last_father"]
        if first_tree_head.contained_function_address != second_tree_head.contained_function_address:
            if first_relative_distance > second_relative_distance:
                first_tree_head.recursion_add_edge(second_tree_head.contained_function_address)
                self.redis_session.srem('entry:addresses', second_tree_head.contained_function_address)
            else:
                second_tree_head.recursion_add_edge(first_tree_head.contained_function_address)
                self.redis_session.srem('entry:addresses', first_tree_head.contained_function_address)

    @staticmethod
    def get_head_and_relative_distance(file_model: FileModel):
        relative_distance = 0
        file_father = file_model.get_call_in_files()
        last_father = file_model
        while file_father:
            relative_distance += 1
            last_father = file_father[0]
            file_father = file_father[0].get_call_in_files()

        return {"last_father": last_father, "relative_distance": relative_distance}
