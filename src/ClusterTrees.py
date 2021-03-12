from Models import MultipleEntriesModels, MultipleEntriesFunctionNode, MultipleEntriesSortedSet, \
    FileModel, FunctionModel, Files, TreesEntriesFunctionsAddresses


class ClusterTrees:
    def __init__(self, redis_session):
        self.redis_session = redis_session

    def run(self):
        self.set_trees_heads_sets_and_sorted_set()
        self.cluster_trees()
        self.set_trees_entries_points()

    def set_trees_heads_sets_and_sorted_set(self):
        multiple_entries_models = MultipleEntriesModels(
            redis_session=self.redis_session).get_multiple_entries_functions()
        for multiple_entries_model in multiple_entries_models:
            self.set_trees_heads_set(multiple_entries_model)
            MultipleEntriesSortedSet(redis_session=self.redis_session). \
                add_element(number_of_calling_in_trees=multiple_entries_model.get_number_of_call_in_trees(),
                            function_model_id=multiple_entries_model.model_id)

    def set_trees_heads_set(self, multiple_entries_model: MultipleEntriesFunctionNode):
        call_in_models = multiple_entries_model.get_call_in_functions()
        for call_in_model in call_in_models:
            tree_head_function_model_id = call_in_model.get_tree_head_function_model_id()
            tree_head_function_model = FunctionModel(redis_session=self.redis_session,
                                                     function_id=tree_head_function_model_id)
            if call_in_model.contained_function_address and not MultipleEntriesModels(
                    redis_session=self.redis_session).is_member(
                address=tree_head_function_model.contained_function_address):
                multiple_entries_model.add_called_tree_head_function_models_id(
                    tree_head_function_models_id=tree_head_function_model_id)

    def cluster_trees(self):
        sorted_multiple_entries_model_ids = MultipleEntriesSortedSet(
            redis_session=self.redis_session).get_sorted_elements()
        for multiple_entries_model_id in sorted_multiple_entries_model_ids:
            multiple_entries_model = MultipleEntriesFunctionNode(redis_session=self.redis_session,
                                                                 function_id=multiple_entries_model_id)
            function_call_in_trees_heads_models = multiple_entries_model.get_call_in_functions_trees_heads()
            self.connect_trees(function_call_in_trees_heads_models=function_call_in_trees_heads_models,
                               multiple_entries_model=multiple_entries_model)

    def connect_trees(self, function_call_in_trees_heads_models, multiple_entries_model: MultipleEntriesFunctionNode):
        """
        Connect the multiple entries tree head to the calling in trees or their last father.
        """
        multiple_entries_file_model = multiple_entries_model.get_parent_file_model()
        if len(function_call_in_trees_heads_models) == 1:
            self.connect_multiple_entries_node_in_a_tree(multiple_entries_model)
        else:
            self.connect_multiple_trees_with_multiple_entries_node(function_call_in_trees_heads_models,
                                                                   multiple_entries_file_model)

    @staticmethod
    def connect_multiple_entries_node_in_a_tree(multiple_entries_model: MultipleEntriesFunctionNode):
        multiple_entries_file_model = multiple_entries_model.get_parent_file_model()
        called_function_models = multiple_entries_model.get_call_in_functions()
        first_called_function = called_function_models[0]
        first_called_file = first_called_function.get_parent_file_model()
        first_called_file.recursion_add_edge(called_file_model=multiple_entries_file_model)

    def connect_multiple_trees_with_multiple_entries_node(self, function_call_in_trees_heads_models,
                                                          multiple_entries_file_model: FileModel):
        for function_model in function_call_in_trees_heads_models:
            parent_file_model = function_model.get_parent_file_model()
            last_father_file_model = self.get_tree_head(file_model=parent_file_model)
            if multiple_entries_file_model.model_id != last_father_file_model.model_id:
                multiple_entries_file_model.recursion_add_edge(called_file_model=last_father_file_model)

    @staticmethod
    def get_tree_head(file_model: FileModel):
        relative_distance = 0
        file_father = file_model.get_call_in_files()
        last_father = file_model
        while file_father:
            relative_distance += 1
            last_father = file_father[0]
            file_father = file_father[0].get_call_in_files()

        return last_father

    def set_trees_entries_points(self):
        files_models = Files(self.redis_session).get_models()
        for file_model in files_models:
            call_in_files_ids = file_model.get_call_in_models_ids()
            call_out_files_ids = file_model.get_call_out_models_ids()
            if not bool(call_in_files_ids) and bool(call_out_files_ids):
                TreesEntriesFunctionsAddresses(redis_session=self.redis_session) \
                    .add_address(file_model.contained_function_address)