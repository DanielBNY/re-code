from Models import Files, EntryModels, get_models_by_ids


class ClusterFilesAndFolders:
    def __init__(self, redis_session, max_function_size, max_number_of_max_files_in_folder):
        self.max_node_size = max_function_size
        self.max_number_of_max_files_in_folder = max_number_of_max_files_in_folder
        self.redis_session = redis_session

    def run(self):
        files = Files(redis_session=self.redis_session)
        average_file_size = files.get_average_file_size()
        if average_file_size > self.max_node_size:
            self.max_node_size = average_file_size
        files_entry_models = EntryModels(self.redis_session).get_models(model_name='file')
        for entry_file_model in files_entry_models:
            self.cluster_sons_of_entry_point([entry_file_model])

    def cluster_sons_of_entry_point(self, entry_node_model):
        neighbors_to_revisit = self.cluster_multiple_nodes(entry_node_model)
        while neighbors_to_revisit:
            neighbors_to_revisit = self.cluster_multiple_nodes(neighbors_to_revisit)

    def cluster_multiple_nodes(self, nodes):
        neighbors_to_revisit = []
        for node in nodes:
            returned_merged_nodes = self.get_merged_nodes(node)
            if returned_merged_nodes:
                neighbors_to_revisit += returned_merged_nodes
        return neighbors_to_revisit

    def get_merged_nodes(self, father_node):
        model_ids = father_node.get_call_out_models_ids()
        sons_models = get_models_by_ids(model_ids=model_ids, redis_session=self.redis_session)
        sum_of_sons = father_node.get_sum_of_sons()
        if not sons_models:
            return
        if sum_of_sons < self.max_node_size:
            if sum_of_sons > self.max_node_size / 2:
                return self.merge_multiple_nodes(sons_models)
            else:
                if father_node.get_size() + sum_of_sons < self.max_node_size:
                    father_and_sons = [father_node] + sons_models
                    return self.merge_multiple_nodes(father_and_sons)
                else:
                    return self.merge_multiple_nodes(sons_models)
        else:
            num_of_cluster = (sum_of_sons / self.max_node_size) + 1
            return self.divide_to_cluster(num_of_cluster, sons_models)

    def divide_to_cluster(self, number_of_clusters, nodes_to_cluster):
        clustered_nodes = []
        smaller_node = None
        if len(nodes_to_cluster) >= number_of_clusters:
            for node_to_cluster in nodes_to_cluster:
                if node_to_cluster.get_size() > self.max_node_size:
                    clustered_nodes.append(node_to_cluster)
                elif node_to_cluster.get_size() < self.max_node_size / 2:
                    if smaller_node:
                        smaller_node.recursion_cluster(node_to_cluster)
                    else:
                        smaller_node = node_to_cluster
                elif smaller_node and smaller_node.get_size() > self.max_node_size * (2 / 3):
                    clustered_nodes.append(smaller_node)
                    smaller_node = None
            clustered_nodes.append(smaller_node)
            return clustered_nodes
        else:
            return nodes_to_cluster

    @staticmethod
    def merge_multiple_nodes(nodes_to_cluster):
        node_to_cluster_into = nodes_to_cluster[0]
        for node in nodes_to_cluster[1:]:
            node_to_cluster_into.recursion_cluster(node)
        return [node_to_cluster_into]
