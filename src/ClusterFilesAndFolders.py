from Models import Files, TreesEntriesFunctionsAddresses, get_tree_models_by_ids
from Models import FileModel, FolderModel
from typing import Union, List
import redis
from AbstractClasses import Action


class ClusterFilesAndFolders(Action):
    def __init__(self, redis_session: redis.Redis, max_file_size: int, max_number_of_max_files_in_folder: int):
        self.max_file_size = max_file_size
        self.max_number_of_max_files_in_folder = max_number_of_max_files_in_folder
        self.redis_session = redis_session

    def run(self):
        """
        Sets the max file size as the average size if it is bigger than the input max file size.
        Get the entry file models and folders.
        Cluster the file models and then cluster the folder models.
        """
        files = Files(redis_session=self.redis_session)
        average_file_size = files.get_average_model_size()
        if average_file_size > self.max_file_size:
            self.max_file_size = average_file_size
        files_entry_models = TreesEntriesFunctionsAddresses(self.redis_session).get_files_models()
        folders_entry_models = TreesEntriesFunctionsAddresses(self.redis_session).get_folders_models()
        self.cluster_trees(trees_heads=files_entry_models,
                           max_node_size=self.max_file_size)
        self.cluster_trees(trees_heads=folders_entry_models,
                           max_node_size=self.max_file_size * self.max_number_of_max_files_in_folder)

    def cluster_trees(self, trees_heads: List[Union[FileModel, FolderModel]], max_node_size: int):
        r"""
        :param trees_heads: List of trees heads.
        :param max_node_size: Max file\folder size in lines of code.

        Cluster trees from the tree head.
        """
        for tree_head in trees_heads:
            self.cluster_sons_of_entry_point(tree_head=tree_head, max_node_size=max_node_size)

    def cluster_sons_of_entry_point(self, tree_head: Union[FileModel, FolderModel], max_node_size: int):
        r"""
        :param tree_head: Tree head file\folder to start the clustering process from.
        :param max_node_size: Max file\folder size in lines of code.

        Cluster the sons of a tree head in graph traversal.
        """
        neighbors_to_revisit = self.cluster_multiple_nodes([tree_head], max_node_size)
        while neighbors_to_revisit:
            neighbors_to_revisit = self.cluster_multiple_nodes(neighbors_to_revisit, max_node_size)

    def cluster_multiple_nodes(self, nodes: List[Union[FileModel, FolderModel]], max_node_size: int):
        r"""
        :param nodes: List of files\folders to cluster
        :param max_node_size: Max file\folder size in lines of code.
        :returns: Next nodes to cluster.

        Cluster multiple nodes and their sons, return the next nodes to cluster.
        """
        neighbors_to_cluster = []
        for node in nodes:
            returned_merged_nodes = self.cluster_father_and_sons(node, max_node_size)
            if returned_merged_nodes:
                neighbors_to_cluster += returned_merged_nodes
        return neighbors_to_cluster

    def cluster_father_and_sons(self, father_node: Union[FileModel, FolderModel], max_node_size: int) \
            -> List[Union[FileModel, FolderModel]]:
        r"""
        :param father_node: File or folder model.
        :param max_node_size: Max file\folder size in lines of code.
        :returns: List of clustered files or folders.

        If the sums of sons is bigger than the max node size cluster the sons to multiple nodes.
        Otherwise cluster to one node, if the sum of sons and father is smaller than the max size cluster the father
        and sons, and if not just cluster the sons.
        """
        sons_models = father_node.get_call_out_models()
        sum_of_sons = father_node.get_sum_of_sons()
        if not sons_models:
            return []
        if sum_of_sons < max_node_size:
            if father_node.get_size() + sum_of_sons < max_node_size:
                father_and_sons = [father_node] + sons_models
                return [self.cluster_to_one_node(father_and_sons)]
            else:
                return [self.cluster_to_one_node(sons_models)]
        else:
            num_of_cluster = (sum_of_sons / max_node_size) + 1
            return self.cluster_to_multiple_nodes(num_of_cluster, sons_models, max_node_size)

    @staticmethod
    def cluster_to_multiple_nodes(number_of_clusters: int,
                                  nodes_to_cluster: List[Union[FileModel, FolderModel]],
                                  max_node_size: int) -> List[Union[FileModel, FolderModel]]:
        r"""
        :param number_of_clusters: number of cluster to cluster the nodes.
        :param nodes_to_cluster: File or folder models list to cluster.
        :param max_node_size: Max file\folder size in lines of code.
        :returns: List of clustered files or folders.

        If their are less nodes than the max number return the input nodes.
        Otherwise iterate over all nodes and return the clustered nodes.
        For each node that is bigger than the max node size add it to the clustered nodes.
        If the node is smaller than the max size, cluster it with other small nodes until they pass the max size
        and than add it to the clustered list.
        """
        clustered_nodes = []
        smaller_node = None
        if len(nodes_to_cluster) >= number_of_clusters:
            for node_to_cluster in nodes_to_cluster:
                if node_to_cluster.get_size() < max_node_size:
                    if smaller_node:
                        smaller_node.recursion_cluster(node_to_cluster)
                    else:
                        smaller_node = node_to_cluster
                else:
                    clustered_nodes.append(node_to_cluster)
                if smaller_node and smaller_node.get_size() >= max_node_size:
                    clustered_nodes.append(smaller_node)
                    smaller_node = None
            if smaller_node:
                clustered_nodes.append(smaller_node)
            return clustered_nodes
        else:
            return nodes_to_cluster

    @staticmethod
    def cluster_to_one_node(nodes_to_cluster: List[Union[FileModel, FolderModel]]) -> \
            Union[FileModel, FolderModel]:
        r"""
        :param nodes_to_cluster: List of file\folder models to cluster into one node.
        :returns: Clustered files or folders in one model.

        Cluster a list of files or folders models into one model and returns it.
        """
        node_to_cluster_into = nodes_to_cluster[0]
        for node in nodes_to_cluster[1:]:
            node_to_cluster_into.recursion_cluster(node)
        return node_to_cluster_into
