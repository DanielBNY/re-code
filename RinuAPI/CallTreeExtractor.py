from RepoActions import FileRepoActions


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
        functions_ids = self.redis_session.smembers('functions')
        for function_id in functions_ids:
            function_info = dict(self.redis_session.hgetall(function_id))
            calls_in_set_id = function_info[b'calls_in_set_id']
            calls_out_set_id = function_info[b'calls_out_set_id']
            if not bool(self.redis_session.smembers(calls_in_set_id)):
                if bool(self.redis_session.smembers(calls_out_set_id)):
                    self.redis_session.sadd('entry_functions', function_id)
                else:
                    self.redis_session.sadd('lonely_functions', function_id)

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
        origin_function_info = dict(self.redis_session.hgetall(origin_function_id))
        calls_out_set_id = origin_function_info[b'calls_out_set_id']
        functions_calls_out = self.redis_session.smembers(calls_out_set_id)
        for called_function_id in functions_calls_out:
            function_info = dict(self.redis_session.hgetall(called_function_id))
            pointed_file_id = function_info[b'file_id']
            pointed_file_info = dict(self.redis_session.hgetall(pointed_file_id))
            file_calls_in_set_id = pointed_file_info[b'calls_in_set_id']
            if not bool(self.redis_session.smembers(file_calls_in_set_id)):
                origin_file_repo = FileRepoActions(origin_function_info[b'contained_address'].decode('ascii'),
                                                   self.redis_session)
                origin_file_repo.recursion_add_edge(pointed_file_info[b'contained_address'].decode('ascii'))
                neighbors_to_revisit.append(called_function_id)
        return neighbors_to_revisit
