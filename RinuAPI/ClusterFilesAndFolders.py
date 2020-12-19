class ClusterFilesAndFolders:
    def __init__(self, redis_session, max_function_size, max_number_of_max_files_in_folder):
        self.max_node_size = max_function_size
        self.max_number_of_max_files_in_folder = max_number_of_max_files_in_folder
        self.redis_session = redis_session


