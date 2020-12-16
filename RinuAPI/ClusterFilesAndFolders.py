class ClusterFilesAndFolders:
    def __init__(self, redis_session):
        self.redis_session = redis_session

    def get_average_function_size(self):
        functions_id = self.redis_session.smembers('functions')
        number_of_functions = len(functions_id)
        functions_size_sum = 0
        for function_id in functions_id:
            function_size = int(self.redis_session.hgetall(function_id)[b'size'])
            functions_size_sum += function_size
        return float(functions_size_sum) / number_of_functions
