class FilesGraphExtractor:

    def __init__(self, redis_session):
        """
        :param redis_session
        """
        self.redis_session = redis_session

    def start(self):
