from Models import FunctionModel, ApiWrappers
from pymongo import MongoClient
import conf


class FunctionsGraphExtractor:
    """
    Functions call graph - functions are nodes and edges are calls to other functions
    """

    def __init__(self, redis_session, mongodb_client: MongoClient):
        """
        The class contain the connection between functions and the list of functions addresses
        :param redis_session
        :param mongodb_client
        """
        self.mongodb_client = mongodb_client
        self.redis_session = redis_session
        db = self.mongodb_client[conf.mongo_db['db_name']]
        self.functions_info_collection = db['FunctionsInfo']
        self.functions_info_ids = self.functions_info_collection.distinct("_id")

    def run(self):
        """
        Extract the functions call graph to redis, saves the nodes and the edges between them
        """
        self.save_functions_graph()
        self.save_functions_edges()

    def save_functions_graph(self):
        for function_info_id in self.functions_info_ids:
            function_info = self.functions_info_collection.find({"_id": function_info_id}).next()
            if function_info["type"] == "fcn":
                fcn_address = function_info['offset']
                if self.redis_session.sismember('retdec_functions_addresses', fcn_address) or \
                        self.redis_session.sismember('retdec_functions_addresses', fcn_address - 1):
                    fcn_model = FunctionModel(address=str(fcn_address).encode(), redis_session=self.redis_session)
                    fcn_model.recursion_init(str(function_info['realsz']).encode())

    def get_valid_function_address(self, address):
        """
        Return the valid function address or None if the address is not a function
        The function is used because some function references are 4-bit behind the exact function address
        :param address: function address
        :return: int or None
        """

        if self.redis_session.exists(f"function:{address}"):
            return address
        elif self.redis_session.exists(f"function:{int(address) + 4}"):
            return address + 4
        elif self.redis_session.exists(f"function:{int(address) + 3}"):
            return address + 3
        elif self.redis_session.exists(f"function:{int(address) + 2}"):
            return address + 2
        elif self.redis_session.exists(f"function:{int(address) + 1}"):
            return address + 1
        return None

    def save_functions_edges(self):
        """
        save the edges between functions
        Their is a validation for the call references because
        not all call references are pointing to functions
        :return: list, function edges
        """
        for function_info_id in self.functions_info_ids:
            function_info = self.functions_info_collection.find({"_id": function_info_id}).next()
            if 'callrefs' in function_info:
                for call_reference in function_info['callrefs']:
                    called_function = self.get_valid_function_address(call_reference['addr'])
                    if called_function and call_reference['type'] == 'CALL':
                        source_function = function_info['offset']
                        fnc_repo_actions = FunctionModel(address=str(source_function).encode(),
                                                         redis_session=self.redis_session)
                        if source_function != called_function:
                            if ApiWrappers(self.redis_session).is_api_wrapper('function:' + str(called_function)):
                                fnc_repo_actions.set_called_function_wrapper(called_function)
                            else:
                                if self.redis_session.sismember("functions", f"function:{source_function}") and \
                                        self.redis_session.sismember("functions", f"function:{called_function}"):
                                    fnc_repo_actions.add_function_edge(str(called_function).encode())
