from Models import FunctionModel, ApiWrappers, Functions, EntryModels, LonelyModels
from pymongo import MongoClient
import conf
import re


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
        self.set_entry_and_lonely_models()

    def save_functions_graph(self):
        for function_info_id in self.functions_info_ids:
            function_info = self.functions_info_collection.find({"_id": function_info_id}).next()
            if function_info["type"] == "fcn":
                fcn_address = function_info['offset']
                if self.redis_session.sismember('retdec_functions_addresses', fcn_address):
                    fcn_model = FunctionModel(address=str(fcn_address).encode(), redis_session=self.redis_session)
                    fcn_model.recursion_init(str(function_info['realsz']).encode())

    def get_valid_function_address(self, address):
        """
        Return the valid function address or None if the address is not a function
        The function is used because some function references are 4-bit behind the exact function address
        :param address: function address
        :return: int or None
        """
        if self.redis_session.exists(f"function:{int(address) + 3}"):
            # some functions have an empty function that is detected -3 from the real function address
            return address + 3
        if self.redis_session.exists(f"function:{address}"):
            return address
        elif self.redis_session.exists(f"function:{int(address) + 4}"):
            return address + 4
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
                    called_function_address = self.get_valid_function_address(call_reference['addr'])
                    if called_function_address and call_reference['type'] == 'CALL':
                        source_function_address = function_info['offset']
                        source_function_model = FunctionModel(address=str(source_function_address).encode(),
                                                              redis_session=self.redis_session)
                        called_function_model = FunctionModel(address=str(called_function_address).encode(),
                                                              redis_session=self.redis_session)
                        if source_function_address != called_function_address:
                            self.set_edge(source_function_model=source_function_model,
                                          called_function_model=called_function_model)

    def set_edge(self, source_function_model: FunctionModel, called_function_model: FunctionModel):
        if ApiWrappers(self.redis_session).is_api_wrapper(called_function_model.model_id):
            source_function_model.set_called_function_wrapper(called_function_model.model_id)
        else:
            if self.redis_session.sismember("functions", source_function_model.model_id):
                if self.redis_session.sismember("functions", called_function_model.model_id):
                    source_function_model.add_function_edge(called_function_model)

    def set_entry_and_lonely_models(self):
        """
        Find and saves the possible entry points (entry_functions, redis set key),
        saves functions that do not call any functions and are not called (lonely_functions, redis set key).
        Possible entry points are functions that functions do not call it
        """
        functions_models = Functions(self.redis_session).get_functions_models()
        for function_model in functions_models:
            call_in_functions = function_model.get_call_in_functions_models()
            call_out_functions = function_model.get_call_out_functions_models()
            if not bool(call_in_functions):
                if bool(call_out_functions):
                    EntryModels(redis_session=self.redis_session).add_address(function_model.contained_address)
                else:
                    LonelyModels(redis_session=self.redis_session).add_address(function_model.contained_address)

    @staticmethod
    def import_calls_from_code(function_model: FunctionModel):
        """
        functions arrived to lonely functions because no calls out where detected but the
        functions do have calls to functions. The issue is that radare2 calls detection missed
        those calls but they exists in the decompiled code. The solution is to parser the functions code and
        find the called functions addresses.
        """
        detected_functions = False
        function_code = function_model.get_function_code()
        all_functions_hex_addresses = re.findall(r'function_([a-f0-9]+)\(', function_code)
        for hex_function_address in all_functions_hex_addresses:
            decimal_function_address = str(int(hex_function_address, 16)).encode()
            if decimal_function_address != function_model.contained_address:
                function_model.add_function_edge(decimal_function_address)
                detected_functions = True
        return detected_functions
