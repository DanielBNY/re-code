from Models import FunctionModel, ApiWrappers, Functions, EntryModels, LonelyModels, RetdecDetectedModels, \
    MultipleEntriesModels
from pymongo import MongoClient
import redis


class FunctionsGraphExtractor:
    """
    Functions call graph - functions are nodes and edges are calls to other functions
    """

    def __init__(self, redis_session: redis.Redis, mongodb_client: MongoClient, functions_info_collection_name: str,
                 mongo_db_name: str):
        self.mongodb_client = mongodb_client
        self.redis_session = redis_session
        db = self.mongodb_client[mongo_db_name]
        self.functions_info_collection = db[functions_info_collection_name]
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
                if RetdecDetectedModels(redis_session=self.redis_session).is_member(address=fcn_address):
                    fcn_model = FunctionModel(address=str(fcn_address).encode(), redis_session=self.redis_session)
                    fcn_model.recursion_init()

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
            source_function_address = function_info['offset']
            source_function_model = FunctionModel(address=str(source_function_address).encode(),
                                                  redis_session=self.redis_session)
            if 'callrefs' in function_info:
                call_references = function_info['callrefs']
                self.add_calls_references(source_function=source_function_model, call_references=call_references)

    def add_calls_references(self, source_function: FunctionModel, call_references):
        for call_reference in call_references:
            called_function_address = self.get_valid_function_address(call_reference['addr'])
            if called_function_address and call_reference['type'] == 'CALL':
                called_function_model = FunctionModel(address=str(called_function_address).encode(),
                                                      redis_session=self.redis_session)
                if source_function.contained_function_address != called_function_model.contained_function_address:
                    self.set_edge(source_function_model=source_function,
                                  called_function_model=called_function_model)

    def set_edge(self, source_function_model: FunctionModel, called_function_model: FunctionModel):
        if ApiWrappers(self.redis_session).is_api_wrapper(called_function_model.model_id):
            source_function_model.set_called_function_wrapper(called_function_model.model_id)
        else:
            if Functions(redis_session=self.redis_session).is_member(source_function_model.model_id):
                if Functions(redis_session=self.redis_session).is_member(called_function_model.model_id):
                    source_function_model.add_function_edge(called_function_model)

    def set_entry_and_lonely_models(self):
        """
        Find and saves the possible entry points (entry_functions, redis set key),
        saves functions that do not call any functions and are not called (lonely_functions, redis set key).
        Possible entry points are functions that functions do not call it
        """
        functions_models = Functions(self.redis_session).get_models()
        for function_model in functions_models:
            call_in_functions = function_model.get_call_in_functions()
            call_out_functions = function_model.get_call_out_models()
            if not bool(call_in_functions):
                EntryModels(redis_session=self.redis_session).add_address(function_model.contained_function_address)
            if len(call_in_functions) > 1:
                MultipleEntriesModels(redis_session=self.redis_session).add_address(
                    function_model.contained_function_address)
            if not bool(call_in_functions) and not bool(call_out_functions):
                LonelyModels(redis_session=self.redis_session).add_address(function_model.contained_function_address)
