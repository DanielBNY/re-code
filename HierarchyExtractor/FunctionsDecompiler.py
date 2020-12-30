from Models import Functions
from BinaryExtractor import BinaryExtractor

URL = 'http://localhost:5000/'


class FunctionsDecompiler:

    def __init__(self, redis_session, binary_extractor: BinaryExtractor):
        self.redis_session = redis_session
        self.binary_extractor = binary_extractor

    def run(self):
        functions_models = Functions(redis_session=self.redis_session).get_functions_models()
        for function_model in functions_models:
            function_code = self.binary_extractor.decompile_function(function_model.contained_address.decode())
            function_model.set_function_code(function_code)
