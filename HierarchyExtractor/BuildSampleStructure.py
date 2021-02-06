from Models import EntryModels, Folders, Files, LonelyModels, get_models_by_ids, FileModel, FunctionModel, ApiWrappers, \
    APIWrapperModel

import os


class BuildSampleStructure:
    def __init__(self, destination_sample, redis_session):
        self.destination_sample = destination_sample
        self.redis_session = redis_session

    def run(self):
        entry_folders_models = EntryModels(redis_session=self.redis_session).get_models('folder')
        self.create_folders_in_path(self.destination_sample, entry_folders_models)
        folders_to_revisit = entry_folders_models
        while folders_to_revisit:
            folders_to_revisit = self.create_folder_for_sons(folders_to_revisit)
        self.set_all_files_paths()
        self.write_functions_to_files()
        self.create_lonely_functions_file()

    def create_lonely_functions_file(self):
        lonely_files_models = LonelyModels(redis_session=self.redis_session).get_models(model_name='file')
        self.write_files_to_file(files_models=lonely_files_models,
                                 file_path=self.destination_sample + b'/lonely_file')

    def create_folder_for_sons(self, folders):
        folders_to_revisit = []
        for folder in folders:
            sons_models = folder.get_sons_models()
            self.create_folders_in_path(path=folder.get_folders_path() + b'/' + folder.model_id, models=sons_models)
            folders_to_revisit += sons_models
        return folders_to_revisit

    @staticmethod
    def create_folders_in_path(path, models):
        for model in models:
            os.mkdir(path + b'/' + model.model_id)
            model.set_folders_path(path)

    def set_all_files_paths(self):
        folder_models = Folders(redis_session=self.redis_session).get_non_lonely_models()
        for folder in folder_models:
            if folder.get_folders_path():
                full_path = folder.get_folders_path() + b'/' + folder.model_id
                contained_files_ids = folder.get_contained_nodes_ids()
                files_models = get_models_by_ids(model_ids=contained_files_ids, redis_session=self.redis_session)
                self.set_files_paths(path=full_path, models=files_models)

    @staticmethod
    def set_files_paths(path, models):
        for model in models:
            model.set_folders_path(path)

    def write_functions_to_files(self):
        files_models = Files(redis_session=self.redis_session).get_non_lonely_models()
        for file_model in files_models:
            if file_model.get_folders_path():
                file_path = file_model.get_folders_path() + b'/' + file_model.model_id
                functions_models = get_models_by_ids(model_ids=file_model.get_contained_nodes_ids(),
                                                     redis_session=self.redis_session)
                self.write_function_to_file(functions_models=functions_models, file_path=file_path)

    def write_function_to_file(self, functions_models, file_path):
        file_code = b''
        for function_model in functions_models:
            self.replace_wrapped_functions(function_model)
            function_code = function_model.get_function_code()
            if function_code:
                file_code += function_code + b'\n'
        if file_code:
            with open(file_path, "wb") as file:
                file.write(file_code)

    def write_files_to_file(self, files_models, file_path):
        file_code = b''
        for file_model in files_models:
            functions_models = get_models_by_ids(redis_session=self.redis_session,
                                                 model_ids=file_model.get_contained_nodes_ids())
            for function in functions_models:
                self.replace_wrapped_functions(function)
                function_code = function.get_function_code()
                if function_code:
                    file_code += function_code + b'\n'
        if file_code:
            with open(file_path, "wb") as file:
                file.write(file_code)

    def replace_wrapped_functions(self, function_model: FunctionModel):
        called_wrapper_functions = function_model.get_called_functions_wrapper()
        function_code = function_model.get_function_code()
        if called_wrapper_functions:
            if function_code:
                for wrapper_function in called_wrapper_functions:
                    wrapped_function_name = APIWrapperModel(redis_session=self.redis_session,
                                                            function_id=wrapper_function.model_id).get_api_name()
                    function_address = FunctionModel(redis_session=self.redis_session,
                                                     function_id=wrapper_function.model_id).contained_address
                    hex_address = hex(int(function_address.decode())).split('x')[1]
                    function_code = function_code.replace(b'function_' + str(hex_address).encode(),
                                                          wrapped_function_name)
                function_model.set_function_code(function_code)
