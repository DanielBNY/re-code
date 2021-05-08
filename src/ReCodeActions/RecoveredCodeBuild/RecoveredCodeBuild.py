import os
import redis
from typing import List
from zipfile import ZipFile

from src.ReCodeActions.Models import FolderModel, FileModel, Folders, Files, LonelyModels, \
    FunctionModel, APIWrapperModel, TreesEntriesFunctionsAddresses
from src.AbstractClasses import Action
from PathSource import get_recovered_code_directory_path, get_recovered_code_zip_path


class RecoveredCodeBuild(Action):
    def __init__(self, redis_session: redis.Redis):
        self.recovered_project_path = get_recovered_code_directory_path()
        self.redis_session = redis_session

    def run(self):
        """
        Build the sample structure with several steps:
        First get all the entry folders models (the trees heads).
        Creates the first folders, and then in recursion create the sons of the father folders.
        Sets all the files path and then write the functions inside the new files.
        Write all the functions with no connection in a lonely file.
        """
        entry_folders_models = TreesEntriesFunctionsAddresses(redis_session=self.redis_session).get_folders_models()
        self.create_folders_in_path(self.recovered_project_path.encode(), entry_folders_models)
        folders_to_revisit = entry_folders_models
        while folders_to_revisit:
            folders_to_revisit = self.create_folder_for_sons(folders_to_revisit)
        self.set_all_files_paths()
        self.write_functions_to_files()
        self.create_lonely_functions_file()
        output_zip_path = get_recovered_code_zip_path()
        self.zip_files_in_dir(self.recovered_project_path, output_zip_path)

    @staticmethod
    def zip_files_in_dir(dir_to_zip, zip_name):
        with ZipFile(zip_name, 'w') as zipObj:
            for folderName, sub_folders, filenames in os.walk(dir_to_zip):
                for filename in filenames:
                    file_path = os.path.join(folderName, filename)
                    zipObj.write(file_path, file_path.replace(dir_to_zip, ''))

    def create_lonely_functions_file(self):
        """
        Creates lonely functions in one file called lonely file.
        """
        lonely_files_models = LonelyModels(redis_session=self.redis_session).get_files_models()
        self.write_files_to_file(files=lonely_files_models,
                                 file_path=os.path.join(self.recovered_project_path.encode(), b'lonely_file'))

    def create_folder_for_sons(self, folders: List[FolderModel]):
        """
        :param folders: List of folder models

        Iterates over the input folders and create the sons of those folders.
        """
        folders_to_revisit = []
        for folder in folders:
            sons_models = folder.get_sons_models()
            self.create_folders_in_path(path=os.path.join(folder.get_folders_path(), folder.get_name()),
                                        folders=sons_models)
            folders_to_revisit += sons_models
        return folders_to_revisit

    @staticmethod
    def create_folders_in_path(path: bytes, folders: List[FolderModel]):
        """
        :param path: Path to create the folder.
        :param folders: List of folders to create in the path

        Creates folders in the target path.
        """
        for folder in folders:
            os.mkdir(os.path.join(path, folder.get_name()))
            folder.set_folders_path(path)

    def set_all_files_paths(self):
        """
        Iterates over all folders and set the contained files path.
        """
        folder_models = Folders(redis_session=self.redis_session).get_non_lonely_folders()
        for folder in folder_models:
            if folder.get_folders_path():
                full_path = os.path.join(folder.get_folders_path(), folder.get_name())
                files_models = folder.get_contained_files_models()
                self.set_files_paths(path=full_path, files_models=files_models)

    @staticmethod
    def set_files_paths(path: bytes, files_models: List[FileModel]):
        """
        :param path: The path to set for the file models.
        :param files_models: List of file models

        Sets for each file model the folder path.
        """
        for file_model in files_models:
            file_model.set_folders_path(path)

    def write_functions_to_files(self):
        """
        Iterates over all files and write the contained functions code into them.
        """
        files_models = Files(redis_session=self.redis_session).get_non_lonely_files()
        for file_model in files_models:
            if file_model.get_folders_path():
                file_path = os.path.join(file_model.get_folders_path(), file_model.get_name())
                functions_models = file_model.get_contained_functions_models()
                self.write_function_to_file(functions=functions_models, file_path=file_path)

    def write_function_to_file(self, functions: List[FunctionModel], file_path: bytes):
        """
        :param functions: List of functions models to be written into a file.
        :param file_path: Output file path.

        Write multiple functions into a file.
        """
        file_code = b''
        for function_model in functions:
            self.replace_wrapped_functions(function_model)
            function_code = function_model.get_function_code()
            if function_code:
                file_code += function_code + b'\n'
        if file_code:
            with open(file_path + b'.c', "wb") as file:
                file.write(file_code)

    def write_files_to_file(self, files: List[FileModel], file_path: bytes):
        """
        :param files: List of file models
        :param file_path: file path to write the code

        Write all the functions in files into one file.
        """
        file_code = b''
        for file_model in files:
            functions_models = file_model.get_contained_functions_models()
            for function in functions_models:
                self.replace_wrapped_functions(function)
                function_code = function.get_function_code()
                if function_code:
                    file_code += function_code + b'\n'
        if file_code:
            with open(file_path + b'.c', "wb") as file:
                file.write(file_code)

    def replace_wrapped_functions(self, function_model: FunctionModel):
        """
        :param function_model: Function model in which the code is manipulated.

        Replace wrapped function names with wrapped function name.
        For example a function calls the function 'function_123' that is wrapping the strcmp function.
        The replacement will change the called function name function_123 to strcmp.
        """
        called_wrapper_functions = function_model.get_called_functions_wrapper()
        function_code = function_model.get_function_code()
        if called_wrapper_functions:
            if function_code:
                for wrapper_function in called_wrapper_functions:
                    wrapped_function_name = APIWrapperModel(redis_session=self.redis_session,
                                                            function_id=wrapper_function.model_id).get_api_name()
                    function_address = FunctionModel(redis_session=self.redis_session,
                                                     function_id=wrapper_function.model_id).contained_function_address
                    hex_address = hex(int(function_address.decode())).split('x')[1]
                    function_code = function_code.replace(b'function_' + str(hex_address).encode(),
                                                          wrapped_function_name)
                function_model.set_function_code(function_code)
