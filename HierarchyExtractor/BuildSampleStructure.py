from Models import EntryModels, Folders, Files, get_models_by_ids

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
        self.create_files()
        self.write_functions_to_files()

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

    def create_files(self):
        folder_models = Folders(redis_session=self.redis_session).get_folder_models()
        for folder in folder_models:
            full_path = folder.get_folders_path() + b'/' + folder.model_id
            contained_files_ids = folder.get_contained_nodes_ids()
            files_models = get_models_by_ids(model_ids=contained_files_ids, redis_session=self.redis_session)
            self.create_files_in_path(path=full_path, models=files_models)

    @staticmethod
    def create_files_in_path(path, models):
        for model in models:
            open(path + b'/' + model.model_id, 'a').close()
            model.set_folders_path(path)

    def write_functions_to_files(self):
        files_models = Files(redis_session=self.redis_session).get_files_models()
        for file_model in files_models:
            file_path = file_model.get_folders_path() + b'/' + file_model.model_id
            with open(file_path, "wb") as file:
                functions_models = get_models_by_ids(model_ids=file_model.get_contained_nodes_ids(),
                                                     redis_session=self.redis_session)
                for function_model in functions_models:
                    file.write(function_model.get_function_code())
