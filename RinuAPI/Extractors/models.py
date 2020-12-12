class FunctionInfo:
    def __init__(self, address):
        """
        id: string
        file_id: string (id to hashes)
        calls_out_set_id: string (set id)
        calls_in_set_id: string (set id)
        """
        self.id = f"function:{address}"
        self.file_id = f"file:{address}"
        self.calls_out_set_id = f"function:{address}:calls_out"
        self.calls_in_set_id = f"function:{address}:calls_in"


class FileInfo:
    def __init__(self, file_id):
        """
        id: string
        folder_id: string (id to hashes)
        contained_functions: string (set id)
        calls_out_set_id: string (set id)
        calls_in_set_id: string (set id)
        """
        self.id = f"file:{file_id}"
        self.folder_id = f"folder:{file_id}"
        self.contained_functions_set_id = f"file:{file_id}:contained_functions"
        self.calls_out_set_id = f"file:{file_id}:calls_out"
        self.calls_in_set_id = f"file:{file_id}:calls_in"


class FolderInfo:
    def __init__(self, folder_id):
        """
        id: string
        contained_files: string (id to hashes)
        calls_out_set_id: string (set id)
        calls_in_set_id: string (set id)
        """
        self.id = f"folder:{folder_id}"
        self.contained_files_set_id = f"folder:{folder_id}:contained_files"
        self.calls_out_set_id = f"folder:{folder_id}:calls_out"
        self.calls_in_set_id = f"folder:{folder_id}:calls_in"
