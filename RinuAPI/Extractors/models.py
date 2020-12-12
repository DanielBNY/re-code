class FunctionInfo:
    def __init__(self, size, address):
        """
        id: string
        size: string
        file_id: string (id to hashes)
        calls_out_set_id: string (set id)
        calls_in_set_id: string (set id)
        """
        self.id = address
        self.size = size
        self.file_id = f"file:{address}"
        self.calls_out_set_id = f"function:{address}:calls_out"
        self.calls_in_set_id = f"function:{address}:calls_in"


class FileInfo:
    def __init__(self, size, file_id):
        """
        id: string
        size: string
        folder_id: string (id to hashes)
        contained_functions: string (set id)
        calls_out_set_id: string (set id)
        calls_in_set_id: string (set id)
        """
        self.id = file_id
        self.size = size
        self.folder_id = f"folder:{file_id}"
        self.contained_functions_set_id = f"file:{file_id}:contained_functions"
        self.calls_out_set_id = f"file:{file_id}:calls_out"
        self.calls_in_set_id = f"file:{file_id}:calls_in"


class FolderInfo:
    def __init__(self, size, folder_id):
        """
        id: string
        size: string
        contained_files: string (id to hashes)
        calls_out_set_id: string (set id)
        calls_in_set_id: string (set id)
        """
        self.id = folder_id
        self.size = size
        self.contained_files_set_id = f"folder:{folder_id}:contained_files"
        self.calls_out_set_id = f"folder:{folder_id}:calls_out"
        self.calls_in_set_id = f"folder:{folder_id}:calls_in"
