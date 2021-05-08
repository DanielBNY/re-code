import os
from flask import send_file
from flask import Flask, request

from src.ReCodeActionsRunner import ReCodeActionsRunner
from PathSource import get_file_to_analyze_directory_path, get_recovered_code_zip_path
from src.ReCodeActions.Cleanup.Cleanup import folders_recreation
app = Flask(__name__)


@app.route('/')
def form():
    return """
<html>
   <body>
      <form action = "http://localhost:5000/uploader" method = "POST"
         enctype = "multipart/form-data">
         <input type = "file" name = "file" />
         <input type = "submit"/>
      </form>
   </body>
</html>
"""


@app.route('/uploader', methods=['POST', 'GET'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        folders_recreation()
        file.save(os.path.join(get_file_to_analyze_directory_path(), file.filename))
        ReCodeActionsRunner(redis_ip='localhost', mongo_ip='localhost',
                            file_name_to_analyze=file.filename).run()
        return "Finished Analyzing"


@app.route('/download')
def down_load_file():
    return send_file(get_recovered_code_zip_path(), as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)
