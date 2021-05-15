import os
from flask import send_file
from flask import Flask, request
from flask import render_template, send_from_directory

from src.ReCodeActions.ReCodeActionsRunner import ReCodeActionsRunner
from PathSource import get_file_to_analyze_directory_path, get_recovered_code_zip_path
from src.Cleanup import folders_recreation

app = Flask(__name__)


@app.route('/')
def root():
    return render_template('index.html')


@app.route('/Logo')
def logo():
    return send_from_directory('templates', 'Logo.PNG')


@app.route('/uploader', methods=['POST', 'GET'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        folders_recreation()
        file.save(os.path.join(get_file_to_analyze_directory_path(), file.filename))
        ReCodeActionsRunner(redis_ip='localhost', mongo_ip='localhost',
                            file_name_to_analyze=file.filename).run()
        return send_file(get_recovered_code_zip_path(), as_attachment=True)


def main():
    app.run(debug=True)


if __name__ == '__main__':
    main()
