from flask import Flask, request
import r2pipe


class BinaryAnalysis:
    def __init__(self):
        self.command_pipe = None

    def set_command_pipe(self, binary_path):
        self.command_pipe = r2pipe.open(binary_path)


app = Flask(__name__)
BIN_ANALYSIS = BinaryAnalysis()


@app.route('/init/', methods=['POST'])
def init():
    data = request.json
    BIN_ANALYSIS.set_command_pipe(data['path'])
    BIN_ANALYSIS.command_pipe.cmd('aaaa')


@app.route('/close_session/', methods=['POST'])
def close_session():
    return BIN_ANALYSIS.command_pipe.cmd('exit')


@app.route('/command/<command>', methods=['POST'])
def pipe_command(command):
    return BIN_ANALYSIS.command_pipe.cmd(command)


if __name__ == '__main__':
    app.run()
