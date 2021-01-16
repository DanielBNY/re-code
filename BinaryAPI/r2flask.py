from flask import Flask, request, Response
import r2pipe
import redis

LOCAL_URL = {'host': 'localhost', 'port': 5000}


class BinaryAnalysis:
    def __init__(self):
        self.command_pipe = None
        self.redis_session = redis.Redis('localhost')

    def set_command_pipe(self, binary_path):
        self.command_pipe = r2pipe.open(binary_path)


app = Flask(__name__)
BIN_ANALYSIS = BinaryAnalysis()


@app.route('/init/', methods=['POST'])
def init():
    data = request.json
    BIN_ANALYSIS.set_command_pipe(data['path'])
    BIN_ANALYSIS.command_pipe.cmd('aaaa')
    return Response(status=201)


@app.route('/close_session/', methods=['POST'])
def close_session():
    BIN_ANALYSIS.command_pipe.cmd('exit')
    BIN_ANALYSIS.command_pipe = None


@app.route('/command/<command>', methods=['POST'])
def pipe_command(command):
    return BIN_ANALYSIS.command_pipe.cmd(command)


@app.route('/decompile_function/<offset>', methods=['GET'])
def decompile_function(offset):
    code = BIN_ANALYSIS.command_pipe.cmd(f"s {offset}; #!pipe r2retdec")
    return code


@app.route('/functions_info_extractor/', methods=['GET'])
def functions_info_extractor():
    data = request.json
    BIN_ANALYSIS.command_pipe.cmd(f"aflj > {data['path']}")
    return Response(status=200)


@app.route('/functions_addresses/', methods=['GET'])
def get_functions_addresses():
    functions_addresses = BIN_ANALYSIS.command_pipe.cmd(f"s @@ fcn.*")
    functions_addresses_list = functions_addresses.split('\n')
    for address in functions_addresses_list:
        BIN_ANALYSIS.redis_session.sadd('r2_functions_addresses', int(address, 16))
    return Response(status=200)


if __name__ == '__main__':
    app.run(host=LOCAL_URL['host'], port=LOCAL_URL['port'])
