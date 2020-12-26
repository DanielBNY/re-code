import redis
import matplotlib.pyplot as plt
import networkx as nx

REDIS_SERVER_IP = 'localhost'


def visualize_graph(graph_name):
    """
    graph: functions, files, folders
    visualize the models graph relations with networkx and matplotlib
    """
    graph = nx.DiGraph()
    redis_session = redis.Redis(REDIS_SERVER_IP)
    model_names = redis_session.smembers(graph_name)
    for model_name in model_names:
        graph.add_node(str(model_name))
        model_info = dict(redis_session.hgetall(model_name))
        calls_out_set_id = model_info[b'calls_out_set_id']
        calls_out = redis_session.smembers(calls_out_set_id)
        for called_model_name in calls_out:
            graph.add_edge(str(model_name), str(called_model_name))
    nx.draw(graph)
    plt.show()
