from django.db import models


class FunctionNode(models.Model):
    address = models.IntegerField(primary_key=True)


class FunctionEdge(models.Model):
    """
    Function Edge source is the calling function and destination is the called function
    """
    source = models.ForeignKey(FunctionNode, related_name="source", on_delete=models.CASCADE)
    destination = models.ForeignKey(FunctionNode, related_name="destination", on_delete=models.CASCADE)
