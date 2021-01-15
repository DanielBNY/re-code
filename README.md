# re-code
re-code is a reverse engineering tool that reconstructs a project file hierarchy from a binary. 
Like developers, reverse engineers can benefit from a hierarchy view of a project instead of only a function view.

The binary file hierarchy is gained by those steps:
1) Creates a directed call graph from functions calling relations. (node: function, edge: call to a function)
2) Detecting entry points, functions with no input calls
2) Creates a files tree from the function's graph, by traversing the graph from the entry points in a 'level-order', 
   edge to an un-connected node in the tree is used, an edge that points to a pre-visited node is skipped.
3) Cluster the functions tree to create the files tree. The clustering has a max file size.
4) Cluster the files tree to create the folders tree. The clustering has a max number of files in a folder.
5) Creates folders and files inside them by using the files and folder trees.


Main usages:
The used databases are MongoDB and Redis to store extracted and analyzed data. 
The extracted data are saved on the MongoDB, the analyzed data are saved and manipulated on the Redis DB,
The reverse engineering tools used are radare2 and retdec.
Radare2 r2pipe is used to extract the functions calls and retdec is used to decompile the binary.

https://github.com/radareorg/radare2-r2pipe
https://github.com/avast/retdec
https://github.com/redis/redis
https://github.com/mongodb/mongo
