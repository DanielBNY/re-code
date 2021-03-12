## re-code

re-code is a reverse engineering tool that reconstructs a project file hierarchy from a binary. Like developers, reverse
engineers can benefit from a hierarchy view of a project instead of only a function view.

The binary file hierarchy is gained by these steps:
1) Creating a directed call graph from functions calling relations. (node: function, edge: call to a function)
2) Detecting entry points, functions with no input calls. Detecting nodes with multiple entries
2) Creating trees from the function's graph, by traversing the graph from the entry points nodes +
   multiple entries nodes in a 'level-order', edge to a node with multiple entries is skipped.
4) Connecting the trees with the multiple entries nodes.
5) Clustering the functions tree to create the files tree. The clustering has a max file size.
6) Clustering the files tree to create the folders tree. The clustering has a max number of files in a folder.
7) Creating folders and files inside them by using the files and folder trees.

Main usages:
The used databases are MongoDB and Redis to store extracted and analyzed data. The extracted data from radare2 is saved
in MongoDB, the models are saved in Redis, The used reverse engineering tools are radare2 and retdec. Radare2 r2pipe is
used to extract the functions calls and retdec is used to decompile the binary.

https://github.com/radareorg/radare2-r2pipe
https://github.com/avast/retdec
https://github.com/redis/redis
https://github.com/mongodb/mongo

## Use

#### Step 1: installing and moving the decompiler
The FirstProjectFolder/RetdecDecompiler need to contain the retdec decompiler. 
1) Install it from https://github.com/avast/retdec/releases/ (version 4.0)
2) Extract the content. 
3) Copy the content from the first retdec folder, So the first folders in this directory would be: bin, include, lib, share

#### Step 2: install docker on your system
https://docs.docker.com/engine/install/

#### Step 3: pull redis image
`sudo docker pull redis:6.2.1`

#### Step 4: pull mongodb image
`sudo docker pull mongo:4.0`

#### Step 5: creating a redis container
`sudo docker run -d --name redis -p 6379:6379 redis`

#### Step 6: creating a mongo container
`sudo docker run -d --name mongo -p 27017:27017 mongo`

#### Step 7: start a redis and a mongo container 
`sudo docker ps -a` Return a table the container id is in the first column, and the container name at the last column
`sudo docker start REDIS_CONTAINER_ID`
`sudo docker start MONGO_CONTAINER_ID`

#### Step 8: install packages
`pip install -r requirements`

#### Step 9: run the /ExtractorsManager.py
