FROM python:3.8-buster

WORKDIR /code

COPY requirements.txt .
RUN pip install -r requirements.txt
RUN echo "deb http://ftp.debian.org/debian testing main contrib non-free" >> /etc/apt/sources.list
RUN apt-get update && apt-get install -y build-essential

RUN apt-get update && apt-get install -y --no-install-recommends wget

RUN apt-get update && apt-get install -y --no-install-recommends tar
RUN wget https://github.com/radareorg/radare2/releases/download/5.2.1/radare2_5.2.1_amd64.deb
RUN apt-get install -y --no-install-recommends ./radare2_5.2.1_amd64.deb
RUN wget https://github.com/avast/retdec/releases/download/v4.0/retdec-v4.0-debian-64b.tar.xz -O RetdecDecompiler.tar.xz
RUN tar -xvf RetdecDecompiler.tar.xz

RUN apt-get update && apt-get install -y --no-install-recommends mongo-tools
COPY . .

EXPOSE 5000

CMD [ "python", "./main.py" ]

