FROM python:3.8-buster

WORKDIR /code

COPY requirements.txt .
RUN pip install -r requirements.txt

RUN apt-get update && apt-get install -y --no-install-recommends wget

RUN apt-get update && apt-get install -y --no-install-recommends tar

COPY . .
RUN wget https://github.com/avast/retdec/releases/download/v4.0/retdec-v4.0-debian-64b.tar.xz -O RetdecDecompiler.tar.xz
RUN tar -xvf RetdecDecompiler.tar.xz
EXPOSE 5000

CMD [ "python", "./main.py" ]

