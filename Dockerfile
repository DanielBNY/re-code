FROM python:3

WORKDIR /code

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.5 \
    python3-pip \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends wget

RUN apt-get update && apt-get install -y --no-install-recommends tar

COPY . .
RUN pip install -r requirements.txt
RUN wget https://github.com/avast/retdec/releases/download/v4.0/retdec-v4.0-debian-64b.tar.xz -O RetdecDecompiler.tar.xz
RUN tar -xvf RetdecDecompiler.tar.xz

CMD [ "python", "main.py" ]

