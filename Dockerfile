FROM alpine:3.17
RUN apk --no-cache add python3 py3-pip
WORKDIR /app
ADD dtrackauditor /app/dtrackauditor
ADD requirements.txt /app/requirements.txt
ADD dtrackauditor/dtrackauditor.py /app
RUN chmod +x /app/dtrackauditor.py
RUN pip3 install -r /app/requirements.txt
ENV PYTHONPATH=/app
ENTRYPOINT ["python3", "/app/dtrackauditor.py"]