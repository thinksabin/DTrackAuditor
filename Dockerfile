FROM alpine:3.12
RUN apk --no-cache add python3 py3-pip
COPY requirements.txt .
COPY dtrackauditor/dtrackauditor.py .
RUN chmod +x dtrackauditor.py
RUN pip install -r requirements.txt
ENTRYPOINT ["python3", "dtrackauditor.py"]