FROM alpine:3.17
RUN apk --no-cache add python3 py3-pip
RUN mkdir /app
RUN adduser -D dtrack-user && chown -R dtrack-user /app
WORKDIR /app
COPY ./dtrackauditor /app/dtrackauditor
COPY ./requirements.txt /app/requirements.txt
RUN ["chmod", "+x", "/app/dtrackauditor/dtrackauditor.py"]
RUN pip3 install -r /app/requirements.txt
ENV PYTHONPATH=/app
USER dtrack-user
ENTRYPOINT ["python3", "/app/dtrackauditor/dtrackauditor.py"]