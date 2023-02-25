FROM alpine:3.17
RUN apk --no-cache add python3 py3-pip
RUN mkdir /app
RUN adduser -D dtrack-user && chown -R dtrack-user /app
RUN pip3 install dtrack-auditor
USER dtrack-user
ENTRYPOINT ["dtrackauditor"]