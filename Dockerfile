FROM alpine:3.21

# Install Python3, pip3, and virtualenv
RUN apk --no-cache add python3 py3-pip py3-virtualenv

# Create a non-root user and application directory
RUN adduser -D dtrack-user && mkdir /app && chown -R dtrack-user /app

# Set the working directory
WORKDIR /app

# Create a virtual environment and install dependencies
RUN virtualenv venv && \
    . venv/bin/activate && \
    pip3 install dtrack-auditor

# Switch to the non-root user
USER dtrack-user

# Set the entrypoint to use the virtual environment
ENTRYPOINT ["/app/venv/bin/dtrackauditor"]