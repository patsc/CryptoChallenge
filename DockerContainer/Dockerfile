# Dockerfile for simple Crypto-Oracle

# Based simply on a Python 3 image
FROM python:3

# Directory where the application code is
ENV APP /app

# Create the directory and instruct Docker to
# work in the directory
RUN mkdir $APP
WORKDIR $APP

# Expose the port the application listens on
EXPOSE 5000

# Get the requirements file (Python dependencies)
COPY requirements.txt .

# Install Python dependencies
RUN pip install -r requirements.txt

# Copy the rest of the local codebase
COPY . .

# Run the server
CMD python app.py

