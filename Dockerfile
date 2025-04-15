# Use a lightweight base Python image
FROM python:3.9-slim

# Install OS packages like Tesseract and its libraries
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    poppler-utils \
    && rm -rf /var/lib/apt/lists/*

# Set working directory inside the container
WORKDIR /app

# Copy your project files into the container
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port Streamlit will run on
EXPOSE 10000

# Start Streamlit app
CMD ["streamlit", "run", "app.py", "--server.port=10000", "--server.enableCORS=false"]
