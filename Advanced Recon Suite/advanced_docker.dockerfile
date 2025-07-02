FROM python:3.10-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    whatweb \
    whois \
    git \
    chromium \          
    wget \             
    build-essential \    
    libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev \ 
    && rm -rf /var/lib/apt/lists/*

RUN wget https://github.com/sensepost/gowitness/releases/download/2.5.0/gowitness-2.5.0-linux-amd64 -O /usr/local/bin/gowitness && \
    chmod +x /usr/local/bin/gowitness

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "advanced_recon.py"]
