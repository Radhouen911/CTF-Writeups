FROM python:3.9-slim

RUN apt-get update && \
    apt-get install -y nginx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 ctf

WORKDIR /app

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY app/ /app/
COPY flag.txt /flag.txt
COPY start.sh /start.sh

RUN chmod +x /start.sh && \
    chmod 444 /flag.txt && \
    chown -R ctf:ctf /app && \
    mkdir -p /var/lib/nginx && \
    chown -R ctf:ctf /var/lib/nginx /run

USER ctf

EXPOSE 5002

CMD ["/start.sh"]
