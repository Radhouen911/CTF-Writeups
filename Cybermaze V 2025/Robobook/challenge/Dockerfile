FROM node:18-alpine

# Create non-root user
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy application files
COPY --chown=nodejs:nodejs . .

# Create secrets directory
RUN mkdir -p /app/secrets && chown nodejs:nodejs /app/secrets

# Make all files read-only except node_modules and secrets
RUN find /app -type f -not -path "*/node_modules/*" -exec chmod 444 {} \; && \
    find /app -type d -not -path "*/node_modules/*" -exec chmod 555 {} \; && \
    chmod 755 /app/secrets && \
    chmod 644 /app/secrets/*

# Harden the container - Remove dangerous binaries
# Allowed: ping, ls, base64, tac, diff, rev (and sh/ash for Docker)
# Server-side blacklist will prevent sh/ash usage
RUN rm -f /usr/bin/wget /usr/bin/curl \
    /usr/bin/nc /usr/bin/netcat /usr/bin/telnet \
    /sbin/apk \
    /bin/chmod /bin/chown /bin/chgrp \
    /bin/mount /bin/umount \
    /usr/bin/find /usr/bin/xargs \
    /usr/bin/awk /usr/bin/sed /usr/bin/grep \
    /usr/bin/vi /usr/bin/vim /usr/bin/nano \
    /usr/bin/tar /usr/bin/gzip /usr/bin/unzip \
    /usr/bin/ssh /usr/bin/scp /usr/bin/sftp \
    /bin/cat /usr/bin/more /usr/bin/less \
    /usr/bin/head /usr/bin/tail /usr/bin/strings \
    /usr/bin/hexdump /usr/bin/od /usr/bin/xxd \
    /usr/bin/cut /usr/bin/paste /usr/bin/sort \
    /usr/bin/uniq /usr/bin/comm /usr/bin/join \
    /usr/bin/split /usr/bin/nl /usr/bin/pr \
    /usr/bin/fold /usr/bin/fmt /usr/bin/expand \
    /usr/bin/unexpand /usr/bin/wc /usr/bin/file \
    /usr/bin/stat /bin/cp /bin/mv /bin/ln

# Switch to non-root user
USER nodejs

EXPOSE 4000

CMD ["node", "server.js"]
