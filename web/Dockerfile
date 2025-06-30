FROM node:18

# Create a non-root user and group, with home directory
RUN groupadd -r appgroup && useradd -r -m -g appgroup appuser

WORKDIR /usr/src/app

# Ensure home directory and npm cache dir exist and owned by appuser
RUN mkdir -p /home/appuser/.npm && chown -R appuser:appgroup /home/appuser

# Copy package files first with correct ownership
COPY --chown=appuser:appgroup web/package*.json ./

# Change ownership of workdir to non-root user before npm install
RUN chown -R appuser:appgroup /usr/src/app
RUN mkdir /sites/
RUN chown -R appuser:appgroup /sites/

USER appuser

# Install npm packages as non-root
RUN npm install --include=dev

# Copy app source files as non-root
COPY --chown=appuser:appgroup web/. .

COPY --chown=appuser:appgroup proto/monitor.proto .

RUN npm run build:css

EXPOSE 3000

CMD ["node", "server.js"]
