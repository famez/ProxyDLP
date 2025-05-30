FROM node:18

WORKDIR /usr/src/app

COPY web/package*.json ./
RUN npm install

COPY web/. .

COPY proto/monitor.proto .

EXPOSE 3000
CMD ["node", "server.js"]
