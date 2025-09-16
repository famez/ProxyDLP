# ---------- Stage 1: Build ProxyDLPAgent exe ----------
FROM ubuntu:24.04 AS builder

RUN apt-get update && \
    apt-get install -y \
        git \
        make \
        mingw-w64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Clone the ProxyDLPAgent repo
#RUN git clone --branch v1.1.0 --single-branch https://github.com/famez/ProxyDLPAgent.git

#For testing
RUN git clone https://github.com/famez/ProxyDLPAgent.git \
    && cd ProxyDLPAgent \
    && git checkout 173af1ebec2e90251a16e032811454e06e24b16a


WORKDIR /build/ProxyDLPAgent/src/

# Build Windows exe with mingw
RUN make

# ---------- Stage 2: Package with Inno Setup ----------
FROM ubuntu:24.04 AS installer

RUN dpkg --add-architecture i386

RUN apt-get update && \
    apt-get install -y wine wget unzip && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get install -y wine32:i386 wine64

RUN apt-get update && apt-get install -y software-properties-common && \
    add-apt-repository universe && apt-get update

RUN apt-get install -y xvfb cabextract

WORKDIR /iss

# Download Inno Setup (command-line compiler ISCC.exe)
RUN wget https://jrsoftware.org/download.php/is.exe -O innosetup.exe
RUN xvfb-run wine innosetup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-

# Copy exe from builder stage
COPY --from=builder /build/ProxyDLPAgent/src/build/proxydlp.exe ./proxydlp.exe
COPY --from=builder /build/ProxyDLPAgent/libs/*.dll ./
COPY --from=builder /build/ProxyDLPAgent/libs/*.sys ./

# Copy your Inno Setup script
COPY web/ProxyDLPAgent.iss .

#Copy the CA certificate to trust.
COPY web/mitmCA.pem .

# Copy .env file into the installer stage
COPY web/hostname .

# Replace "placeholder" with actual hostname
RUN PROXY_HOSTNAME=$(grep '^PROXY_HOSTNAME=' hostname | cut -d '=' -f2-) && \
    sed -i "s/#define ProxyHostname \".*\"/#define ProxyHostname \"$PROXY_HOSTNAME\"/" ProxyDLPAgent.iss && \
    wine "C:\\Program Files (x86)\\Inno Setup 6\\ISCC.exe" ProxyDLPAgent.iss


# ---------- Stage 3: Node.js web app ----------
FROM node:18

RUN groupadd -r appgroup && useradd -r -m -g appgroup appuser
WORKDIR /usr/src/app

COPY --chown=appuser:appgroup web/package*.json ./
RUN chown -R appuser:appgroup /usr/src/app
USER appuser

RUN npm install --include=dev

COPY --chown=appuser:appgroup web/. .
COPY --chown=appuser:appgroup proto/monitor.proto .
COPY --chown=appuser:appgroup proto/proxy.proto .

# Copy built installer into the volume
COPY --from=installer /iss/Output/ProxyDLPAgentSetup.exe /agentInstaller/ProxyDLPAgentSetup.exe

RUN npm run build:css

EXPOSE 3000
CMD ["node", "server.js"]
