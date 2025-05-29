# ProxyGPT
A proxy to detect and monitor Data Leakage through AI tools

The idea is to let in an enterprise or organization, the employees to use free AI tools for speeding productivity while at the same time, ensuring a minimal of privacy and confidentiality on the conversations and attached files on AI tools.

Roadmap

- Detect if we are using a company account or a personal account
- Monitor uploaded files and decode/parse PDFs, excels to plain text 
- Detect embedded images and standalone images and apply OCR to extract text
- Monitor conversations.
- Apply configurable regular expressions to detect data leakage.
- Apply ML detection based on Name Entity Recognition and sentence-transformers with cosine similarity.
- Get telemetry / user behaviour of the AI applications on a dashboard to have more visibility on your company

- Integration with ChatGPT --> On GOING
- Integration with Microsoft Copilot
- Integration with DeepSeek
- ???

#Instructions

1. Optional: Generate auto-signed certificate (Root CA used by Mitmproxy to generate certificates on the fly for the sites) with private key and copy them to:
- ./proxy/mitmCA.key
- ./proxy/mitmCA.pem

2. Optional: Generate certificate with private key for nginx WEB server signed by CA or autosigned and copy them to:
- ./nginx/server.key
- ./nginx/server.crt

3. Execute ./generate_secrets.sh. If the previous certificates were not generated, this command will generate and populate auto-signed certificates on the needed folders. This command also creates a random secret key for JWT token generation and MongoDB password.

4. Execute docker-compose up

This will build all the containers.

The Web page is available on https port 443 and the MiTM proxy, on port 8080.

You must ensure that the traffic to the monitored sites from the workstations reaches de proxy, by system proxy general configuration or by using PAC file. This can be easily achieved in Windows via Global Policy Objects.

You must also configure the CA certificate mitmCA.pem as a trusted certificate on Windows workstations via Global Policy Objects. 