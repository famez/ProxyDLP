function FindProxyForURL(url, host) {
    // Define OpenAI-related domains
    if (
        dnsDomainIs(host, "openai.com") ||      //ChatGPT
        dnsDomainIs(host, "chatgpt.com") ||     //ChatGPT
        dnsDomainIs(host, "oaiusercontent.com") || //ChatGPT
        dnsDomainIs(host, "substrate.office.com") || //Microssoft Copilot
        dnsDomainIs(host, "sharepoint.com") || //Microssoft Copilot
        dnsDomainIs(host, "graph.microsoft.com") //Microssoft Copilot

    ) {
        return "PROXY localhost:8080";  // Replace with your actual proxy
    }

    // All other traffic bypasses proxy
    return "DIRECT";
}
