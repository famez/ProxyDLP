function FindProxyForURL(url, host) {
    // Define OpenAI-related domains
    if (
        dnsDomainIs(host, "openai.com") ||
        dnsDomainIs(host, "chatgpt.com")
    ) {
        return "PROXY localhost:8080";  // Replace with your actual proxy
    }

    // All other traffic bypasses proxy
    return "DIRECT";
}
