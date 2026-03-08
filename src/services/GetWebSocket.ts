function GetWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws-api/`;

    // Fallback to process.env for testing environments where window is undefined
    const connectStr = typeof window !== 'undefined' ? wsUrl : process.env.NEXT_PUBLIC_WEBSOCKET_CONNECT;
    const websocket = new WebSocket(connectStr!);
    return websocket;
}

export default GetWebSocket;