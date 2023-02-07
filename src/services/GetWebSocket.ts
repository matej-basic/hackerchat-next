function GetWebSocket() {
    const websocket = new WebSocket(process.env.NEXT_PUBLIC_WEBSOCKET_CONNECT!);
    return websocket;
}

export default GetWebSocket;