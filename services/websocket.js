import { WebSocket, WebSocketServer } from 'ws';
import DemoRequest from '../models/DemoRequest.js';

// Store connected clients

class WebSocketService {
  constructor(server) {
    this.wss = new WebSocketServer({ server, path: '/ws' });
    this.clients = new Set();
    this.setupWebSocket();
  }

  setupWebSocket() {
    this.wss.on('connection', (ws) => {
      console.log('New WebSocket connection');
      this.clients.add(ws);

      ws.on('close', () => {
        console.log('Client disconnected');
        this.clients.delete(ws);
      });

      ws.on('error', (error) => {
        console.error('WebSocket error:', error);
        this.clients.delete(ws);
      });
    });
  }

  broadcastNewDemoRequest(demoRequest) {
    if (!this.clients || this.clients.size === 0) return;
    
    const message = JSON.stringify({
      type: 'NEW_DEMO_REQUEST',
      data: demoRequest
    });

    this.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        try {
          client.send(message);
        } catch (error) {
          console.error('Error sending WebSocket message:', error);
        }
      }
    });
  }

  broadcastUpdate(demoRequest) {
    const message = JSON.stringify({
      type: 'UPDATE_DEMO_REQUEST',
      data: demoRequest
    });

    this.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  }

  broadcastDelete(id) {
    const message = JSON.stringify({
      type: 'DELETE_DEMO_REQUEST',
      data: { _id: id }
    });

    this.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  }
}

let webSocketService = null;

export const initWebSocket = (server) => {
  if (!webSocketService) {
    webSocketService = new WebSocketService(server);
    console.log('WebSocket service initialized');
  }
  return webSocketService;
};

export const getWebSocketService = () => webSocketService;
