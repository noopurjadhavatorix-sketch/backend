import { WebSocket, WebSocketServer } from 'ws';
import Submission from '../models/Submission.js';

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

  broadcastNewSubmission(submission) {
    if (!this.clients || this.clients.size === 0) return;
    
    const message = JSON.stringify({
      type: 'NEW_SUBMISSION',
      data: submission
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

  broadcastUpdate(submission) {
    const message = JSON.stringify({
      type: 'UPDATE_SUBMISSION',
      data: submission
    });

    this.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  }

  broadcastDelete(id) {
    const message = JSON.stringify({
      type: 'DELETE_SUBMISSION',
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
