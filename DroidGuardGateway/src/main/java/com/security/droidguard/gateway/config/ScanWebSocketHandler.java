package com.security.droidguard.gateway.config;

import lombok.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class ScanWebSocketHandler extends TextWebSocketHandler {
    private final ConcurrentHashMap<String, WebSocketSession> activeSessions = new ConcurrentHashMap<>();

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        String path = Objects.requireNonNull(session.getUri()).getPath();
        String jobId = path.substring(path.lastIndexOf('/') + 1);

        activeSessions.put(jobId, session);
        System.out.println("Android client connected via WebSocket for Job ID: " + jobId);
    }

    @Override
    public void afterConnectionClosed(@NonNull WebSocketSession session, @NonNull CloseStatus status) {
        activeSessions.values().remove(session);
    }

    public void sendPayloadToClient(String jobId, String jsonPayload) {
        WebSocketSession session = activeSessions.get(jobId);
        if (session != null && session.isOpen()) {
            try {
                session.sendMessage(new TextMessage(jsonPayload));

                Thread.sleep(100);
                session.close();
                activeSessions.remove(jobId);
            } catch (IOException e) {
                System.out.println("Error while sending payload: " + e.getMessage());
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public void sendProgressToClient(String jobId, String jsonPayload) {
        WebSocketSession session = activeSessions.get(jobId);
        if (session != null && session.isOpen()) {
            try {
                session.sendMessage(new TextMessage(jsonPayload));
            } catch (IOException e) {
                System.out.println("Error while sending progress: " + e.getMessage());
            }
        }
    }
}