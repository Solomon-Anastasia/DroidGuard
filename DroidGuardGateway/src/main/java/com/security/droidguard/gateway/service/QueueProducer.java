package com.security.droidguard.gateway.service;

import com.security.droidguard.gateway.model.dto.AnalysisJobMessage;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class QueueProducer {

    private final RabbitTemplate rabbitTemplate;

    @Value("${rabbitmq.analysis.exchange}")
    private String exchangeName;

    @Value("${rabbitmq.analysis.routing-key}")
    private String routingKey;

    @Autowired
    public QueueProducer(RabbitTemplate rabbitTemplate) {
        this.rabbitTemplate = rabbitTemplate;
    }

    public void sendJobToQueue(AnalysisJobMessage message) {
        rabbitTemplate.convertAndSend(exchangeName, routingKey, message);
    }
}