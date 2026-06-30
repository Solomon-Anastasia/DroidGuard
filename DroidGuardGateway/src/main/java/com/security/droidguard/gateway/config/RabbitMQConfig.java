package com.security.droidguard.gateway.config;

import org.springframework.amqp.core.*;
import org.springframework.amqp.support.converter.JacksonJsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitMQConfig {

    @Value("${rabbitmq.analysis.queue}")
    private String queueName;

    @Value("${rabbitmq.analysis.exchange}")
    private String exchangeName;

    @Value("${rabbitmq.analysis.routing-key}")
    private String routingKey;

    @Bean
    public Queue analysisJobsQueue() {
        return QueueBuilder.durable(queueName)
                .withArgument("x-max-length", 10_000)
                .build();
    }

    @Bean
    public DirectExchange analysisExchange() {
        return new DirectExchange(exchangeName);
    }

    @Bean
    public Binding bindingAnalysis(Queue analysisJobsQueue, DirectExchange analysisExchange) {
        return BindingBuilder
                .bind(analysisJobsQueue)
                .to(analysisExchange)
                .with(routingKey);
    }

    @Bean
    public MessageConverter jsonMessageConverter() {
        return new JacksonJsonMessageConverter();
    }
}