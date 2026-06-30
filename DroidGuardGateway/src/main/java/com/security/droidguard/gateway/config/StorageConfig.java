package com.security.droidguard.gateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Configuration
public class StorageConfig {

    private static final Logger logger = LoggerFactory.getLogger(StorageConfig.class);
    private final StorageProperties storageProperties;

    @Autowired
    public StorageConfig(StorageProperties storageProperties) {
        this.storageProperties = storageProperties;
    }

    @Bean
    public boolean initStorageDirectory() {
        Path targetLocation = Paths.get(storageProperties.getUploadDir()).toAbsolutePath().normalize();

        try {
            if (!Files.exists(targetLocation)) {
                Files.createDirectories(targetLocation);
                logger.info("Initialized DroidGuard storage directory at: {}", targetLocation);
            } else {
                logger.info("Storage directory already exists at: {}", targetLocation);
            }
            return true;
        } catch (IOException ex) {
            logger.error("Could not create the directory where the uploaded files will be stored.", ex);
            throw new RuntimeException("Could not initialize storage directory", ex);
        }
    }
}