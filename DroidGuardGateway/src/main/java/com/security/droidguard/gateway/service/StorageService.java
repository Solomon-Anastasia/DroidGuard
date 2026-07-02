package com.security.droidguard.gateway.service;

import com.security.droidguard.gateway.config.StorageProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class StorageService {
    private final Path rootLocation;

    @Autowired
    public StorageService(StorageProperties properties) {
        this.rootLocation = Paths.get(properties.getUploadDir()).toAbsolutePath().normalize();
    }

    public String saveFile(MultipartFile file, String filename) throws IOException {
        Path targetLocation = this.rootLocation.resolve(filename);

        if (!Files.exists(targetLocation)) {
            Files.copy(file.getInputStream(), targetLocation);
        }

        return targetLocation.toString();
    }
}
