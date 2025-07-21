package com.java.petrovsm.authorizationservice.config;

import com.java.petrovsm.authorizationservice.model.ERole;
import com.java.petrovsm.authorizationservice.model.Role;
import com.java.petrovsm.authorizationservice.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
@ConditionalOnProperty(name = "app.init.roles", havingValue = "true", matchIfMissing = true)
public class DatabaseInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;

    @Override
    public void run(String... args) {
        log.info("Начинаем инициализацию ролей...");

        int createdRolesCount = 0;
        for (ERole role : ERole.values()) {
            if (roleRepository.findByName(role).isEmpty()) {
                Role newRole = new Role(role);
                roleRepository.save(newRole);
                log.info("✅ Создана роль: {}", role);
                createdRolesCount++;
            } else {
                log.debug("Роль уже существует: {}", role);
            }
        }

        if (createdRolesCount > 0) {
            log.info("Инициализация ролей завершена. Создано новых ролей: {}", createdRolesCount);
        } else {
            log.info("Все роли уже существуют. Инициализация не требуется.");
        }
    }
}
