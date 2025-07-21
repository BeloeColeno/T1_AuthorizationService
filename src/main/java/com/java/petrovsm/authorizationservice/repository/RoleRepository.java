package com.java.petrovsm.authorizationservice.repository;

import com.java.petrovsm.authorizationservice.model.ERole;
import com.java.petrovsm.authorizationservice.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(ERole name);
}
