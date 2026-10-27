package com.enterprise.auth.repository;

import com.enterprise.auth.entity.Role;
import com.enterprise.auth.entity.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByCode(RoleName code);
}
