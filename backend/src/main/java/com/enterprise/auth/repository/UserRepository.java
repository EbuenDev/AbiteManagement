package com.enterprise.auth.repository;

import com.enterprise.auth.entity.RoleName;
import com.enterprise.auth.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    @Query("SELECT u FROM User u WHERE LOWER(u.username) = LOWER(:identifier) OR LOWER(u.email) = LOWER(:identifier)")
    Optional<User> findByIdentifier(@Param("identifier") String identifier);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    @Query("SELECT COUNT(u) > 0 FROM User u JOIN u.roles r WHERE r.code = :roleCode")
    boolean existsByRoleCode(@Param("roleCode") RoleName roleCode);

    @Query("SELECT COUNT(u) FROM User u JOIN u.roles r WHERE r.code = :roleCode")
    long countByRoleCode(@Param("roleCode") RoleName roleCode);

    Optional<User> findByUsernameIgnoreCase(String username);

    Optional<User> findByEmailIgnoreCase(String email);

    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.code = :roleCode")
    Page<User> findAllByRoleCode(@Param("roleCode") RoleName roleCode, Pageable pageable);
}
