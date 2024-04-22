package dev.taras.hamkalo.spring.repository;

import dev.taras.hamkalo.spring.enity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

  Optional<User> findUserByUsername(String username);

  boolean existsUserByUsername(String username);

}