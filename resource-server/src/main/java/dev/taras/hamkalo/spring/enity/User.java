package dev.taras.hamkalo.spring.enity;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.io.Serializable;


@Entity
@Getter
@Setter
@Table(name = "users")
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class User implements Serializable {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  Long id;

  @Column(nullable = false, unique = true)
  String username;

  @Column(nullable = false)
  String password;

}
