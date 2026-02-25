package com.diegoveliz.auth_api_jwt.service;

import com.diegoveliz.auth_api_jwt.dto.LoginRequest;
import com.diegoveliz.auth_api_jwt.dto.RegisterRequest;
import com.diegoveliz.auth_api_jwt.model.Role;
import com.diegoveliz.auth_api_jwt.model.User;
import com.diegoveliz.auth_api_jwt.repository.UserRepository;
import com.diegoveliz.auth_api_jwt.security.JwtService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;    //encripta la contraseña
    private final JwtService jwtService;    //genera y valida el token

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    public String register(RegisterRequest request) {

        //primero validamos que el usuario no exista
        if (userRepository.existsByUsername(request.getUsername())) {
            return "Username already exists";
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            return "Email already exists";
        }

        //si no existe, creamos el usuario
        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.ROLE_USER);

        userRepository.save(user);

        return "User registered successfully";
    }

    public String login(LoginRequest request) {

        //primero validamos que el usuario exista
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        //validamos la contraseña
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        //generamos el token
        return jwtService.generateToken(user.getUsername());
    }
}