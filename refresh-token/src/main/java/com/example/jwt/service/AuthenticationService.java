package com.example.jwt.service;

import com.example.jwt.dto.UserDto;
import com.example.jwt.dto.UserRequest;
import com.example.jwt.dto.UserResponse;
import com.example.jwt.enums.Role;
import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    private final PasswordEncoder passwordEncoder;

    public UserResponse save(UserDto userDto) {
        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nameSurname(userDto.getNameSurname())
                .role(Role.USER).build();
        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        return UserResponse
                .builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public UserResponse auth(UserRequest userRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userRequest.getUsername(), userRequest.getPassword()));
        User user = userRepository.findByUsername(userRequest.getUsername()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        return UserResponse
                .builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String header = request.getHeader("Authorization");
        final String refreshToken;
        final String username;
        if (header == null || !header.startsWith("Bearer ")) {
            return;
        }
        refreshToken = header.substring(7);
        username = jwtService.findUsername(refreshToken);

        if (username != null) {
            Optional<User> optionalUser = userRepository.findByUsername(username);

            // refresh token valid ise
            if (optionalUser.isPresent() && jwtService.tokenControl(refreshToken, optionalUser.get())) {
                UserDetails user = optionalUser.get();
                String jwtToken = jwtService.generateToken(user);
                UserResponse userResponse = UserResponse
                        .builder()
                        .accessToken(jwtToken)
                        .refreshToken(refreshToken)
                        .build();

                // kullanıcıya yeni access token'ı vereceğiz ancak fonksiyonumuz void return değerine sahip.
                // o yüzden bu işlemi yapıyoruz.
                new ObjectMapper().writeValue(response.getOutputStream(), userResponse);
            }
            // refresh token valid değil ise kullanıcı tekrar login olmak zorunda
        }
    }
}