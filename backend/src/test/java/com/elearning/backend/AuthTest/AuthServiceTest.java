package com.elearning.backend.AuthTest;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.util.Optional;
import com.elearning.backend.entity.Role;
import com.elearning.backend.entity.User;
import com.elearning.backend.repository.StudentRepository;
import com.elearning.backend.repository.UserRepository;
import com.elearning.backend.dto.AuthDTO;
import com.elearning.backend.security.JwtService;
import com.elearning.backend.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.crypto.password.PasswordEncoder;


class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private StudentRepository studentRepo;

    @Mock
    private JwtService jwtService;



    @InjectMocks
    private AuthService authService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void shouldFindUserByEmail() {
        User user = new User();
        user.setEmail("test@example.com");

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));

        Optional<User> result = authService.findByEmail("test@example.com");

        assertTrue(result.isPresent());
        assertEquals("test@example.com", result.get().getEmail());
    }

    @Test
    void shouldUpdatePasswordSuccessfully() {
        User user = new User();
        user.setEmail("test@example.com");
        user.setPassword("oldPassword");

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("newPassword")).thenReturn("hashedNewPassword");

        authService.updatePassword("test@example.com", "newPassword");

        verify(userRepository, times(1)).save(user);
        assertEquals("hashedNewPassword", user.getPassword());
    }

    @Test
    void shouldNotUpdatePasswordIfUserNotFound() {
        when(userRepository.findByEmail("missing@example.com")).thenReturn(Optional.empty());

        authService.updatePassword("missing@example.com", "newPassword");

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void shouldRegisterNewUserSuccessfully() {
        // Arrange: Create a signup request
        AuthDTO.SignupRequest request = new AuthDTO.SignupRequest(
                "Jane Doe",
                "jane@example.com",
                "securePass",
                Role.STUDENT
        );

        // Mock repository and service behavior
        when(userRepository.existsByEmail(request.email())).thenReturn(false);
        when(passwordEncoder.encode("securePass")).thenReturn("hashedSecurePass");
        when(userRepository.saveAndFlush(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
        when(jwtService.generateToken(eq(request.email()), anyMap())).thenReturn("mockToken");

        // Act: Call the signup method
        AuthDTO.AuthResponse response = authService.signup(request);

        // Assert: Verify the response
        assertEquals("jane@example.com", response.email());
        assertEquals("Jane Doe", response.fullName());
        assertEquals(Role.STUDENT, response.role());
        assertEquals("mockToken", response.token());

        // Verify interactions
        verify(userRepository, times(1)).existsByEmail(request.email());
        verify(passwordEncoder, times(1)).encode("securePass");
        verify(userRepository, times(1)).saveAndFlush(any(User.class));
        verify(jwtService, times(1)).generateToken(eq(request.email()), anyMap());
    }

    @Test
    void shouldLoginSuccessfully() {
        // Arrange: Create a login request
        AuthDTO.LoginRequest request = new AuthDTO.LoginRequest(
                "john@example.com",
                "securePass"
        );

        // Create a mock user
        User user = new User();
        user.setId(1L);
        user.setFullName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword("hashedSecurePass");
        user.setRole(Role.STUDENT);

        // Mock repository and service behavior
        when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("securePass", "hashedSecurePass")).thenReturn(true);
        when(jwtService.generateToken(eq("john@example.com"), anyMap())).thenReturn("mockToken");

        // Act: Call the login method
        AuthDTO.AuthResponse response = authService.login(request);

        // Assert: Verify the response
        assertEquals(1L, response.id());
        assertEquals("John Doe", response.fullName());
        assertEquals("john@example.com", response.email());
        assertEquals(Role.STUDENT, response.role());
        assertEquals("mockToken", response.token());

        // Verify interactions
        verify(userRepository, times(1)).findByEmail("john@example.com");
        verify(passwordEncoder, times(1)).matches("securePass", "hashedSecurePass");
        verify(jwtService, times(1)).generateToken(eq("john@example.com"), anyMap());
    }

}

