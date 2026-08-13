package com.cerberus.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MailService {

    // Auto-configured by spring-boot-starter-mail from the spring.mail.*
    // properties in application.yml -- currently pointed at Mailhog, so
    // nothing actually leaves your machine while developing locally.
    private final JavaMailSender mailSender;

    @Value("${app.base-url}")
    private String baseUrl;

    public void sendVerificationEmail(String to, String token) {
        String link = baseUrl + "/api/auth/verify-email?token=" + token;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Verify your Cerberus account");
        message.setText("Click to verify your email:\n" + link + "\n\nThis link expires in 24 hours.");
        mailSender.send(message);
    }

    public void sendPasswordResetEmail(String to, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Reset your Cerberus password");
        message.setText(
                "Use this token to reset your password: " + token +
                "\n\nThis link expires in 1 hour." +
                "\nIf you didn't request this, you can safely ignore this email."
        );
        mailSender.send(message);
    }
}
