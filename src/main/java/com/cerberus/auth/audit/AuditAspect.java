package com.cerberus.auth.audit;

import com.cerberus.auth.entity.AuditLog;
import com.cerberus.auth.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;

@Aspect
@Component
@RequiredArgsConstructor
public class AuditAspect {

    private final AuditLogRepository auditLogRepository;

    // The pointcut expression "@annotation(audited)" means: run this advice
    // around ANY method, in ANY class, annotated with @Audited. We never
    // have to list which methods -- adding @Audited("SOMETHING") to a brand
    // new service method is enough to wire it into logging automatically.
    @Around("@annotation(audited)")
    public Object audit(ProceedingJoinPoint joinPoint, Audited audited) throws Throwable {
        String baseAction = audited.value();
        String actorEmail = extractActorEmail(joinPoint.getArgs());

        try {
            // proceed() is what actually calls the real method (register,
            // login, etc). Everything before this line runs BEFORE the real
            // method; everything in the try/catch below runs AFTER it.
            Object result = joinPoint.proceed();
            writeLog(baseAction + "_SUCCESS", actorEmail, null);
            return result;
        } catch (Throwable ex) {
            writeLog(baseAction + "_FAILURE", actorEmail, ex.getMessage());
            // Re-throw, always. An aspect's job is to OBSERVE, never to
            // swallow errors -- GlobalExceptionHandler still needs to see
            // this exception to turn it into the right HTTP response.
            throw ex;
        }
    }

    private String extractActorEmail(Object[] args) {
        // Reflection-based best effort: several audited methods take a DTO
        // with a getEmail() (RegisterRequest, LoginRequest), but others
        // (refresh, logout, verifyEmail) only take an opaque token string
        // upfront -- the actual email isn't known until AFTER the method
        // runs. That's a real, known gap: those methods' FAILURE logs will
        // show "unknown" as the actor. A more complete system might
        // correlate those via a hash of the token instead -- worth
        // knowing as a limitation, not hidden as if it doesn't exist.
        for (Object arg : args) {
            if (arg == null) continue;
            try {
                Method getEmail = arg.getClass().getMethod("getEmail");
                Object value = getEmail.invoke(arg);
                if (value instanceof String s && !s.isBlank()) {
                    return s;
                }
            } catch (NoSuchMethodException ignored) {
                // this argument doesn't expose an email -- expected for
                // several audited methods, not an error
            } catch (Exception ignored) {
                // reflective invoke failed for some other reason -- fall
                // through to the next arg rather than fail the whole request
            }
        }
        return "unknown";
    }

    private void writeLog(String action, String actorEmail, String failureDetail) {
        HttpServletRequest request = currentRequest();

        AuditLog log = AuditLog.builder()
                .actorEmail(actorEmail)
                .action(action)
                .ipAddress(request != null ? extractIp(request) : null)
                .userAgent(request != null ? request.getHeader("User-Agent") : null)
                .metadata(failureDetail)
                .build();

        auditLogRepository.save(log);
    }

    private HttpServletRequest currentRequest() {
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attrs != null ? attrs.getRequest() : null;
    }

    private String extractIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
