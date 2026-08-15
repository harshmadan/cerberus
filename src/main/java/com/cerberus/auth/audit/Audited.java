package com.cerberus.auth.audit;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

// Purely a marker -- carries no behavior itself. All the actual logging
// logic lives in AuditAspect, which watches for this annotation. This
// separation (declare WHAT to audit here, HOW to audit it there) is the
// whole point of the AOP pattern: the "what" travels with the business
// code as a one-line annotation, instead of every method having to know
// how to write an audit log itself.
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Audited {
    String value(); // base action name, e.g. "LOGIN" -- becomes LOGIN_SUCCESS / LOGIN_FAILURE
}
