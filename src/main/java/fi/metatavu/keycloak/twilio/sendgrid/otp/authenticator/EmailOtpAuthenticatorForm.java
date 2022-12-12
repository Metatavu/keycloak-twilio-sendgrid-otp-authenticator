package fi.metatavu.keycloak.twilio.sendgrid.otp.authenticator;

import com.sendgrid.Method;
import com.sendgrid.Request;
import com.sendgrid.SendGrid;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Content;
import com.sendgrid.helpers.mail.objects.Email;
import lombok.extern.jbosslog.JBossLog;
import org.eclipse.microprofile.config.ConfigProvider;
import org.keycloak.authentication.*;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.List;

@JBossLog
public class EmailOtpAuthenticatorForm implements Authenticator {

    static final String ID = "sendgrid-email-otp-form";
    public static final String OTP_CODE = "otpCode";
    public static final String RESEND_CODE_FIELD_NAME = "resendCode";
    public static final String CANCEL_FIELD_NAME = "cancel";
    private static final Integer EMAIL_CODE_LENGTH = ConfigProvider.getConfig().getValue("kc.otp.length", Integer.class);
    private static final String SENDGRID_API_KEY = ConfigProvider.getConfig().getValue("kc.sendgrid.api.key", String.class);


    public EmailOtpAuthenticatorForm() {
    }

    /**
     * This method is being run by Keycloak upon executing.
     *
     * @param context context
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        challenge(context, null);

    }

    /**
     * Validates form data and appends possible error message to form
     *
     * @param context context
     * @param errorMessage error message
     */
    private void challenge(AuthenticationFlowContext context, FormMessage errorMessage) {
        generateAndSendEmailCode(context);
        LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
        if (errorMessage != null) {
            form.setErrors(List.of(errorMessage));
        }

        Response response = form.createForm("email-code-form.ftl");
        context.challenge(response);
    }

    /**
     * Generates Email OTP code and sends it.
     *
     * @param context Authentication flow context
     */
    private void generateAndSendEmailCode(AuthenticationFlowContext context) {
        if (context.getAuthenticationSession().getAuthNote(OTP_CODE) != null) {
            return;
        }

        String smsCode = SecretGenerator.getInstance().randomString(EMAIL_CODE_LENGTH, SecretGenerator.DIGITS);
        sendEmailWithCode(context.getRealm(), context.getUser(), smsCode);
        context.getAuthenticationSession().setAuthNote(OTP_CODE, smsCode);
    }

    /**
     * Called when form is being submitted.
     * Checks what form button is pressed and acts accordingly.
     * If correct OTP code is given, this Authentication Flow Context is marked successful.
     *
     * @param context context
     */
    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey(RESEND_CODE_FIELD_NAME)) {
            resetOtpCode(context);
            challenge(context, null);
            return;
        }

        if (formData.containsKey(CANCEL_FIELD_NAME)) {
            resetOtpCode(context);
            context.resetFlow();
            return;
        }

        if (formData.getFirst(OTP_CODE) != null) {
            int givenSmsCode = Integer.parseInt(formData.getFirst(OTP_CODE));
            boolean valid = validateCode(context, givenSmsCode);

            if (!valid) {
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                challenge(context, new FormMessage(Messages.INVALID_ACCESS_CODE));
                return;
            }

            resetOtpCode(context);
            context.success();
        }
    }

    /**
     * Resets current valid Email OTP code.
     *
     * @param context context
     */
    private void resetOtpCode(AuthenticationFlowContext context) {
        context.getAuthenticationSession().removeAuthNote(OTP_CODE);
    }

    /**
     * Validates that given Email OTP code is correct.
     *
     * @param context context
     * @param givenCode given code
     * @return Whether given code is correct
     */
    private boolean validateCode(AuthenticationFlowContext context, int givenCode) {
        int emailCode = Integer.parseInt(context.getAuthenticationSession().getAuthNote(OTP_CODE));
        return givenCode == emailCode;
    }

    /**
     * Sends Email with OTP code to user.
     * Throws error if email is not found on user.
     *
     * @param realm realm
     * @param user user
     * @param emailCode email code
     */
    private void sendEmailWithCode(RealmModel realm, UserModel user, String emailCode) {
        String userEmail = user.getEmail();

        if (userEmail == null) {
            log.warnf("Could not send OTP Code email due to missing email. Realm=%s User=%s", realm.getId(), user.getUsername());
            throw new AuthenticationFlowException(AuthenticationFlowError.INVALID_USER);
        }

        Email from = new Email("no-reply@votech.app");
        String subject = "Votech App One Time Password";
        Email to = new Email(userEmail);
        Content content = new Content("text/plain", String.format("Your OTP code for Votech App: %s", emailCode));
        Mail mail = new Mail(from, subject, to, content);
        SendGrid sendGrid = new SendGrid(SENDGRID_API_KEY);
        Request request = new Request();

        try {
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());
            sendGrid.api(request);
        } catch (IOException exception) {
            log.error("Couldn't send OTP Code email", exception);
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }
}
