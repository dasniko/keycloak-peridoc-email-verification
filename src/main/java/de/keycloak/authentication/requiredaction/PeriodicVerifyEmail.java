package de.keycloak.authentication.requiredaction;

import com.google.auto.service.AutoService;
import de.keycloak.util.BuildDetails;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriBuilderException;
import jakarta.ws.rs.core.UriInfo;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.actiontoken.verifyemail.VerifyEmailActionToken;
import org.keycloak.authentication.requiredactions.VerifyEmail;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.AuthorizationEndpointBase;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.provider.ServerInfoAwareProviderFactory;
import org.keycloak.services.Urls;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.userprofile.ValidationException;
import org.keycloak.validate.ValidationError;

import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

@JBossLog
@AutoService(RequiredActionFactory.class)
public class PeriodicVerifyEmail extends VerifyEmail implements ServerInfoAwareProviderFactory {

	public static final String EMAIL_VERIFIED_AT = UserModel.EMAIL_VERIFIED + "At";

	private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;
	private static final String EMAIL_VERIFY_PERIOD_AMOUNT = "email-verify-period-amount";
	private static final String EMAIL_VERIFY_PERIOD_UNIT = "email-verify-period-unit";

	static {
		CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
			.property()
			.name(EMAIL_VERIFY_PERIOD_AMOUNT)
			.label("Verification Period")
			.helpText("Enter the amount of the period, after which the user should be enforced to verify its email address again (0 = switched off).")
			.type(ProviderConfigProperty.STRING_TYPE)
			.defaultValue("0")
			.add()
			.property()
			.name(EMAIL_VERIFY_PERIOD_UNIT)
			.label("Verification Period Unit")
			.helpText("Select the temporal unit of the periodic verification.")
			.type(ProviderConfigProperty.LIST_TYPE)
			.options(List.of(ChronoUnit.MINUTES.name(), ChronoUnit.HOURS.name(), ChronoUnit.DAYS.name(), ChronoUnit.WEEKS.name(), ChronoUnit.MONTHS.name()))
			.defaultValue(ChronoUnit.MONTHS.name())
			.add()
			.build();
	}

	@Override
	public void evaluateTriggers(RequiredActionContext context) {
		if (isPeriodicVerificationEnabled(context)) {
			UserModel user = context.getUser();
			if (isOlderThanPeriod(user.getFirstAttribute(EMAIL_VERIFIED_AT), context.getConfig())) {
				user.setEmailVerified(false);
				user.addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);
				log.debug("User is required to verify email upon periodic check.");
			}
		} else {
			super.evaluateTriggers(context);
		}
	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		process(context, true);
	}

	private void process(RequiredActionContext context, boolean isChallenge) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();

		if (isPeriodicVerificationEnabled(context)) {
			if (!isOlderThanPeriod(context.getUser().getFirstAttribute(EMAIL_VERIFIED_AT), context.getConfig())) {
				context.success();
				authSession.removeAuthNote(Constants.VERIFY_EMAIL_KEY);
				return;
			}
		} else {
			if (context.getUser().isEmailVerified()) {
				context.success();
				authSession.removeAuthNote(Constants.VERIFY_EMAIL_KEY);
				return;
			}
		}

		String email = context.getUser().getEmail();
		if (Validation.isBlank(email)) {
			context.ignore();
			return;
		}

		LoginFormsProvider loginFormsProvider = context.form();
		loginFormsProvider.setAuthenticationSession(context.getAuthenticationSession());
		Response challenge;
		authSession.setClientNote(AuthorizationEndpointBase.APP_INITIATED_FLOW, null);

		// Do not allow resending e-mail by simple page refresh, i.e. when e-mail sent, it should be resent properly via email-verification endpoint
		if (!Objects.equals(authSession.getAuthNote(Constants.VERIFY_EMAIL_KEY), email) && !(isCurrentActionTriggeredFromAIA(context) && isChallenge)) {
			authSession.setAuthNote(Constants.VERIFY_EMAIL_KEY, email);
			EventBuilder event = context.getEvent().clone().event(EventType.SEND_VERIFY_EMAIL).detail(Details.EMAIL, email);
			challenge = sendVerifyEmail(context, event);
		} else {
			challenge = loginFormsProvider.createResponse(UserModel.RequiredAction.VERIFY_EMAIL);
		}

		context.challenge(challenge);
	}

	private boolean isCurrentActionTriggeredFromAIA(RequiredActionContext context) {
		return Objects.equals(context.getAuthenticationSession().getClientNote(Constants.KC_ACTION), getId());
	}

	@Override
	public void processAction(RequiredActionContext context) {
		log.debugf("Re-sending email requested for user: %s", context.getUser().getUsername());

		// This will allow user to re-send email again
		context.getAuthenticationSession().removeAuthNote(Constants.VERIFY_EMAIL_KEY);

		process(context, false);
	}

	private Response sendVerifyEmail(RequiredActionContext context, EventBuilder event) throws UriBuilderException, IllegalArgumentException {
		RealmModel realm = context.getRealm();
		UriInfo uriInfo = context.getUriInfo();
		UserModel user = context.getUser();
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		KeycloakSession session = context.getSession();

		int validityInSecs = realm.getActionTokenGeneratedByUserLifespan(VerifyEmailActionToken.TOKEN_TYPE);
		int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;

		String authSessionEncodedId = AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId();
		VerifyEmailActionToken token = new VerifyEmailActionToken(user.getId(), absoluteExpirationInSecs, authSessionEncodedId, user.getEmail(), authSession.getClient().getClientId());
		UriBuilder builder = Urls.actionTokenBuilder(uriInfo.getBaseUri(), token.serialize(session, realm, uriInfo),
			authSession.getClient().getClientId(), authSession.getTabId(), AuthenticationProcessor.getClientData(session, authSession));
		String link = builder.build(realm.getName()).toString();
		long expirationInMinutes = TimeUnit.SECONDS.toMinutes(validityInSecs);

		try {
			session
				.getProvider(EmailTemplateProvider.class)
				.setAuthenticationSession(authSession)
				.setRealm(realm)
				.setUser(user)
				.sendVerifyEmail(link, expirationInMinutes);
			event.success();
			return context.form().createResponse(UserModel.RequiredAction.VERIFY_EMAIL);
		} catch (EmailException e) {
			event.clone().event(EventType.SEND_VERIFY_EMAIL)
				.detail(Details.REASON, e.getMessage())
				.user(user)
				.error(Errors.EMAIL_SEND_FAILED);
			log.error("Failed to send verification email", e);
			context.failure(Messages.EMAIL_SENT_ERROR);
			return context.form()
				.setError(Messages.EMAIL_SENT_ERROR)
				.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
		}
	}

	@Override
	public int order() {
		return super.order() + 10;
	}

	@Override
	public String getDisplayText() {
		return "Verify Email (Periodic)";
	}

	@Override
	public List<ProviderConfigProperty> getConfigMetadata() {
		return List.copyOf(CONFIG_PROPERTIES);
	}

	@Override
	public void validateConfig(KeycloakSession session, RealmModel realm, RequiredActionConfigModel model) {
		try {
			String configValue = model.getConfigValue(EMAIL_VERIFY_PERIOD_AMOUNT, "0");
			Integer.parseInt(configValue);
		} catch (NumberFormatException ex) {
			throw new ValidationException(new ValidationError(getId(), EMAIL_VERIFY_PERIOD_AMOUNT, "periodNotANumber"));
		}
	}

	private long getPeriod(RequiredActionConfigModel model) {
		if (model != null) {
			if (model.containsConfigKey(EMAIL_VERIFY_PERIOD_AMOUNT)) {
				String periodString = model.getConfigValue(EMAIL_VERIFY_PERIOD_AMOUNT, "0");
				return Long.parseLong(periodString);
			}
		}
		return 0;
	}

	private TemporalUnit getPeriodUnit(RequiredActionConfigModel model) {
		if (model != null) {
			if (model.containsConfigKey(EMAIL_VERIFY_PERIOD_UNIT)) {
				String temporalUnit = model.getConfigValue(EMAIL_VERIFY_PERIOD_UNIT, ChronoUnit.MONTHS.name());
				return ChronoUnit.valueOf(temporalUnit);
			}
		}
		return ChronoUnit.MONTHS;
	}

	private boolean isPeriodicVerificationEnabled(RequiredActionContext context) {
		return getPeriod(context.getConfig()) > 0;
	}

	private boolean isOlderThanPeriod(String unixTimestamp, RequiredActionConfigModel model) {
		if (unixTimestamp == null || unixTimestamp.isEmpty()) {
			return true;
		}
		Instant timestamp = Instant.ofEpochSecond(Long.parseLong(unixTimestamp));
		long period = getPeriod(model);
		TemporalUnit unit = getPeriodUnit(model);
		Instant timeAgo = Instant.now().atZone(ZoneId.systemDefault()).minus(period, unit).toInstant();
		return timestamp.isBefore(timeAgo);
	}

	@Override
	public Map<String, String> getOperationalInfo() {
		return BuildDetails.get();
	}
}
