package io.mosip.registration.processor.credentialrequestor.stage;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.biometrics.util.ConvertRequestDto;
import io.mosip.biometrics.util.face.FaceDecoder;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.core.exception.BaseUncheckedException;
import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.registration.processor.core.abstractverticle.*;
import io.mosip.registration.processor.core.code.EventId;
import io.mosip.registration.processor.core.code.EventName;
import io.mosip.registration.processor.core.code.EventType;
import io.mosip.registration.processor.core.code.*;
import io.mosip.registration.processor.core.common.rest.dto.ErrorDTO;
import io.mosip.registration.processor.core.constant.*;
import io.mosip.registration.processor.core.exception.ApisResourceAccessException;
import io.mosip.registration.processor.core.exception.util.PlatformErrorMessages;
import io.mosip.registration.processor.core.exception.util.PlatformSuccessMessages;
import io.mosip.registration.processor.core.http.RequestWrapper;
import io.mosip.registration.processor.core.http.ResponseWrapper;
import io.mosip.registration.processor.core.idrepo.dto.CredentialRequestDto;
import io.mosip.registration.processor.core.idrepo.dto.CredentialResponseDto;
import io.mosip.registration.processor.core.idrepo.dto.VidInfoDTO;
import io.mosip.registration.processor.core.idrepo.dto.VidsInfosDTO;
import io.mosip.registration.processor.core.logger.LogDescription;
import io.mosip.registration.processor.core.logger.RegProcessorLogger;
import io.mosip.registration.processor.core.spi.restclient.RegistrationProcessorRestClientService;
import io.mosip.registration.processor.core.status.util.StatusUtil;
import io.mosip.registration.processor.core.status.util.TrimExceptionMessage;
import io.mosip.registration.processor.core.util.JsonUtil;
import io.mosip.registration.processor.credentialrequestor.dto.CredentialPartner;
import io.mosip.registration.processor.credentialrequestor.stage.exception.VidNotAvailableException;
import io.mosip.registration.processor.credentialrequestor.util.CredentialPartnerUtil;
import io.mosip.registration.processor.packet.storage.utils.Utilities;
import io.mosip.registration.processor.rest.client.audit.builder.AuditLogRequestBuilder;
import io.mosip.registration.processor.status.code.RegistrationStatusCode;
import io.mosip.registration.processor.status.dto.InternalRegistrationStatusDto;
import io.mosip.registration.processor.status.dto.RegistrationStatusDto;
import io.mosip.registration.processor.status.service.RegistrationStatusService;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.json.JSONArray;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * The Class PrintStage.
 * 
 * @author M1048358 Alok
 * @author Ranjitha Siddegowda
 * @author Sowmya
 */
@RefreshScope
@Service
@Configuration
@EnableScheduling
@ComponentScan(basePackages = { "${mosip.auth.adapter.impl.basepackage}",
		"io.mosip.registration.processor.core.config",
		"io.mosip.registration.processor.stages.config", 
		"io.mosip.registration.processor.credentialrequestor.config",
		"io.mosip.registrationprocessor.stages.config",
		"io.mosip.registration.processor.status.config",
		"io.mosip.registration.processor.rest.client.config", 
		"io.mosip.registration.processor.packet.storage.config",
		"io.mosip.registration.processor.packet.manager.config", 
		"io.mosip.kernel.idobjectvalidator.config",
		"io.mosip.registration.processor.core.kernel.beans" })
public class CredentialRequestorStage extends MosipVerticleAPIManager {
	
	private static final String STAGE_PROPERTY_PREFIX = "mosip.regproc.credentialrequestor.";
	private Random sr = null;
	private static final int max = 999999;
	private static final int min = 100000;

	/** The reg proc logger. */
	private static Logger regProcLogger = RegProcessorLogger.getLogger(CredentialRequestorStage.class);

	/** The cluster manager url. */
	@Value("${vertx.cluster.configuration}")
	private String clusterManagerUrl;


	/** The core audit request builder. */
	@Autowired
	private AuditLogRequestBuilder auditLogRequestBuilder;

	/** The mosip event bus. */
	private MosipEventBus mosipEventBus;

	/** The registration status service. */
	@Autowired
	RegistrationStatusService<String, InternalRegistrationStatusDto, RegistrationStatusDto> registrationStatusService;

	/** worker pool size. */
	@Value("${worker.pool.size}")
	private Integer workerPoolSize;

	/** After this time intervel, message should be considered as expired (In seconds). */
	@Value("${mosip.regproc.credentialrequestor.message.expiry-time-limit}")
	private Long messageExpiryTimeLimit;

	@Value("${mosip.registration.processor.encrypt:false}")
	private boolean encrypt;

	@Value("${mosip.regproc.credentialrequestor.credissuer.url:https://teste-autenticacao.gov.st/api/credentials/issue/client/bulk}")
	private String credIssuerUrl;

	@Value("${mosip.regproc.credentialrequestor.credissuer.auth:Bearer 70e09182bf0e4abf81a431d89b066bb1}")
	private String credIssuerAuthHeader;

	@Value("${mosip.regproc.credentialrequestor.credissuer.template-id:1A1911ABDEC6}")
	private String credIssuerTemplateId;

	@Value("${mosip.regproc.credentialrequestor.credissuer.mode:issue_and_notify}")
	private String credIssuerModeOfIssuance;

	/** Mosip router for APIs */
	@Autowired
	MosipRouter router;

	private static final String SEPERATOR = "::";

	@Autowired
	private RegistrationProcessorRestClientService<Object> restClientService;

	@Autowired
	private ObjectMapper mapper;

	@Autowired
	private Environment env;

	private static final String DATETIME_PATTERN = "mosip.registration.processor.datetime.pattern";

	private static final String ISSUERS = "mosip.registration.processor.issuer";

	@Value("#{T(java.util.Arrays).asList('${mosip.registration.processor.credential.default.partner-ids:}')}")
	private List<String> defaultPartners;

	private static String COMMA = ",";
	private static String HASH_DELIMITER = "#";

	@Autowired
	private Utilities utilities;

	@Autowired
	private CredentialPartnerUtil credentialPartnerUtil;

	@Override
	protected String getPropertyPrefix() {
		return STAGE_PROPERTY_PREFIX;
	}

	/**
	 * Deploy verticle.
	 */
	public void deployVerticle() {
		mosipEventBus = this.getEventBus(this, clusterManagerUrl, workerPoolSize);
		this.consumeAndSend(mosipEventBus, MessageBusAddress.PRINTING_BUS_IN, MessageBusAddress.PRINTING_BUS_OUT,
				messageExpiryTimeLimit);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.registration.processor.core.spi.eventbus.EventBusManager#process(
	 * java.lang.Object)
	 */
	@Override
	public MessageDTO process(MessageDTO object) {
		TrimExceptionMessage trimeExpMessage = new TrimExceptionMessage();
		object.setMessageBusAddress(MessageBusAddress.PRINTING_BUS_IN);
		object.setInternalError(Boolean.FALSE);
		object.setIsValid(Boolean.FALSE);
		LogDescription description = new LogDescription();

		boolean isTransactionSuccessful = false;
		String uin = null;
		String refIds = null;
		String regId = object.getRid();
		regProcLogger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
				regId, "PrintStage::process()::entry");

		InternalRegistrationStatusDto registrationStatusDto = null;
		RequestWrapper<CredentialRequestDto> requestWrapper = new RequestWrapper<>();
		ResponseWrapper<?> responseWrapper = null;
		CredentialResponseDto credentialResponseDto;
		try {
			registrationStatusDto = registrationStatusService.getRegistrationStatus(
					regId, object.getReg_type(), object.getIteration(), object.getWorkflowInstanceId());
			registrationStatusDto
					.setLatestTransactionTypeCode(RegistrationTransactionTypeCode.PRINT_SERVICE.toString());
			registrationStatusDto.setRegistrationStageName(getStageName());
			JSONObject jsonObject = utilities.idrepoRetrieveIdentityByRid(regId);
			uin = JsonUtil.getJSONValue(jsonObject, IdType.UIN.toString());
			if (uin == null) {
				regProcLogger.error(LoggerFileConstant.SESSIONID.toString(),
						LoggerFileConstant.REGISTRATIONID.toString(), null,
						PlatformErrorMessages.RPR_PRT_UIN_NOT_FOUND_IN_DATABASE.name());
				object.setIsValid(Boolean.FALSE);
				isTransactionSuccessful = false;
				description.setMessage(PlatformErrorMessages.RPR_PRT_PRINT_REQUEST_FAILED.getMessage());
				description.setCode(PlatformErrorMessages.RPR_PRT_PRINT_REQUEST_FAILED.getCode());

				registrationStatusDto.setStatusComment(
						StatusUtil.UIN_NOT_FOUND_IN_DATABASE.getMessage());
				registrationStatusDto.setSubStatusCode(StatusUtil.UIN_NOT_FOUND_IN_DATABASE.getCode());
				registrationStatusDto
						.setLatestTransactionStatusCode(RegistrationTransactionStatusCode.FAILED.toString());
				registrationStatusDto
						.setLatestTransactionTypeCode(RegistrationTransactionTypeCode.PRINT_SERVICE.toString());

			} else {
				requestWrapper.setId(env.getProperty("mosip.registration.processor.credential.request.service.id"));
				DateTimeFormatter format = DateTimeFormatter.ofPattern(env.getProperty(DATETIME_PATTERN));
				requestWrapper.setVersion("1.0");
				List<CredentialPartner> allIssuerList = credentialPartnerUtil.getAllCredentialPartners().getPartners();
				// filtering with default partner ids and process
				List<CredentialPartner> filteredPartners = allIssuerList.stream()
						.filter(issuer -> defaultPartners.contains(issuer.getId()))
						.filter(issuer -> (issuer.getProcess() == null) || (issuer.getProcess().contains(object.getReg_type())))
						.collect(Collectors.toList());
				filteredPartners.addAll(credentialPartnerUtil.getCredentialPartners(
						regId, registrationStatusDto.getRegistrationType(), jsonObject));
				for (CredentialPartner key : filteredPartners) {
					CredentialRequestDto credentialRequestDto = getCredentialRequestDto(regId, registrationStatusDto.getRegistrationType(), key);
					LocalDateTime localdatetime = LocalDateTime.parse(
							DateUtils.getUTCCurrentDateTimeString(env.getProperty(DATETIME_PATTERN)), format);
					requestWrapper.setRequesttime(localdatetime);
					requestWrapper.setRequest(credentialRequestDto);
					// issuers with appIdBasedCredentialIdSuffix is calling v1 api and for others stage is calling v2 api for credential
					if (StringUtils.isNotEmpty(key.getAppIdBasedCredentialIdSuffix())) {
						List<String> pathsegments = new ArrayList<>();
						pathsegments.add(regId + key.getAppIdBasedCredentialIdSuffix()); //  #PDF suffix is added to identify the requested credential via rid
						responseWrapper = (ResponseWrapper<?>) restClientService.postApi(ApiName.CREDENTIALREQUESTV2, MediaType.APPLICATION_JSON, pathsegments, null,
									null, requestWrapper, ResponseWrapper.class);
					} else {
						responseWrapper = (ResponseWrapper<?>) restClientService.postApi(ApiName.CREDENTIALREQUEST, null, null,
								requestWrapper, ResponseWrapper.class, MediaType.APPLICATION_JSON);
					}
					if (responseWrapper.getErrors() != null && !responseWrapper.getErrors().isEmpty()) {
						ErrorDTO error = responseWrapper.getErrors().get(0);
						object.setIsValid(Boolean.FALSE);
						isTransactionSuccessful = false;
						registrationStatusDto.setRefId(refIds);
						description.setMessage(PlatformErrorMessages.RPR_PRT_PRINT_REQUEST_FAILED.getMessage());
						description.setCode(PlatformErrorMessages.RPR_PRT_PRINT_REQUEST_FAILED.getCode());

						registrationStatusDto.setStatusComment(
								StatusUtil.PRINT_REQUEST_FAILED.getMessage() + SEPERATOR + error.getMessage());
						registrationStatusDto.setSubStatusCode(StatusUtil.PRINT_REQUEST_FAILED.getCode());
						registrationStatusDto
								.setLatestTransactionStatusCode(RegistrationTransactionStatusCode.REPROCESS.toString());
						registrationStatusDto
								.setLatestTransactionTypeCode(RegistrationTransactionTypeCode.PRINT_SERVICE.toString());
						break;
					} else {
						credentialResponseDto = mapper.readValue(mapper.writeValueAsString(responseWrapper.getResponse()),
								CredentialResponseDto.class);
						refIds = credentialResponseDto.getRequestId();
						isTransactionSuccessful = true;
					}
				}
				if (isTransactionSuccessful) {
					callCredIssuer(regId, uin, registrationStatusDto.getRegistrationType());
					registrationStatusDto.setRefId(refIds);
					object.setIsValid(Boolean.TRUE);
					description.setMessage(PlatformSuccessMessages.RPR_PRINT_STAGE_REQUEST_SUCCESS.getMessage());
					description.setCode(PlatformSuccessMessages.RPR_PRINT_STAGE_REQUEST_SUCCESS.getCode());
					registrationStatusDto.setStatusComment(
							trimeExpMessage.trimExceptionMessage(StatusUtil.PRINT_REQUEST_SUCCESS.getMessage()));
					registrationStatusDto.setSubStatusCode(StatusUtil.PRINT_REQUEST_SUCCESS.getCode());
					registrationStatusDto
							.setLatestTransactionStatusCode(RegistrationTransactionStatusCode.PROCESSED.toString());
					registrationStatusDto
							.setLatestTransactionTypeCode(RegistrationTransactionTypeCode.PRINT_SERVICE.toString());

					regProcLogger.debug(LoggerFileConstant.SESSIONID.toString(),
							LoggerFileConstant.REGISTRATIONID.toString(), regId, "PrintStage::process()::exit");
				}
			}
		} catch (ApisResourceAccessException e) {
			regProcLogger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
					regId, PlatformErrorMessages.RPR_PRT_PRINT_REQUEST_FAILED.name() + e.getMessage()
							+ ExceptionUtils.getStackTrace(e));
			registrationStatusDto
					.setLatestTransactionStatusCode(RegistrationTransactionStatusCode.REPROCESS.toString());
			registrationStatusDto.setStatusComment(trimeExpMessage.trimExceptionMessage(
					StatusUtil.API_RESOUCE_ACCESS_FAILED.getMessage() + SEPERATOR + e.getMessage()));
			registrationStatusDto.setSubStatusCode(StatusUtil.API_RESOUCE_ACCESS_FAILED.getCode());
			description.setMessage(PlatformErrorMessages.RPR_PRT_PRINT_REQUEST_FAILED.getMessage());
			description.setCode(PlatformErrorMessages.RPR_PRT_PRINT_REQUEST_FAILED.getCode());
			object.setInternalError(Boolean.TRUE);
		} catch (IOException e) {
			regProcLogger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
					regId, PlatformErrorMessages.RPR_PRT_PRINT_REQUEST_FAILED.name() + e.getMessage()
							+ ExceptionUtils.getStackTrace(e));
			registrationStatusDto
					.setLatestTransactionStatusCode(RegistrationTransactionStatusCode.REPROCESS.toString());
			registrationStatusDto.setStatusComment(
					trimeExpMessage.trimExceptionMessage(StatusUtil.IO_EXCEPTION.getMessage() + e.getMessage()));
			registrationStatusDto.setSubStatusCode(StatusUtil.IO_EXCEPTION.getCode());
			description.setMessage(PlatformErrorMessages.RPR_PRT_PRINT_REQUEST_FAILED.getMessage());
			description.setCode(PlatformErrorMessages.RPR_PRT_PRINT_REQUEST_FAILED.getCode());
			object.setInternalError(Boolean.TRUE);
		} catch (Exception e) {
			regProcLogger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
					regId, PlatformErrorMessages.RPR_PRT_PRINT_REQUEST_FAILED.name() + e.getMessage()
							+ ExceptionUtils.getStackTrace(e));
			registrationStatusDto
					.setLatestTransactionStatusCode(RegistrationTransactionStatusCode.REPROCESS.toString());
			registrationStatusDto.setStatusComment(
					trimeExpMessage.trimExceptionMessage(StatusUtil.UNKNOWN_EXCEPTION_OCCURED.getMessage()));
			registrationStatusDto.setSubStatusCode(StatusUtil.UNKNOWN_EXCEPTION_OCCURED.getCode());
			description.setMessage(PlatformErrorMessages.RPR_PRT_PRINT_REQUEST_FAILED.getMessage());
			description.setCode(PlatformErrorMessages.RPR_PRT_PRINT_REQUEST_FAILED.getCode());
			object.setInternalError(Boolean.TRUE);
		}
		finally {
			if (object.getInternalError()) {
				updateErrorFlags(registrationStatusDto, object);
			}
			String eventId = "";
			String eventName = "";
			String eventType = "";
			eventId = isTransactionSuccessful ? EventId.RPR_402.toString() : EventId.RPR_405.toString();
			eventName = eventId.equalsIgnoreCase(EventId.RPR_402.toString()) ? EventName.UPDATE.toString()
					: EventName.EXCEPTION.toString();
			eventType = eventId.equalsIgnoreCase(EventId.RPR_402.toString()) ? EventType.BUSINESS.toString()
					: EventType.SYSTEM.toString();
			/** Module-Id can be Both Success/Error code */
			String moduleId = isTransactionSuccessful
					? PlatformSuccessMessages.RPR_PRINT_STAGE_REQUEST_SUCCESS.getCode()
					: description.getCode();
			String moduleName = ModuleName.PRINT_STAGE.toString();
			registrationStatusService.updateRegistrationStatus(registrationStatusDto, moduleId, moduleName);

			auditLogRequestBuilder.createAuditRequestBuilder(description.getMessage(), eventId, eventName, eventType,
					moduleId, moduleName, regId);

		}
		return object;
	}

	private CredentialRequestDto getCredentialRequestDto(String regId, String process, CredentialPartner key) {
		CredentialRequestDto credentialRequestDto = new CredentialRequestDto();
		Map<String, Object> additionalAttributes=new HashMap<>();

		credentialRequestDto.setCredentialType(key.getCredentialType());
		credentialRequestDto.setEncrypt(encrypt);

		credentialRequestDto.setId(regId);

		credentialRequestDto.setIssuer(key.getPartnerId());

		credentialRequestDto.setEncryptionKey(generatePin());
		additionalAttributes.put("templateTypeCode", key.getTemplate());
		additionalAttributes.put("registrationId", regId);
		if (CollectionUtils.isNotEmpty(key.getMetaInfoFields()))
			getAdditionalCredentialFields(regId, process, key.getMetaInfoFields(), additionalAttributes);
		credentialRequestDto.setAdditionalData(additionalAttributes);

		return credentialRequestDto;
	}

	private void callCredIssuer(String regId, String uin, String process) {
		try {
			// Get dynamic field values from packet
			Map<String, String> fieldMap = getCredentialFieldMap(regId, process);

			// Build request dynamically using extracted values
			Map<String, Object> request = buildCredIssuerRequest(regId, uin, fieldMap);

			regProcLogger.info(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(), "",
					"PrintServiceImpl::callCredIssuer():: credIssuer API request created");

			HttpHeaders headers = new HttpHeaders();
			headers.set("Authorization", credIssuerAuthHeader);
			headers.setContentType(MediaType.APPLICATION_JSON);
			HttpEntity<Object> requestEntity = new HttpEntity<>(request, headers);
			List<String> queryParamNames = Arrays.asList("credential_template", "mode_of_issuance");
			List<Object> queryParamValues = Arrays.asList(credIssuerTemplateId, credIssuerModeOfIssuance);
			restClientService.postApi(credIssuerUrl, MediaType.APPLICATION_JSON, null, queryParamNames, queryParamValues,
					requestEntity, Object.class);

			regProcLogger.info(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(), "",
					"PrintServiceImpl::callCredIssuer():: credIssuer API called successfully");
		} catch (Exception e) {
			regProcLogger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
					regId, "CredIssuer call failed: " + e.getMessage() + ExceptionUtils.getStackTrace(e));
		}
	}

	private Map<String, String> getCredentialFieldMap(String regId, String process) {
		try {
			List<String> fields = new ArrayList<>();

			JSONObject regProcessorIdentityJson = utilities.getRegistrationProcessorMappingJson(MappingJsonConstants.IDENTITY);

			String dob = JsonUtil.getJSONValue(JsonUtil.getJSONObject(regProcessorIdentityJson, MappingJsonConstants.DOB),
					MappingJsonConstants.VALUE);
			String gender = JsonUtil.getJSONValue(JsonUtil.getJSONObject(regProcessorIdentityJson, MappingJsonConstants.GENDER),
					MappingJsonConstants.VALUE);
			String email = JsonUtil.getJSONValue(JsonUtil.getJSONObject(regProcessorIdentityJson, MappingJsonConstants.EMAIL),
					MappingJsonConstants.VALUE);

			fields.add("firstName");
			fields.add("surname");
			fields.add("addressLine1");
			fields.add("addressLine2");
			fields.add("municipality");
			fields.add("town");
			fields.add(dob);
			fields.add(gender);
			fields.add(email);
			fields.add("height");
			fields.add("countryOfCitizenship");

			Map<String, String> fieldMap = utilities.getPacketManagerService()
							.getFields(regId, fields, process, ProviderStageName.CREDENTIAL_REQUESTOR);

			regProcLogger.info(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(), regId,
					"Extracted Credential Fields = " + fieldMap);

			List<String> modalities = List.of("Face");
			String individualBiometricsLabel = JsonUtil.getJSONValue(
					JsonUtil.getJSONObject(regProcessorIdentityJson, MappingJsonConstants.INDIVIDUAL_BIOMETRICS),
					MappingJsonConstants.VALUE);
			BiometricRecord biometricRecord = utilities.getPacketManagerService().getBiometrics(
					regId, individualBiometricsLabel, modalities, process, ProviderStageName.CREDENTIAL_REQUESTOR);
			List<BIR> segments = biometricRecord.getSegments();

			for (BIR bir : segments) {
				if ("Face".equalsIgnoreCase(bir.getBdbInfo().getType().get(0).value())) {
					byte[] isoBytes = bir.getBdb();

					ConvertRequestDto convertRequestDto = new ConvertRequestDto();
					convertRequestDto.setInputBytes(isoBytes);
					convertRequestDto.setVersion("ISO19794_5_2011");

					byte[] imageBytes = FaceDecoder.convertFaceISOToImageBytes(convertRequestDto);

					String faceBase64 = Base64.getEncoder().encodeToString(imageBytes);

					fieldMap.put("face", faceBase64);
					regProcLogger.info(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(), regId,
							"Extracted Face Content: " + faceBase64);
				}
			}

			return fieldMap;
		} catch (Exception e) {
			regProcLogger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(), regId,
					"Failed to extract credential fields: " + e.getMessage()
			);
			return Collections.emptyMap();
		}
	}

	private String getFieldValue(Map<String, String> fieldMap, String key, String preferredLang) {
		String value = fieldMap.get(key);

		if (value == null) return "Test"; //TODO: change to null after testing

		// If localized JSON array
		if (value.trim().startsWith("[")) {
			return extractLocalizedValue(value, preferredLang);
		}
		return value;
	}

	private String extractLocalizedValue(String jsonArrayString, String preferredLang) {
		try {
			List<Map<String, Object>> list = mapper.readValue(jsonArrayString, List.class);

			for (Map<String, Object> item : list) {
				if (preferredLang.equalsIgnoreCase((String) item.get("language"))) {
					return (String) item.get("value");
				}
			}

			return list.isEmpty() ? null : (String) list.get(0).get("value");
		} catch (Exception e) {
			regProcLogger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(), "",
					"Failed to parse localized field: " + e.getMessage());
			return null;
		}
	}

	private String convertToISODate(String date) {
		try {
			if (date == null) return null;
			LocalDate localDate = LocalDate.parse(date, DateTimeFormatter.ofPattern("yyyy/MM/dd"));
			return localDate.atStartOfDay().toInstant(ZoneOffset.UTC).toString();
		} catch (Exception e) {
			return date;
		}
	}

	private Map<String, Object> buildCredIssuerRequest(String regId, String uin, Map<String, String> fieldMap) {
		regProcLogger.info(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(), regId,
				"PrintServiceImpl::buildCredIssuerRequest():: Building credIssuer API request");

		Map<String, Object> request = new HashMap<>();
		Map<String, Object> issuerInfo = new HashMap<>();
		String preferredLang = "por";
		issuerInfo.put("org_code", "CHAS-7EAA8DD9");
		issuerInfo.put("email", "tochandru.engineer@gmail.com");
		request.put("issuer_info", issuerInfo);
		request.put("issuer_credential_template_id", credIssuerTemplateId);

		Map<String, Object> credentialData = new HashMap<>();
		credentialData.put("email", getFieldValue(fieldMap, "email", preferredLang));
		credentialData.put("addressLine1", getFieldValue(fieldMap, "addressLine1", preferredLang));
		credentialData.put("addressLine2", getFieldValue(fieldMap, "addressLine2", preferredLang));
		credentialData.put("addressLine3", getFieldValue(fieldMap, "municipality", preferredLang));
		credentialData.put("addressLine4", getFieldValue(fieldMap, "town", preferredLang));
		credentialData.put("surnameLine1", getFieldValue(fieldMap, "surname", preferredLang));
		credentialData.put("surnameLine2", "");
		credentialData.put("firstName", getFieldValue(fieldMap, "firstName", preferredLang));
		credentialData.put("sex", getFieldValue(fieldMap, "gender", preferredLang));
		credentialData.put("height", getFieldValue(fieldMap, "height", preferredLang));
		credentialData.put("NID", uin != null ? uin : regId);
		credentialData.put("nationality", getFieldValue(fieldMap, "countryOfCitizenship", preferredLang));
		credentialData.put("expiresAt", "2027-02-06T00:00:00.000Z");
		credentialData.put("dateOfBirth", convertToISODate(getFieldValue(fieldMap, "dateOfBirth", preferredLang)));

		Map<String, Object> photo = new HashMap<>();
		photo.put("storage", "base64");
		photo.put("name", "photograph -1--862458fb-9f17-4020-a8ce-d64d88bff0b4.png");
		String faceFromPacket = getFieldValue(fieldMap, "face", preferredLang);
		String faceData = "data:image/png;base64,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";
		photo.put("url", faceFromPacket.equalsIgnoreCase("Test") ? faceData : "data:image/jpg;base64," + faceFromPacket);
		photo.put("size", 1);
		photo.put("type", "image/png");
		photo.put("originalName", "john-image.png");
		photo.put("hash", "");
		credentialData.put("photo", Collections.singletonList(photo));

		request.put("credential_data", Collections.singletonList(credentialData));
		return request;
	}

	private void getAdditionalCredentialFields(String regId, String process,
											   List<String> metaInfoFields,
											   Map<String, Object> additionalAttributes) {
		try {
			Map<String,String> metaInfo = utilities.getPacketManagerService().getMetaInfo(regId, process, ProviderStageName.CREDENTIAL_REQUESTOR);
			JSONArray metadata = new JSONArray(metaInfo.get(JsonConstant.METADATA));
			for(int i=0; i<metadata.length(); i++){
				org.json.JSONObject jsonObject = metadata.getJSONObject(i);
				if (metaInfoFields.contains(jsonObject.getString("label"))){
					additionalAttributes.put(jsonObject.getString("label"), jsonObject.getString("value"));
				}
			}

		} catch (Exception e) {
			regProcLogger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
					regId, RegistrationStatusCode.FAILED + e.getMessage() + ExceptionUtils.getStackTrace(e));
			throw new BaseUncheckedException(PlatformErrorMessages.RPR_PRT_PARSING_ADDITIONAL_CRED_CONFIG.getCode(),
					PlatformErrorMessages.RPR_PRT_PARSING_ADDITIONAL_CRED_CONFIG.getMessage(), e);
		}
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see io.vertx.core.AbstractVerticle#start()
	 */
	@Override
	public void start() {
		router.setRoute(this.postUrl(getVertx(),
				MessageBusAddress.PRINTING_BUS_IN, MessageBusAddress.PRINTING_BUS_OUT));
		this.createServer(router.getRouter(), getPort());
	}

	public String generatePin() {
		if (sr == null)
			instantiate();
		int randomInteger = sr.nextInt(max - min) + min;
		return String.valueOf(randomInteger);
	}

	@SuppressWarnings("unchecked")
	private String getVid(String uin) throws ApisResourceAccessException, VidNotAvailableException {
		List<String> pathsegments = new ArrayList<>();
		pathsegments.add(uin);
		String vid = null;

		VidsInfosDTO vidsInfosDTO;

		regProcLogger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(), "",
				"PrintServiceImpl::getVid():: get GETVIDSBYUIN service call started with request data : "
		);

		vidsInfosDTO =  (VidsInfosDTO) restClientService.getApi(ApiName.GETVIDSBYUIN,
				pathsegments, "", "", VidsInfosDTO.class);

		if (vidsInfosDTO.getErrors() != null && !vidsInfosDTO.getErrors().isEmpty()) {
			ServiceError error = vidsInfosDTO.getErrors().get(0);
			throw new VidNotAvailableException(PlatformErrorMessages.RPR_PRT_VID_NOT_AVAILABLE_EXCEPTION.getCode(),
					error.getMessage());

		} else {
			if(vidsInfosDTO.getResponse()!=null && !vidsInfosDTO.getResponse().isEmpty()) {
				for (VidInfoDTO VidInfoDTO : vidsInfosDTO.getResponse()) {
					if (VidType.PERPETUAL.name().equalsIgnoreCase(VidInfoDTO.getVidType())) {
						vid = VidInfoDTO.getVid();
						break;
					}
				}
				if (vid == null) {
					throw new VidNotAvailableException(
							PlatformErrorMessages.RPR_PRT_VID_NOT_AVAILABLE_EXCEPTION.getCode(),
							PlatformErrorMessages.RPR_PRT_VID_NOT_AVAILABLE_EXCEPTION.getMessage());
				}
				regProcLogger.debug(LoggerFileConstant.SESSIONID.toString(),
						LoggerFileConstant.REGISTRATIONID.toString(), "",
						"PrintServiceImpl::getVid():: get GETVIDSBYUIN service call ended successfully");

			}else {
				throw new VidNotAvailableException(PlatformErrorMessages.RPR_PRT_VID_NOT_AVAILABLE_EXCEPTION.getCode(),
						PlatformErrorMessages.RPR_PRT_VID_NOT_AVAILABLE_EXCEPTION.getMessage());
			}

		}

		return vid;
	}

	private void updateErrorFlags(InternalRegistrationStatusDto registrationStatusDto, MessageDTO object) {
		object.setInternalError(true);
		if (registrationStatusDto.getLatestTransactionStatusCode()
				.equalsIgnoreCase(RegistrationTransactionStatusCode.REPROCESS.toString())) {
			object.setIsValid(true);
		} else {
			object.setIsValid(false);
		}
	}

	@Scheduled(fixedDelayString = "${mosip.regproc.printstage.pingeneration.refresh.millisecs:1800000}",
			initialDelayString = "${mosip.regproc.printstage.pingeneration.refresh.delay-on-startup.millisecs:5000}")
	private void instantiate() {
		regProcLogger.debug("Instantiating SecureRandom for credential pin generation............");
		try {
			sr = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			regProcLogger.error("Could not instantiate SecureRandom for credential pin generation", e);
		}
	}
}
