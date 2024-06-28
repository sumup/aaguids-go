package aaguids

import (
	_ "embed"
)

//go:embed raw.json
var RawMetadata []byte

// This descriptor contains description in alternative languages.
// Example:
//
// {
//   "ru-RU": "Пример U2F аутентификатора от FIDO Alliance",
//   "fr-FR": "Exemple U2F authenticator de FIDO Alliance"
// }//
// See: map[string]string

// This enumeration describes the status of an authenticator model as identified by its AAID/AAGUID or attestationCertificateKeyIdentifiers and potentially some additional information (such as a specific attestation key).
type AuthenticatorStatus string

const (
	// This authenticator is not FIDO certified.
	// Applicable StatusReport fields are:
	// - effectiveDate - When status was achieved
	// - authenticatorVersion - The minimum applicable authenticator version.
	// - url - To the authenticator page or additional information about the authenticator
	NOT_FIDO_CERTIFIED AuthenticatorStatus = "NOT_FIDO_CERTIFIED"
	// This authenticator has passed FIDO functional certification. This certification scheme is phased out and will be replaced by FIDO_CERTIFIED_L1.
	// Applicable StatusReport fields are:
	// - effectiveDate - When certification was issued
	// - authenticatorVersion - The minimum version of the certified solution
	// - certificationDescriptor - Authenticator Description. I.e. "Munikey 7c Black Edition"
	// - certificateNumber - FIDO Alliance Certificate Number
	// - certificationPolicyVersion - Authenticator Certification Policy
	// - certificationRequirementsVersion - Security Requirements Version
	// - url - URL to the certificate, or the news article about achievement of the certification.
	// These fields are applicable to any of the FIDO_CERTIFIED_*.
	FIDO_CERTIFIED AuthenticatorStatus = "FIDO_CERTIFIED"
	// Indicates that malware is able to bypass the user verification. This means that the authenticator could be used without the user’s consent and potentially even without the user’s knowledge.
	// Applicable StatusReport fields are:
	// - effectiveDate - Date of incident being reported
	// - authenticatorVersion - Minimum affected authenticator version
	// - url - URL to the news/corporate article explaining the incident
	USER_VERIFICATION_BYPASS AuthenticatorStatus = "USER_VERIFICATION_BYPASS"
	// Indicates that an attestation key for this authenticator is known to be compromised. The relying party SHOULD check the certificate field and use it to identify the compromised authenticator batch. If the certificate field is not set, the relying party should reject all new registrations of the compromised authenticator. The Authenticator manufacturer should set the date to the date when compromise has occurred.
	// Applicable StatusReport fields are:
	// - effectiveDate - Date of incident being reported
	// - authenticatorVersion - Minimum affected authenticator version
	// - certificate - Base64 DER-encoded PKIX certificate identifying compromised attestation root. If missing, then assume all authenticators of this model are compromised.
	// - url - URL to the news/corporate article explaining the incident
	ATTESTATION_KEY_COMPROMISE AuthenticatorStatus = "ATTESTATION_KEY_COMPROMISE"
	// This authenticator has identified weaknesses that allow registered keys to be compromised and should not be trusted. This would include both, e.g. weak entropy that causes predictable keys to be generated or side channels that allow keys or signatures to be forged, guessed or extracted.
	// Applicable StatusReport fields are:
	// - effectiveDate - Date of incident being reported
	// - authenticatorVersion - Minimum affected authenticator version
	// - url - URL to the news/corporate article explaining the incident
	USER_KEY_REMOTE_COMPROMISE AuthenticatorStatus = "USER_KEY_REMOTE_COMPROMISE"
	// This authenticator has known weaknesses in its key protection mechanism(s) that allow user keys to be extracted by an adversary in physical possession of the device.
	// Applicable StatusReport fields are:
	// - effectiveDate - Date of incident being reported
	// - authenticatorVersion - Minimum affected authenticator version
	// - url - URL to the news/corporate article explaining the incident
	USER_KEY_PHYSICAL_COMPROMISE AuthenticatorStatus = "USER_KEY_PHYSICAL_COMPROMISE"
	// A software or firmware update is available for the device. The Authenticator manufacturer should set the url to the URL where users can obtain an update and the date the update was published. When this status code is used, then the field authenticatorVersion in the authenticator Metadata Statement [FIDOMetadataStatement] MUST be updated, if the update fixes severe security issues, e.g. the ones reported by preceding StatusReport entries with status code USER_VERIFICATION_BYPASS, ATTESTATION_KEY_COMPROMISE, USER_KEY_REMOTE_COMPROMISE, USER_KEY_PHYSICAL_COMPROMISE, REVOKED. The Relying party MUST reject the Metadata Statement if the authenticatorVersion has not increased
	// Applicable StatusReport fields are:
	// - effectiveDate - Date of incident being reported
	// - authenticatorVersion - New authenticator version that is available. MUST match authenticatorVersion in the metadata statement.
	// - url - URL to the page with the update info
	// Relying parties might want to inform users about available firmware updates.
	// More values might be added in the future. FIDO Servers MUST silently ignore all unknown AuthenticatorStatus values.
	UPDATE_AVAILABLE AuthenticatorStatus = "UPDATE_AVAILABLE"
	// The FIDO Alliance has determined that this authenticator should not be trusted for any reason. For example if it is known to be a fraudulent product or contain a deliberate backdoor. Relying parties SHOULD reject any future registration of this authenticator model.
	// Applicable StatusReport fields are:
	// - effectiveDate - Date of incident being reported
	// - authenticatorVersion - New authenticator version that is
	// - url - URL to the news/corporate article explaining the reason for revocation
	REVOKED AuthenticatorStatus = "REVOKED"
	// The authenticator vendor has completed and submitted the self-certification checklist to the FIDO Alliance. If this completed checklist is publicly available, the URL will be specified in url.
	// Applicable StatusReport fields are:
	// - effectiveDate - Date of incident being reported
	// - authenticatorVersion - New authenticator version that is
	SELF_ASSERTION_SUBMITTED AuthenticatorStatus = "SELF_ASSERTION_SUBMITTED"
	// The authenticator has passed FIDO Authenticator certification at level 1. This level is the more strict successor of FIDO_CERTIFIED.
	FIDO_CERTIFIED_L1 AuthenticatorStatus = "FIDO_CERTIFIED_L1"
	// The authenticator has passed FIDO Authenticator certification at level 1+. This level is the more than level 1.
	FIDO_CERTIFIED_L1plus AuthenticatorStatus = "FIDO_CERTIFIED_L1plus"
	// The authenticator has passed FIDO Authenticator certification at level 2. This level is more strict than level 1+.
	FIDO_CERTIFIED_L2 AuthenticatorStatus = "FIDO_CERTIFIED_L2"
	// The authenticator has passed FIDO Authenticator certification at level 2+. This level is more strict than level 2.
	FIDO_CERTIFIED_L2plus AuthenticatorStatus = "FIDO_CERTIFIED_L2plus"
	// The authenticator has passed FIDO Authenticator certification at level 3. This level is more strict than level 2+.
	FIDO_CERTIFIED_L3 AuthenticatorStatus = "FIDO_CERTIFIED_L3"
	// The authenticator has passed FIDO Authenticator certification at level 3+. This level is more strict than level 3.
	FIDO_CERTIFIED_L3plus AuthenticatorStatus = "FIDO_CERTIFIED_L3plus"
)

// The latest StatusReport entry MUST reflect the "current" status. For example, if the latest entry has status USER_VERIFICATION_BYPASS, then it is recommended assuming an increased risk associated with all authenticators of this AAID; if the latest entry has status UPDATE_AVAILABLE, then the update is intended to address at least all previous issues reported in this StatusReport dictionary.
type StatusReport struct {
	// Status of the authenticator. Additional fields MAY be set depending on this value.
	Status AuthenticatorStatus `json:"status"`
	// ISO-8601 formatted date since when the status code was set, if applicable. If no date is given, the status is assumed to be effective while present.
	EffectiveDate *string `json:"effectiveDate"`
	// The authenticatorVersion that this status report relates to. In the case of FIDO_CERTIFIED* status values, the status applies to higher authenticatorVersions until there is a new statusReport.
	AuthenticatorVersion *uint64 `json:"authenticatorVersion"`
	// Base64-encoded [RFC4648] (not base64url!) DER [ITU-X690-2008] PKIX certificate value related to the current status, if applicable.
	Certificate *string `json:"certificate"`
	// HTTPS URL where additional information may be found related to the current status, if applicable.
	URL *string `json:"url"`
	// Describes the externally visible aspects of the Authenticator Certification evaluation.
	CertificationDescriptor *string `json:"certificationDescriptor"`
	// The unique identifier for the issued Certification.
	CertificateNumber *string `json:"certificateNumber"`
	// The version of the Authenticator Certification Policy the implementation is Certified to, e.g. "1.0.0".
	CertificationPolicyVersion *string `json:"certificationPolicyVersion"`
	// The Document Version of the Authenticator Security Requirements (DV) [FIDOAuthenticatorSecurityRequirements] the implementation is certified to, e.g. "1.2.0".
	CertificationRequirementsVersion *string `json:"certificationRequirementsVersion"`
}

// This descriptor contains description in alternative languages.
// Example:
//
//	{
//	  "ru-RU": "Пример U2F аутентификатора от FIDO Alliance",
//	  "fr-FR": "Exemple U2F authenticator de FIDO Alliance"
//	}
type AlternativeDescription map[string]string

type MetadataStatement struct {
	// The legalHeader, which must be in each Metadata Statement, is an indication of the acceptance of the relevant legal agreement for using the MDS.
	// The example of a Metadata Statement legal header is:
	// "legalHeader": "https://fidoalliance.org/metadata/metadata-statement-legal-header/".
	LegalHeader string `json:"legalHeader"`
	// The Authenticator Attestation ID. See [UAFProtocol] for the definition of the AAID structure. This field MUST be set if the authenticator implements FIDO UAF.
	AAID string `json:"aaid"`
	// The Authenticator Attestation GUID. See [FIDOKeyAttestation] for the definition of the AAGUID structure. This field MUST be set if the authenticator implements FIDO2.
	AAGUID string `json:"aaguid"`
	// A list of the attestation certificate public key identifiers encoded as hex string.
	// This value MUST be calculated according to method 1 for computing the keyIdentifier as defined in [RFC5280] section 4.2.1.2. The hex string MUST NOT contain any non-hex characters (e.g. spaces). All hex letters MUST be lower case. This field MUST be set if neither aaid nor aaguid are set. Setting this field implies that the attestation certificate(s) are dedicated to a single authenticator model.
	// All attestationCertificateKeyIdentifier values should be unique within the scope of the Metadata Service.
	AttestationCertificateKeyIdentifiers []string `json:"attestationCertificateKeyIdentifiers"`
	// A human-readable, short description of the authenticator, in English.
	Description string
	// A list of human-readable short descriptions of the authenticator in different languages.
	AlternativeDescriptions AlternativeDescription `json:"alternativeDescriptions"`
	// Earliest (i.e. lowest) trustworthy authenticatorVersion meeting the requirements specified in this metadata statement.
	// Adding new StatusReport entries with status UPDATE_AVAILABLE to the metadata BLOB object [FIDOMetadataService] MUST also change this authenticatorVersion if the update fixes severe security issues, e.g. the ones reported by preceding StatusReport entries with status code USER_VERIFICATION_BYPASS,ATTESTATION_KEY_COMPROMISE,USER_KEY_REMOTE_COMPROMISE,USER_KEY_PHYSICAL_COMPROMISE,REVOKED.
	// It is RECOMMENDED to assume increased risk if this version is higher (newer) than the firmware version present in an authenticator. For example, if a StatusReport entry with status USER_VERIFICATION_BYPASS or USER_KEY_REMOTE_COMPROMISE precedes the UPDATE_AVAILABLE entry, than any firmware version lower (older) than the one specified in the metadata statement is assumed to be vulnerable.
	// The specified version should equal the value of the 'firmwareVersion' member of the authenticatorGetInfo response. If present, see [FIDOCTAP].
	AuthenticatorVersion uint64 `json:"authenticatorVersion"`
	// The FIDO protocol family. The values "uaf", "u2f", and "fido2" are supported.
	// Metadata Statements for U2F authenticators MUST set the value of protocolFamily to "u2f". Metadata statement for UAF authenticator MUST set the value of protocolFamily to "uaf", and FIDO2/WebAuthentication Authenticator implementations MUST set the value of protocolFamily to "fido2".
	ProtocolFamily string `json:"protocolFamily"`
	// The Metadata Schema version
	// Metadata schema version defines what schema of the metadata statement is currently present. The schema version of this version of the specification is 3.
	Schema uint16 `json:"schema"`

	// TODO:
	// required Version[]                           upv;
	// required DOMString[]                         authenticationAlgorithms;
	// required DOMString[]                         publicKeyAlgAndEncodings;
	// required DOMString[]                         attestationTypes;
	// required VerificationMethodANDCombinations[] userVerificationDetails;

	// The list of key protection types supported by the authenticator. Must be set to the complete list of the supported KEY_PROTECTION_ constant case-sensitive string names defined in the FIDO Registry of Predefined Values [FIDORegistry] in section "Key Protection Types" e.g. "secure_element". Each value MUST NOT be empty.
	KeyProtection []string `json:"keyProtection"`
	// This entry is set to true, if the Uauth private key is restricted by the authenticator to only sign valid FIDO signature assertions. This entry is set to false, if the authenticator doesn’t restrict the Uauth key to only sign valid FIDO signature assertions. In this case, the calling application could potentially get any hash value signed by the authenticator. If this field is missing, the assumed value is isKeyRestricted=true.
	IsKeyRestricted bool `json:"isKeyRestricted"`
	// This entry is set to true, if Uauth key usage always requires a fresh user verification. If this field is missing, the assumed value is isFreshUserVerificationRequired=true. This entry is set to false, if the Uauth key can be used without requiring a fresh user verification, e.g. without any additional user interaction, if the user was verified a (potentially configurable) caching time ago.
	// In the case of isFreshUserVerificationRequired=false, the FIDO server MUST verify the registration response and/or authentication response and verify that the (maximum) caching time (sometimes also called "authTimeout") is acceptable.
	// This entry solely refers to the user verification. In the case of transaction confirmation, the authenticator MUST always ask the user to authorize the specific transaction.
	IsFreshUserVerificationRequired bool `json:"isFreshUserVerificationRequired"`

	// TODO:
	// required DOMString[]                         matcherProtection;
	// unsigned short                               cryptoStrength;
	// DOMString[]                                  attachmentHint;
	// required DOMString[]                         tcDisplay;
	// DOMString                                    tcDisplayContentType;
	// DisplayPNGCharacteristicsDescriptor[]        tcDisplayPNGCharacteristics;
	// required DOMString[]                         attestationRootCertificates;
	// EcdaaTrustAnchor[]                           ecdaaTrustAnchors;

	// A data: url [RFC2397](https://datatracker.ietf.org/doc/html/rfc2397) encoded [PNG](https://www.w3.org/TR/png/) icon for the Authenticator.
	Icon string `json:"icon"`

	// TODO:
	// ExtensionDescriptor[]                        supportedExtensions;
	// AuthenticatorGetInfo                         authenticatorGetInfo;
}

type BiometricStatusReport struct {
	// Achieved level of the biometric certification of this biometric component of the authenticator.
	CertLevel uint8 `json:"certLevel"`
	// A single USER_VERIFY short form case-sensitive string name constant, representing biometric modality. See section "User Verification Methods" in [FIDORegistry] (e.g. "fingerprint_internal"). This value MUST NOT be empty and this value MUST correspond to one or more entries in field userVerificationDetails in the related Metadata Statement [FIDOMetadataStatement]. This value MUST represent a biometric modality.
	Modality string `json:"modality"`
	// ISO-8601 formatted date since when the certLevel achieved, if applicable. If no date is given, the status is assumed to be effective while present.
	EffectiveDate *string `json:"effectiveDate"`
	// Describes the externally visible aspects of the Biometric Certification evaluation.
	CertificationDescriptor *string `json:"certificationDescriptor"`
	// The unique identifier for the issued Biometric Certification.
	CertificateNumber *string `json:"certificateNumber"`
	// The version of the Biometric Certification Policy the implementation is Certified to, e.g. "1.0.0".
	CertificationPolicyVersion *string `json:"certificationPolicyVersion"`
	// The version of the Biometric Requirements [FIDOBiometricsRequirements] the implementation is certified to, e.g. "1.0.0".
	CertificationRequirementsVersion *string `json:"certificationRequirementsVersion"`
}

type Entry struct {
	//  The Authenticator Attestation GUID. See [FIDOKeyAttestation](https://fidoalliance.org/specs/fido-v2.0-ps-20150904/fido-key-attestation-v2.0-ps-20150904.html) for the definition of the AAGUID structure. This field MUST be set if the authenticator implements FIDO2.
	AAGUID string `json:"aaguid"`
	// The AAID of the authenticator this metadata BLOB payload entry relates to. See [UAFProtocol] for the definition of the AAID structure. This field MUST be set if the authenticator implements FIDO UAF.
	AAID string `json:"aaid"`
	// The metadataStatement JSON object.
	MetadataStatement MetadataStatement `json:"metadataStatement"`
	// A list of the attestation certificate public key identifiers encoded as hex string. This value MUST be calculated according to method 1 for computing the keyIdentifier as defined in [RFC5280] section 4.2.1.2.
	// - The hex string MUST NOT contain any non-hex characters (e.g. spaces).
	// - All hex letters MUST be lower case.
	// - This field MUST be set if neither aaid nor aaguid are set. Setting this field implies that the attestation certificate(s) are dedicated to a single authenticator model.
	AttestationCertificateKeyIdentifiers []string `json:"attestationCertificateKeyIdentifiers"`
	// Status of the FIDO Biometric Certification of one or more biometric components of the Authenticator.
	BiometricStatusReports []BiometricStatusReport `json:"biometricStatusReports"`
	// An array of status reports applicable to this authenticator.
	StatusReports []StatusReport `json:"statusReports"`
	// ISO-8601 formatted date since when the status report array was set to the current value.
	TimeOfLastStatusChange string `json:"timeOfLastStatusChange"`
	// URL of a list of rogue (i.e. untrusted) individual authenticators.
	RogueListURL string `json:"rogueListURL"`
	// base64url(string[1..512])
	RogueListHash string `json:"rogueListHash"`
}
