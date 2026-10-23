package inference

import "strings"

// ResultValidationError records only a closed category. Provider content, IDs,
// references and underlying errors are deliberately absent from this type.
type ResultValidationError struct{ Reason string }

func (e *ResultValidationError) Error() string {
	if validValidationReason(e.Reason) {
		return "result_validation_failed:" + e.Reason
	}
	return "result_validation_failed"
}
func (*ResultValidationError) Unwrap() error { return ErrInvalid }
func invalidResult(reason string) error      { return &ResultValidationError{Reason: reason} }
func validValidationReason(reason string) bool {
	switch reason {
	case "null_collections", "version_kind", "limits", "labels_intent", "root_refs", "claim_fields_refs", "entity_fields_refs", "role_fields_refs", "observable_extraction", "plan", "identity":
		return true
	}
	return false
}
func IsResultValidationCode(code string) bool {
	if code == "result_validation_failed" {
		return true
	}
	return strings.HasPrefix(code, "result_validation_failed:") && validValidationReason(strings.TrimPrefix(code, "result_validation_failed:"))
}
func validationCode(code string) (string, string) {
	if code == "result_validation_failed" {
		return code, ""
	}
	if strings.HasPrefix(code, "result_validation_failed:") {
		reason := strings.TrimPrefix(code, "result_validation_failed:")
		if validValidationReason(reason) {
			return "result_validation_failed", reason
		}
		return "result_validation_failed", ""
	}
	return code, ""
}
