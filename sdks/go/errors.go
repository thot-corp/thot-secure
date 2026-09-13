package thotsecure

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

/* ====================================================================================== */
/* Codes du contrat §4.6                                                                   */
/* ====================================================================================== */

// Codes d'erreur normalisés par le contrat d'interface (§4.6).
const (
	CodeValidationError = "validation_error" // 400
	CodeUnauthenticated = "unauthenticated"   // 401
	CodeForbidden       = "forbidden"         // 403
	CodeNotFound        = "not_found"         // 404
	CodeConflict        = "conflict"          // 409
	CodeUnprocessable   = "unprocessable"     // 422
	CodeRateLimited     = "rate_limited"      // 429
	CodeInternalError   = "internal_error"    // 500
	CodeTransportError  = "transport_error"   // erreur réseau locale
)

// Redacted est la valeur de remplacement des données masquées.
const Redacted = "[REDACTED]"

/* ====================================================================================== */
/* APIError                                                                                */
/* ====================================================================================== */

// APIError est l'erreur unique du SDK : elle couvre aussi bien un refus HTTP normalisé par le
// contrat §4.6 qu'une erreur de transport locale.
//
// Un appelant l'inspecte avec `errors.As` :
//
//	var apiErr *thotsecure.APIError
//	if errors.As(err, &apiErr) && apiErr.IsRateLimited() {
//		time.Sleep(apiErr.RetryAfter)
//	}
//
// Aucun secret n'y figure : l'URL est masquée par `redactURL`.
type APIError struct {
	// StatusCode est le statut HTTP observé (0 pour une erreur purement locale).
	StatusCode int
	// Code est le code du contrat (`forbidden`, `rate_limited`…).
	Code string
	// Message est le message renvoyé par le serveur (ou un message local explicite).
	Message string
	// Details est le bloc `details` du contrat, jamais censé contenir de secret.
	Details map[string]any
	// Method et URL identifient l'appel fautif (URL masquée).
	Method string
	URL    string
	// RequestID est l'identifiant de corrélation éventuel (`X-Request-Id`).
	RequestID string
	// RetryAfter est le délai conseillé par le serveur (en-tête `Retry-After`), 0 si absent.
	RetryAfter time.Duration
	// Retryable indique qu'un nouvel essai a un sens (429/502/503/504, erreur réseau).
	Retryable bool
	// Cause est l'erreur d'origine (erreur réseau, annulation de contexte…).
	Cause error
}

// Error implémente `error` : `message (status=403, code=forbidden, GET /api/v1/findings/f1)`.
func (e *APIError) Error() string {
	if e == nil {
		return "<nil>"
	}
	message := e.Message
	if message == "" {
		if e.StatusCode > 0 {
			message = fmt.Sprintf("HTTP %d", e.StatusCode)
		} else {
			message = "erreur inconnue"
		}
	}
	parts := make([]string, 0, 4)
	if e.StatusCode > 0 {
		parts = append(parts, fmt.Sprintf("status=%d", e.StatusCode))
	}
	if e.Code != "" {
		parts = append(parts, "code="+e.Code)
	}
	if e.Method != "" {
		parts = append(parts, strings.TrimSpace(e.Method+" "+redactURL(e.URL)))
	}
	if e.RequestID != "" {
		parts = append(parts, "request_id="+e.RequestID)
	}
	if len(parts) == 0 {
		return message
	}
	return fmt.Sprintf("%s (%s)", message, strings.Join(parts, ", "))
}

// Unwrap expose la cause d'origine (compatible `errors.Is` / `errors.As`).
func (e *APIError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// IsNotFound : **404** — ressource inexistante, ou appartenant à un autre tenant (isolation §1).
func (e *APIError) IsNotFound() bool {
	return e.matches(http.StatusNotFound, CodeNotFound)
}

// IsForbidden : **403** — clé valide mais capacité RBAC manquante (contrat §4).
func (e *APIError) IsForbidden() bool {
	return e.matches(http.StatusForbidden, CodeForbidden)
}

// IsRateLimited : **429** — quota dépassé ; voir `RetryAfter`.
func (e *APIError) IsRateLimited() bool {
	return e.matches(http.StatusTooManyRequests, CodeRateLimited)
}

// IsConflict : **409** — conflit d'état (action non approuvée, rollback déjà effectué…).
func (e *APIError) IsConflict() bool {
	return e.matches(http.StatusConflict, CodeConflict)
}

// IsUnauthenticated : **401** — clé absente, inconnue ou révoquée.
func (e *APIError) IsUnauthenticated() bool {
	return e.matches(http.StatusUnauthorized, CodeUnauthenticated)
}

// IsValidation : **400** ou **422** — corps de requête invalide.
func (e *APIError) IsValidation() bool {
	if e == nil {
		return false
	}
	return e.Code == CodeValidationError || e.Code == CodeUnprocessable ||
		e.StatusCode == http.StatusBadRequest || e.StatusCode == http.StatusUnprocessableEntity
}

// IsServerError : **5xx** — erreur interne du serveur.
func (e *APIError) IsServerError() bool {
	return e != nil && e.StatusCode >= 500 && e.StatusCode < 600
}

// IsTransport : erreur réseau locale (aucune réponse HTTP reçue).
func (e *APIError) IsTransport() bool {
	return e != nil && e.StatusCode == 0
}

// matches compare code du contrat et statut HTTP (le code prime, le statut sert de repli).
func (e *APIError) matches(status int, code string) bool {
	if e == nil {
		return false
	}
	if e.Code != "" {
		return e.Code == code
	}
	return e.StatusCode == status
}

// AsAPIError extrait un `*APIError` d'une chaîne d'erreurs.
func AsAPIError(err error) (*APIError, bool) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr, true
	}
	return nil, false
}

/* ====================================================================================== */
/* Construction depuis une réponse HTTP                                                    */
/* ====================================================================================== */

// retryableStatus : statuts transitoires pour lesquels un nouvel essai a un sens.
func retryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, // 429
		http.StatusBadGateway,         // 502
		http.StatusServiceUnavailable, // 503
		http.StatusGatewayTimeout:     // 504
		return true
	default:
		return false
	}
}

// codeForStatus donne le code du contrat associé à un statut HTTP.
func codeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return CodeValidationError
	case http.StatusUnauthorized:
		return CodeUnauthenticated
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusConflict:
		return CodeConflict
	case http.StatusUnprocessableEntity:
		return CodeUnprocessable
	case http.StatusTooManyRequests:
		return CodeRateLimited
	default:
		if status >= 500 {
			return CodeInternalError
		}
		return CodeInternalError
	}
}

// apiErrorFromResponse traduit une réponse HTTP en erreur du SDK.
//
// Priorité : `error.code` du contrat → statut HTTP → corps brut. Comme pour les autres SDK, un
// corps non JSON (proxy, page d'erreur d'un reverse-proxy) reste exploitable.
func apiErrorFromResponse(
	status int,
	body []byte,
	header http.Header,
	method string,
	rawURL string,
) *APIError {
	payload := strings.TrimSpace(string(body))
	code := ""
	message := ""
	details := map[string]any(nil)

	var envelope APIErrorBody
	if payload != "" && json.Unmarshal(body, &envelope) == nil && envelope.Error.Code != "" {
		code = envelope.Error.Code
		message = envelope.Error.Message
		details = envelope.Error.Details
	} else {
		// FastAPI renvoie parfois {"detail": "…"} : on l'accepte sans le masquer.
		var detail struct {
			Detail any `json:"detail"`
		}
		if payload != "" && json.Unmarshal(body, &detail) == nil && detail.Detail != nil {
			switch value := detail.Detail.(type) {
			case string:
				message = value
			default:
				message = "validation error"
				details = map[string]any{"errors": value}
			}
		}
	}
	if code == "" {
		code = codeForStatus(status)
	}
	if message == "" {
		if payload != "" {
			message = truncate(payload, 500)
		} else {
			message = fmt.Sprintf("HTTP %d", status)
		}
	}

	apiErr := &APIError{
		StatusCode: status,
		Code:       code,
		Message:    message,
		Details:    details,
		Method:     method,
		URL:        rawURL,
		RequestID:  firstHeader(header, "X-Request-Id", "X-Correlation-Id"),
		Retryable:  retryableStatus(status),
	}
	if header != nil {
		if delay, ok := parseRetryAfterHeader(header.Get("Retry-After"), time.Now()); ok {
			apiErr.RetryAfter = delay
		}
	}
	if apiErr.RetryAfter == 0 && details != nil {
		apiErr.RetryAfter = retryAfterFromDetails(details)
	}
	return apiErr
}

// transportError construit une erreur réseau (aucune réponse HTTP reçue).
func transportError(method, rawURL, message string, cause error) *APIError {
	return &APIError{
		Code:      CodeTransportError,
		Message:   message,
		Method:    method,
		URL:       rawURL,
		Retryable: true,
		Cause:     cause,
	}
}

/* ====================================================================================== */
/* Utilitaires                                                                             */
/* ====================================================================================== */

// parseRetryAfterHeader convertit un en-tête `Retry-After` (secondes ou date HTTP) en durée.
func parseRetryAfterHeader(value string, now time.Time) (time.Duration, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(trimmed); err == nil {
		if seconds < 0 {
			seconds = 0
		}
		return time.Duration(seconds) * time.Second, true
	}
	if when, err := http.ParseTime(trimmed); err == nil {
		delay := when.Sub(now)
		if delay < 0 {
			delay = 0
		}
		return delay, true
	}
	return 0, false
}

// retryAfterFromDetails lit `details.retry_after` (secondes) si l'en-tête est absent.
func retryAfterFromDetails(details map[string]any) time.Duration {
	raw, ok := details["retry_after"]
	if !ok {
		return 0
	}
	switch value := raw.(type) {
	case float64:
		return time.Duration(value * float64(time.Second))
	case int:
		return time.Duration(value) * time.Second
	case int64:
		return time.Duration(value) * time.Second
	case string:
		if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			return time.Duration(seconds) * time.Second
		}
	}
	return 0
}

// sensitiveQueryParams : paramètres d'URL qui ne doivent jamais apparaître dans un message.
var sensitiveQueryParams = []string{
	"api_key", "apikey", "api-key", "token", "access_token", "refresh_token",
	"key", "password", "secret",
}

// redactURL masque les paramètres sensibles d'une URL avant toute journalisation.
func redactURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	lower := strings.ToLower(rawURL)
	for _, param := range sensitiveQueryParams {
		needle := param + "="
		searchFrom := 0
		for {
			index := strings.Index(lower[searchFrom:], needle)
			if index < 0 {
				break
			}
			start := searchFrom + index + len(needle)
			end := start
			for end < len(rawURL) && rawURL[end] != '&' && rawURL[end] != '#' && rawURL[end] != ' ' {
				end++
			}
			rawURL = rawURL[:start] + "***" + rawURL[end:]
			lower = strings.ToLower(rawURL)
			searchFrom = start + 3
		}
	}
	return rawURL
}

// firstHeader retourne la première valeur non vide parmi les en-têtes donnés (casse ignorée).
func firstHeader(header http.Header, names ...string) string {
	if header == nil {
		return ""
	}
	for _, name := range names {
		if value := header.Get(name); value != "" {
			return value
		}
	}
	return ""
}

// truncate coupe une chaîne à n runes (bornes en runes, sans casser l'UTF-8).
func truncate(value string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= n {
		return value
	}
	return string(runes[:n]) + "…"
}
