package thotsecure

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

/* ====================================================================================== */
/* Constantes publiques                                                                    */
/* ====================================================================================== */

const (
	// DefaultBaseURL est la racine par défaut du service.
	DefaultBaseURL = "http://127.0.0.1:8080"
	// APIPrefix est le préfixe des routes métier (contrat §4).
	APIPrefix = "/api/v1"
	// SDKVersion est la version de ce SDK.
	SDKVersion = "0.1.0"
	// APIContractVersion est la version du contrat d'interface implémentée.
	APIContractVersion = "0.1.0"
	// MaxBatchSize est la taille maximale d'un lot d'ingestion (contrat §4.3 : ≤ 500).
	MaxBatchSize = 500
	// DefaultUserAgent est l'en-tête `User-Agent` envoyé par le SDK.
	DefaultUserAgent = "thot-secure-sdk-go/0.1.0"

	defaultMaxRetries  = 3
	defaultBackoffBase = 500 * time.Millisecond
	defaultBackoffMax  = 30 * time.Second
	defaultTimeout     = 30 * time.Second
	// maxResponseBytes borne la lecture d'une réponse (protection anti-flux infini).
	maxResponseBytes = 32 << 20
)

/* ====================================================================================== */
/* Options du client                                                                       */
/* ====================================================================================== */

// Option configure un `Client` (modèle des options fonctionnelles).
type Option func(*Client)

// WithBaseURL fixe la racine du service (`http://` ou `https://`).
//
// Par défaut : `THOT_SECURE_URL`, `THOT_URL`, puis `THOT_URL`, puis `DefaultBaseURL`.
func WithBaseURL(baseURL string) Option {
	return func(c *Client) { c.baseURL = baseURL }
}

// WithAPIKey fixe la clé API `ao_…`. Elle n'est **jamais** journalisée ni renvoyée par un
// accesseur : seul `APIKeyConfigured` indique si elle est définie.
//
// Par défaut : `THOT_SECURE_API_KEY`, `THOT_API_KEY`, puis `THOT_API_KEY`.
func WithAPIKey(apiKey string) Option {
	return func(c *Client) { c.apiKey = strings.TrimSpace(apiKey) }
}

// WithTenantID fixe le tenant utilisé par les routes `{id}` et par le flux WebSocket.
func WithTenantID(tenantID string) Option {
	return func(c *Client) { c.tenantID = strings.TrimSpace(tenantID) }
}

// WithHTTPClient injecte un `*http.Client` existant (proxy, instrumentation, tests).
//
// Le SDK ne modifie jamais ce client ; `WithTimeout` et `WithInsecureTLS` ne s'appliquent alors
// qu'au client créé par le SDK.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
			c.customHTTPClient = true
		}
	}
}

// WithMaxRetries fixe le nombre de tentatives **supplémentaires** (défaut 3).
//
// Une reprise n'a lieu que sur les statuts transitoires (429/502/503/504) et les erreurs réseau,
// et jamais sur une méthode non idempotente dépourvue de clé d'idempotence.
func WithMaxRetries(maxRetries int) Option {
	return func(c *Client) { c.maxRetries = maxRetries }
}

// WithUserAgent remplace l'en-tête `User-Agent`.
func WithUserAgent(userAgent string) Option {
	return func(c *Client) {
		if strings.TrimSpace(userAgent) != "" {
			c.userAgent = strings.TrimSpace(userAgent)
		}
	}
}

// WithTimeout fixe le délai global du client HTTP créé par le SDK (défaut 30 s).
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		if timeout > 0 {
			c.timeout = timeout
		}
	}
}

// WithBackoff ajuste le backoff de reprise (base et plafond).
func WithBackoff(base, maxDelay time.Duration) Option {
	return func(c *Client) {
		if base > 0 {
			c.backoffBase = base
		}
		if maxDelay > 0 {
			c.backoffMax = maxDelay
		}
	}
}

// WithLogger injecte un journal `log/slog` (défaut : `slog.Default()`).
//
// Le SDK n'y écrit jamais de secret : ni clé API, ni en-tête, ni URL non masquée.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Client) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithInsecureTLS désactive la vérification du certificat TLS.
//
// ⚠️ **DANGEREUX — à n'utiliser que sur un laboratoire isolé**, jamais en production : sans
// vérification du certificat, un attaquant en position d'homme du milieu peut lire et modifier
// tout le trafic (clé API, findings, actions de remédiation). Le SDK journalise un
// avertissement bruyant à la construction lorsqu'une telle désactivation est active, et le
// `README.md` le rappelle. La vérification TLS est **activée par défaut** et n'est jamais
// désactivée implicitement.
func WithInsecureTLS() Option {
	return func(c *Client) { c.insecureTLS = true }
}

/* ====================================================================================== */
/* Options d'appel                                                                         */
/* ====================================================================================== */

// callOptions regroupe les réglages d'un appel unitaire.
type callOptions struct {
	idempotencyKey string
	comment        string
	reason         string
	dryRun         *bool
	batchSize      int
	onBatch        func(*IngestResult) error
	headers        map[string]string
	noRetry        bool
}

// CallOption ajuste un appel unitaire (clé d'idempotence, commentaire, en-tête…).
type CallOption func(*callOptions)

// WithIdempotencyKey fournit une clé d'idempotence.
//
// Effet de bord important : elle rend un `POST`/`PATCH` **réessayable** sans risque de double
// exécution (le serveur déduplique), ce que le SDK refuse par défaut.
func WithIdempotencyKey(key string) CallOption {
	return func(o *callOptions) { o.idempotencyKey = strings.TrimSpace(key) }
}

// WithComment joint un commentaire (approbation, acquittement).
func WithComment(comment string) CallOption {
	return func(o *callOptions) { o.comment = comment }
}

// WithReason joint un motif (rejet, rollback).
func WithReason(reason string) CallOption {
	return func(o *callOptions) { o.reason = reason }
}

// WithDryRun force l'indicateur `dry_run` du corps de requête.
//
// Le SDK ne lève **jamais** ce garde-fou de lui-même : `PlanAction` reste une simulation tant que
// `WithDryRun(false)` (ou `PlanActionInput.DryRun`) ne l'indique pas explicitement.
func WithDryRun(dryRun bool) CallOption {
	return func(o *callOptions) { o.dryRun = &dryRun }
}

// WithBatchSize fixe la taille des lots d'ingestion (≤ MaxBatchSize).
func WithBatchSize(size int) CallOption {
	return func(o *callOptions) { o.batchSize = size }
}

// WithBatchCallback est appelé après **chaque** lot d'ingestion confirmé : c'est le point
// d'ancrage de la contre-pression (ne produisez le lot suivant qu'ici).
func WithBatchCallback(fn func(*IngestResult) error) CallOption {
	return func(o *callOptions) { o.onBatch = fn }
}

// WithHeader ajoute un en-tête HTTP à l'appel.
func WithHeader(name, value string) CallOption {
	return func(o *callOptions) { o.headers[name] = value }
}

// WithoutRetry interdit toute reprise pour cet appel (sondes `/readyz`, appels non idempotents).
func WithoutRetry() CallOption {
	return func(o *callOptions) { o.noRetry = true }
}

func newCallOptions(opts ...CallOption) *callOptions {
	out := &callOptions{headers: map[string]string{}}
	for _, opt := range opts {
		if opt != nil {
			opt(out)
		}
	}
	return out
}

/* ====================================================================================== */
/* Client                                                                                  */
/* ====================================================================================== */

// Client est le client REST du SDK. Il est **sûr en concurrence** : créez-en un seul et
// partagez-le entre goroutines.
//
// Utilisation :
//
//	client, err := thotsecure.NewClient(thotsecure.WithTenantID("acme"))
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer client.Close()
//
//	findings, err := client.ListFindings(ctx, thotsecure.ListFindingsOptions{Status: "open", MinRisk: 70})
type Client struct {
	baseURL          string
	apiKey           string
	tenantID         string
	userAgent        string
	maxRetries       int
	backoffBase      time.Duration
	backoffMax       time.Duration
	timeout          time.Duration
	httpClient       *http.Client
	logger           *slog.Logger
	insecureTLS      bool
	customHTTPClient bool
	randFloat        func() float64
	sleep            func(ctx context.Context, delay time.Duration) error
}

// NewClient construit un client. Aucun paramètre n'est obligatoire : la configuration par défaut
// est sûre (racine locale, TLS vérifié, dry-run côté serveur, aucune reprise dangereuse).
func NewClient(opts ...Option) (*Client, error) {
	client := &Client{
		baseURL:     firstEnv("THOT_SECURE_URL", "THOT_URL", "THOT_URL", "AEGIS_OPS_URL"),
		apiKey:      firstEnv("THOT_SECURE_API_KEY", "THOT_API_KEY", "THOT_API_KEY", "AEGIS_OPS_API_KEY"),
		tenantID:    firstEnv("THOT_SECURE_TENANT_ID", "THOT_TENANT_ID", "THOT_TENANT_ID", "AEGIS_OPS_TENANT_ID"),
		userAgent:   DefaultUserAgent,
		maxRetries:  defaultMaxRetries,
		backoffBase: defaultBackoffBase,
		backoffMax:  defaultBackoffMax,
		timeout:     defaultTimeout,
		logger:      slog.Default(),
		randFloat:   rand.Float64,
		sleep:       sleepContext,
	}
	if strings.TrimSpace(client.baseURL) == "" {
		client.baseURL = DefaultBaseURL
	}
	for _, opt := range opts {
		if opt != nil {
			opt(client)
		}
	}

	client.baseURL = strings.TrimRight(strings.TrimSpace(client.baseURL), "/")
	if client.baseURL == "" {
		return nil, validationError("NewClient", "base URL vide")
	}
	if !strings.HasPrefix(client.baseURL, "http://") && !strings.HasPrefix(client.baseURL, "https://") {
		return nil, validationError("NewClient", fmt.Sprintf(
			"base URL invalide « %s » : attendu http:// ou https://", client.baseURL))
	}
	if client.maxRetries < 0 {
		client.maxRetries = 0
	}
	if client.backoffBase < 0 {
		client.backoffBase = 0
	}
	if client.backoffMax < client.backoffBase {
		client.backoffMax = client.backoffBase
	}

	if client.httpClient == nil {
		httpClient := &http.Client{Timeout: client.timeout}
		if client.insecureTLS {
			transport, ok := http.DefaultTransport.(*http.Transport)
			var cloned *http.Transport
			if ok {
				cloned = transport.Clone()
			} else {
				cloned = &http.Transport{}
			}
			// #nosec G402 — désactivation explicite, demandée par l'appelant, jamais par défaut.
			cloned.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			httpClient.Transport = cloned
			client.logger.Warn(
				"thotsecure: ATTENTION — la vérification du certificat TLS est DÉSACTIVÉE "+
					"(WithInsecureTLS). Le trafic peut être intercepté et modifié : à réserver "+
					"à un laboratoire isolé, jamais à la production.")
		}
		client.httpClient = httpClient
	} else if client.insecureTLS {
		client.logger.Warn(
			"thotsecure: WithInsecureTLS ignoré — un client HTTP personnalisé a été fourni " +
				"(WithHTTPClient) : configurez sa propre `TLSClientConfig` si nécessaire.")
	}

	return client, nil
}

/* -------------------------------------------------------------------------------------- */
/* Accesseurs et cycle de vie                                                              */
/* -------------------------------------------------------------------------------------- */

// BaseURL retourne la racine configurée (sans clé API).
func (c *Client) BaseURL() string { return c.baseURL }

// TenantID retourne le tenant configuré, chaîne vide s'il n'y en a pas.
func (c *Client) TenantID() string { return c.tenantID }

// APIKeyConfigured indique si une clé API est configurée — **sans jamais la révéler**.
func (c *Client) APIKeyConfigured() bool { return c.apiKey != "" }

// String représente le client sans jamais exposer la clé API.
func (c *Client) String() string {
	key := "null"
	if c.apiKey != "" {
		key = "'***'"
	}
	tenant := c.tenantID
	if tenant == "" {
		tenant = "null"
	}
	return fmt.Sprintf("Client(base_url=%s, tenant_id=%s, api_key=%s)", c.baseURL, tenant, key)
}

// Close ferme les connexions HTTP inactives. Le client reste utilisable ensuite.
func (c *Client) Close() {
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
}

// StreamURL construit l'URL `ws://` / `wss://` du flux temps réel (contrat §4.8).
//
// ⚠️ L'URL retournée **contient la clé API** (les navigateurs ne peuvent pas poser d'en-tête sur
// `ws://`) : ne la journalisez jamais telle quelle, utilisez `redactURL` ou `StreamURLRedacted`.
func (c *Client) StreamURL(path string) (string, error) {
	if path == "" {
		path = WSPath
	}
	return NewStreamURL(c.baseURL, c.apiKey, c.tenantID, path)
}

// StreamURLRedacted est la variante sûre à journaliser : la clé API y est masquée.
func (c *Client) StreamURLRedacted(path string) (string, error) {
	raw, err := c.StreamURL(path)
	if err != nil {
		return "", err
	}
	return redactURL(raw), nil
}

/* -------------------------------------------------------------------------------------- */
/* Exécution des requêtes                                                                  */
/* -------------------------------------------------------------------------------------- */

// requestSpec décrit un appel HTTP interne.
type requestSpec struct {
	method      string
	path        string
	query       url.Values
	body        any
	rawBody     []byte
	contentType string
	noAuth      bool
	accept      string
	out         any
	rawOut      *[]byte
	opts        *callOptions
}

// call exécute une requête avec la politique de reprise du SDK.
func (c *Client) call(ctx context.Context, spec requestSpec) error {
	opts := spec.opts
	if opts == nil {
		opts = &callOptions{headers: map[string]string{}}
	}

	fullURL := c.baseURL + spec.path
	if len(spec.query) > 0 {
		fullURL += "?" + spec.query.Encode()
	}

	var body []byte
	switch {
	case spec.rawBody != nil:
		body = spec.rawBody
	case spec.body != nil:
		encoded, err := json.Marshal(spec.body)
		if err != nil {
			return validationError(spec.method, "sérialisation JSON impossible : "+err.Error())
		}
		body = encoded
	}

	contentType := spec.contentType
	if contentType == "" && body != nil {
		contentType = "application/json"
	}
	accept := spec.accept
	if accept == "" {
		accept = "application/json"
	}

	// Une reprise n'est permise que sur une méthode idempotente ou avec une clé d'idempotence.
	retrySafe := isIdempotentMethod(spec.method) || opts.idempotencyKey != ""
	if opts.noRetry {
		retrySafe = false
	}

	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		request, err := http.NewRequestWithContext(ctx, spec.method, fullURL, bytes.NewReader(body))
		if err != nil {
			return validationError(spec.method, "requête invalide : "+err.Error())
		}
		request.Header.Set("Accept", accept)
		request.Header.Set("User-Agent", c.userAgent)
		if !spec.noAuth && c.apiKey != "" {
			request.Header.Set("X-API-Key", c.apiKey)
		}
		if contentType != "" && body != nil {
			request.Header.Set("Content-Type", contentType)
		}
		if opts.idempotencyKey != "" {
			request.Header.Set("Idempotency-Key", opts.idempotencyKey)
		}
		for name, value := range opts.headers {
			request.Header.Set(name, value)
		}

		response, err := c.httpClient.Do(request)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			apiErr := transportError(spec.method, fullURL, "échec du transport : "+err.Error(), err)
			if !retrySafe || attempt >= c.maxRetries {
				return apiErr
			}
			c.logger.Warn("thotsecure: échec réseau, nouvel essai",
				"attempt", attempt+1, "method", spec.method, "url", redactURL(fullURL))
			if err := c.sleep(ctx, c.backoffDelay(attempt)); err != nil {
				return err
			}
			continue
		}

		responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
		closeErr := response.Body.Close()
		if readErr == nil {
			readErr = closeErr
		}
		if readErr != nil {
			apiErr := transportError(spec.method, fullURL, "lecture de la réponse impossible : "+readErr.Error(), readErr)
			if !retrySafe || attempt >= c.maxRetries {
				return apiErr
			}
			c.logger.Warn("thotsecure: lecture de réponse interrompue, nouvel essai",
				"attempt", attempt+1, "method", spec.method, "url", redactURL(fullURL))
			if err := c.sleep(ctx, c.backoffDelay(attempt)); err != nil {
				return err
			}
			continue
		}

		if response.StatusCode >= 400 {
			apiErr := apiErrorFromResponse(response.StatusCode, responseBody, response.Header, spec.method, fullURL)
			if apiErr.Retryable && retrySafe && attempt < c.maxRetries {
				delay := apiErr.RetryAfter
				if delay <= 0 {
					delay = c.backoffDelay(attempt)
				}
				c.logger.Warn("thotsecure: réponse transitoire, nouvel essai",
					"attempt", attempt+1, "status", apiErr.StatusCode, "code", apiErr.Code,
					"delay", delay.String(), "method", spec.method, "url", redactURL(fullURL))
				if err := c.sleep(ctx, delay); err != nil {
					return err
				}
				continue
			}
			return apiErr
		}

		if spec.rawOut != nil {
			*spec.rawOut = responseBody
			return nil
		}
		if spec.out == nil {
			return nil
		}
		if len(bytes.TrimSpace(responseBody)) == 0 {
			return nil
		}
		if err := json.Unmarshal(responseBody, spec.out); err != nil {
			return &APIError{
				StatusCode: response.StatusCode,
				Code:       "invalid_response",
				Message:    "réponse non JSON ou non conforme au contrat : " + err.Error(),
				Method:     spec.method,
				URL:        fullURL,
				Cause:      err,
			}
		}
		return nil
	}
}

// backoffDelay : backoff exponentiel plafonné, avec jitter multiplicatif dans [0.5, 1[.
func (c *Client) backoffDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	raw := float64(c.backoffBase) * math.Pow(2, float64(attempt))
	if limit := float64(c.backoffMax); raw > limit {
		raw = limit
	}
	sample := c.randFloat()
	if math.IsNaN(sample) {
		sample = 1
	}
	jitter := 0.5 + 0.5*math.Min(1, math.Max(0, sample))
	return time.Duration(raw * jitter)
}

// sleepContext attend un délai, en respectant l'annulation du contexte.
func sleepContext(ctx context.Context, delay time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// isIdempotentMethod : méthodes réessayables sans risque (RFC 9110).
func isIdempotentMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

// validationError construit une erreur locale de validation.
func validationError(method, message string) *APIError {
	return &APIError{
		Code:      CodeValidationError,
		Message:   message,
		Method:    method,
		Retryable: false,
	}
}

// firstEnv retourne la première variable d'environnement non vide parmi les noms donnés.
func firstEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

// setIfNotEmpty ajoute un filtre non vide à une chaîne de requête.
func setIfNotEmpty(query url.Values, key, value string) {
	if value != "" {
		query.Set(key, value)
	}
}

// requireTenant résout le tenant (`read:stats` self, contrat §4.2).
func (c *Client) requireTenant(tenantID string) (string, error) {
	resolved := strings.TrimSpace(tenantID)
	if resolved == "" {
		resolved = c.tenantID
	}
	if resolved == "" {
		return "", validationError("tenant", "aucun tenant_id : passez-le en argument, dans WithTenantID, "+
			"ou via THOT_SECURE_TENANT_ID")
	}
	return resolved, nil
}

// fillTenant renseigne `tenant_id` depuis la configuration du client (copie défensive).
func (c *Client) fillTenant(events []EventInput) []EventInput {
	out := make([]EventInput, len(events))
	copy(out, events)
	if c.tenantID == "" {
		return out
	}
	for index := range out {
		if out[index].TenantID == "" {
			out[index].TenantID = c.tenantID
		}
	}
	return out
}

/* ====================================================================================== */
/* §4.1 Santé, méta, observabilité                                                         */
/* ====================================================================================== */

// Whoami appelle `GET /api/v1/auth/whoami` : tenant, rôle, capacités, mode d'autonomie.
func (c *Client) Whoami(ctx context.Context) (*WhoAmI, error) {
	out := &WhoAmI{}
	if err := c.call(ctx, requestSpec{method: http.MethodGet, path: APIPrefix + "/auth/whoami", out: out}); err != nil {
		return nil, err
	}
	return out, nil
}

// Healthz appelle `GET /healthz` (public).
func (c *Client) Healthz(ctx context.Context) (*HealthStatus, error) {
	out := &HealthStatus{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: "/healthz", noAuth: true, out: out,
		opts: newCallOptions(WithoutRetry()),
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// Readyz appelle `GET /readyz` (public : vérifie base, bus et règles).
//
// Un `503` **ne lève pas d'erreur** : il retourne `Status: "unavailable"` et `HTTPStatus: 503`,
// comportement attendu par une sonde d'orchestrateur. Aucune reprise n'est tentée.
func (c *Client) Readyz(ctx context.Context) (*ReadyStatus, error) {
	out := &ReadyStatus{}
	err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: "/readyz", noAuth: true, out: out,
		opts: newCallOptions(WithoutRetry()),
	})
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusServiceUnavailable {
			return &ReadyStatus{
				Status:     "unavailable",
				HTTPStatus: apiErr.StatusCode,
				Error:      apiErr.Message,
				Details:    apiErr.Details,
			}, nil
		}
		return nil, err
	}
	out.HTTPStatus = http.StatusOK
	if out.Status == "" {
		out.Status = "ready"
	}
	return out, nil
}

// Version appelle `GET /version` (public).
func (c *Client) Version(ctx context.Context) (*VersionInfo, error) {
	out := &VersionInfo{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: "/version", noAuth: true, out: out,
		opts: newCallOptions(WithoutRetry()),
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// Metrics appelle `GET /metrics` (public, réseau interne) et retourne le texte Prometheus.
func (c *Client) Metrics(ctx context.Context) (string, error) {
	var raw []byte
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: "/metrics", noAuth: true, accept: "text/plain", rawOut: &raw,
	}); err != nil {
		return "", err
	}
	return string(raw), nil
}

/* ====================================================================================== */
/* §4.2 Tenants et clés                                                                    */
/* ====================================================================================== */

// ListTenants appelle `GET /api/v1/tenants` (capacité `admin:tenants`).
func (c *Client) ListTenants(ctx context.Context) (*Page[Tenant], error) {
	out := &Page[Tenant]{}
	if err := c.call(ctx, requestSpec{method: http.MethodGet, path: APIPrefix + "/tenants", out: out}); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateTenant appelle `POST /api/v1/tenants` (capacité `admin:tenants`).
func (c *Client) CreateTenant(ctx context.Context, input CreateTenantInput) (*Tenant, error) {
	if strings.TrimSpace(input.TenantID) == "" {
		return nil, validationError("CreateTenant", "tenant_id requis")
	}
	if strings.TrimSpace(input.Name) == "" {
		return nil, validationError("CreateTenant", "name requis")
	}
	out := &Tenant{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodPost, path: APIPrefix + "/tenants", body: input, out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// GetTenant appelle `GET /api/v1/tenants/{id}` (capacité `read:stats`, self).
// Un `tenantID` vide utilise celui du client.
func (c *Client) GetTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	resolved, err := c.requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	out := &Tenant{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: APIPrefix + "/tenants/" + url.PathEscape(resolved), out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateTenant appelle `PATCH /api/v1/tenants/{id}` (capacité `admin:tenants`).
//
// ⚠️ `Mode: "auto"` ou `DryRun: false` change le niveau d'autonomie : décision de sécurité
// volontaire, limitée et journalisée (contrat §6).
func (c *Client) UpdateTenant(ctx context.Context, tenantID string, input UpdateTenantInput) (*Tenant, error) {
	resolved, err := c.requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	body := map[string]any{}
	if input.Mode != "" {
		body["mode"] = input.Mode
	}
	if input.DryRun != nil {
		body["dry_run"] = *input.DryRun
	}
	if input.Name != "" {
		body["name"] = input.Name
	}
	if input.AutonomyAllowlist != nil {
		body["autonomy_allowlist"] = input.AutonomyAllowlist
	}
	if len(body) == 0 {
		return nil, validationError("UpdateTenant", "aucun champ à modifier (mode, dry_run, name, autonomy_allowlist)")
	}
	out := &Tenant{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodPatch, path: APIPrefix + "/tenants/" + url.PathEscape(resolved), body: body, out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateKey appelle `POST /api/v1/tenants/{id}/keys` (capacité `admin:keys`).
//
// La valeur `api_key` n'est **affichée qu'une seule fois** : le SDK ne la journalise jamais.
func (c *Client) CreateKey(ctx context.Context, tenantID string, input CreateKeyInput) (*ApiKeyInfo, error) {
	resolved, err := c.requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.Role) == "" {
		return nil, validationError("CreateKey", "role requis (viewer|analyst|responder|admin)")
	}
	out := &ApiKeyInfo{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodPost,
		path:   APIPrefix + "/tenants/" + url.PathEscape(resolved) + "/keys",
		body:   input,
		out:    out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// ListKeys appelle `GET /api/v1/tenants/{id}/keys` (capacité `admin:keys`).
func (c *Client) ListKeys(ctx context.Context, tenantID string) (*Page[ApiKeyInfo], error) {
	resolved, err := c.requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	out := &Page[ApiKeyInfo]{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: APIPrefix + "/tenants/" + url.PathEscape(resolved) + "/keys", out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeKey appelle `DELETE /api/v1/keys/{key_id}` (capacité `admin:keys`) — révocation immédiate.
func (c *Client) RevokeKey(ctx context.Context, keyID string) error {
	if strings.TrimSpace(keyID) == "" {
		return validationError("RevokeKey", "key_id requis")
	}
	return c.call(ctx, requestSpec{
		method: http.MethodDelete, path: APIPrefix + "/keys/" + url.PathEscape(keyID),
	})
}

/* ====================================================================================== */
/* §4.3 Événements                                                                         */
/* ====================================================================================== */

// IngestEvent appelle `POST /api/v1/events` avec un événement unique (capacité `write:events`).
func (c *Client) IngestEvent(ctx context.Context, event EventInput, opts ...CallOption) (*IngestResult, error) {
	batch := c.fillTenant([]EventInput{event})
	out := &IngestResult{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodPost, path: APIPrefix + "/events", body: batch[0], out: out,
		opts: newCallOptions(opts...),
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// IngestEvents appelle `POST /api/v1/events` avec `{"events":[…]}` (capacité `write:events`).
//
// Le contrat impose **au plus 500 événements par lot** : les lots plus grands sont découpés
// automatiquement et les réponses fusionnées. `WithBatchCallback` est appelé après chaque lot
// confirmé — c'est le point d'ancrage de la contre-pression.
func (c *Client) IngestEvents(ctx context.Context, events []EventInput, opts ...CallOption) (*IngestResult, error) {
	callOpts := newCallOptions(opts...)
	batchSize := callOpts.batchSize
	if batchSize <= 0 {
		batchSize = MaxBatchSize
	}
	if batchSize > MaxBatchSize {
		return nil, validationError("IngestEvents",
			fmt.Sprintf("batch size %d > %d (limite du contrat §4.3)", batchSize, MaxBatchSize))
	}

	total := &IngestResult{EventIDs: []string{}, Findings: []IngestOutcome{}}
	for start := 0; start < len(events); start += batchSize {
		end := start + batchSize
		if end > len(events) {
			end = len(events)
		}
		batch := c.fillTenant(events[start:end])
		result := &IngestResult{}
		if err := c.call(ctx, requestSpec{
			method: http.MethodPost, path: APIPrefix + "/events",
			body: map[string]any{"events": batch}, out: result, opts: callOpts,
		}); err != nil {
			return total, err
		}
		total.Accepted += result.Accepted
		total.Rejected += result.Rejected
		total.EventIDs = append(total.EventIDs, result.EventIDs...)
		total.Findings = append(total.Findings, result.Findings...)
		if callOpts.onBatch != nil {
			if err := callOpts.onBatch(result); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

// ListEventsOptions filtre `GET /api/v1/events` (contrat §4.3).
type ListEventsOptions struct {
	Kind       string
	SourceType string
	Since      string
	Until      string
	Query      string
	Limit      int
	Cursor     string
}

// ListEvents appelle `GET /api/v1/events` (capacité `read:events`).
func (c *Client) ListEvents(ctx context.Context, opts ListEventsOptions) (*Page[Event], error) {
	query := url.Values{}
	setIfNotEmpty(query, "kind", opts.Kind)
	setIfNotEmpty(query, "source_type", opts.SourceType)
	setIfNotEmpty(query, "since", opts.Since)
	setIfNotEmpty(query, "until", opts.Until)
	setIfNotEmpty(query, "q", opts.Query)
	setIfNotEmpty(query, "cursor", opts.Cursor)
	if opts.Limit > 0 {
		if opts.Limit > MaxBatchSize {
			return nil, validationError("ListEvents", fmt.Sprintf("limit %d > %d (contrat §4.3)", opts.Limit, MaxBatchSize))
		}
		query.Set("limit", fmt.Sprintf("%d", opts.Limit))
	}
	out := &Page[Event]{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: APIPrefix + "/events", query: query, out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// GetEvent appelle `GET /api/v1/events/{event_id}` (capacité `read:events`).
func (c *Client) GetEvent(ctx context.Context, eventID string) (*Event, error) {
	if strings.TrimSpace(eventID) == "" {
		return nil, validationError("GetEvent", "event_id requis")
	}
	out := &Event{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: APIPrefix + "/events/" + url.PathEscape(eventID), out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

/* ====================================================================================== */
/* §4.4 Findings                                                                           */
/* ====================================================================================== */

// ListFindingsOptions filtre `GET /api/v1/findings` (contrat §4.4).
type ListFindingsOptions struct {
	Status   string
	Severity string
	RuleID   string
	Since    string
	Until    string
	MinRisk  float64
	// Sort ∈ `risk_score` | `last_seen`.
	Sort   string
	Limit  int
	Cursor string
}

// ListFindings appelle `GET /api/v1/findings` (capacité `read:findings`).
func (c *Client) ListFindings(ctx context.Context, opts ListFindingsOptions) (*Page[Finding], error) {
	query := url.Values{}
	setIfNotEmpty(query, "status", opts.Status)
	setIfNotEmpty(query, "severity", opts.Severity)
	setIfNotEmpty(query, "rule_id", opts.RuleID)
	setIfNotEmpty(query, "since", opts.Since)
	setIfNotEmpty(query, "until", opts.Until)
	setIfNotEmpty(query, "sort", opts.Sort)
	setIfNotEmpty(query, "cursor", opts.Cursor)
	if opts.MinRisk > 0 {
		query.Set("min_risk", fmt.Sprintf("%g", opts.MinRisk))
	}
	if opts.Limit > 0 {
		query.Set("limit", fmt.Sprintf("%d", opts.Limit))
	}
	out := &Page[Finding]{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: APIPrefix + "/findings", query: query, out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// GetFinding appelle `GET /api/v1/findings/{id}` : le finding et ses actions liées.
func (c *Client) GetFinding(ctx context.Context, findingID string) (*Finding, error) {
	if strings.TrimSpace(findingID) == "" {
		return nil, validationError("GetFinding", "finding_id requis")
	}
	out := &Finding{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: APIPrefix + "/findings/" + url.PathEscape(findingID), out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// AckFinding appelle `POST /api/v1/findings/{id}/ack` (capacité `write:findings`).
func (c *Client) AckFinding(ctx context.Context, findingID string, opts ...CallOption) (*StatusResult, error) {
	if strings.TrimSpace(findingID) == "" {
		return nil, validationError("AckFinding", "finding_id requis")
	}
	callOpts := newCallOptions(opts...)
	body := map[string]any{}
	if callOpts.comment != "" {
		body["comment"] = callOpts.comment
	}
	out := &StatusResult{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodPost,
		path:   APIPrefix + "/findings/" + url.PathEscape(findingID) + "/ack",
		body:   body, out: out, opts: callOpts,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// CloseFinding appelle `POST /api/v1/findings/{id}/close` (capacité `write:findings`).
//
// `Resolution` ∈ `true_positive | false_positive | mitigated`.
func (c *Client) CloseFinding(ctx context.Context, findingID string, input CloseFindingInput) (*StatusResult, error) {
	if strings.TrimSpace(findingID) == "" {
		return nil, validationError("CloseFinding", "finding_id requis")
	}
	switch input.Resolution {
	case "true_positive", "false_positive", "mitigated":
	default:
		return nil, validationError("CloseFinding",
			"resolution invalide : attendu true_positive, false_positive ou mitigated")
	}
	out := &StatusResult{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodPost,
		path:   APIPrefix + "/findings/" + url.PathEscape(findingID) + "/close",
		body:   input, out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// SuppressFinding appelle `POST /api/v1/findings/{id}/suppress` : crée une exception temporaire
// sur la règle. À utiliser avec un motif explicite et une durée bornée.
func (c *Client) SuppressFinding(ctx context.Context, findingID string, input SuppressFindingInput) (*StatusResult, error) {
	if strings.TrimSpace(findingID) == "" {
		return nil, validationError("SuppressFinding", "finding_id requis")
	}
	if input.DurationSeconds <= 0 {
		input.DurationSeconds = 86400
	}
	out := &StatusResult{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodPost,
		path:   APIPrefix + "/findings/" + url.PathEscape(findingID) + "/suppress",
		body:   input, out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// GetReport appelle `GET /api/v1/findings/{id}/report?format=…` et retourne l'artefact brut.
//
// `format` ∈ `md | html | json | sarif` (SARIF 2.1.0 pour GitHub Code Scanning).
func (c *Client) GetReport(ctx context.Context, findingID, format string) ([]byte, error) {
	if strings.TrimSpace(findingID) == "" {
		return nil, validationError("GetReport", "finding_id requis")
	}
	if format == "" {
		format = "md"
	}
	switch format {
	case "md", "html", "json", "sarif":
	default:
		return nil, validationError("GetReport", "format invalide : attendu md, html, json ou sarif")
	}
	var raw []byte
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet,
		path:   APIPrefix + "/findings/" + url.PathEscape(findingID) + "/report",
		query:  url.Values{"format": []string{format}},
		rawOut: &raw,
	}); err != nil {
		return nil, err
	}
	return raw, nil
}

/* ====================================================================================== */
/* §4.5 Règles, politiques, playbooks                                                      */
/* ====================================================================================== */

// ListRules appelle `GET /api/v1/rules` (capacité `read:rules`).
func (c *Client) ListRules(ctx context.Context) (*Page[Rule], error) {
	out := &Page[Rule]{}
	if err := c.call(ctx, requestSpec{method: http.MethodGet, path: APIPrefix + "/rules", out: out}); err != nil {
		return nil, err
	}
	return out, nil
}

// GetRule appelle `GET /api/v1/rules/{rule_id}` : règle complète et YAML source.
func (c *Client) GetRule(ctx context.Context, ruleID string) (*Rule, error) {
	if strings.TrimSpace(ruleID) == "" {
		return nil, validationError("GetRule", "rule_id requis")
	}
	out := &Rule{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: APIPrefix + "/rules/" + url.PathEscape(ruleID), out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateRule appelle `POST /api/v1/rules/validate` (capacité `admin:rules`).
//
// `source` est le YAML (ou JSON) de la règle, transmis tel quel avec `Content-Type: application/yaml`.
func (c *Client) ValidateRule(ctx context.Context, source []byte) (*RuleValidation, error) {
	if len(bytes.TrimSpace(source)) == 0 {
		return nil, validationError("ValidateRule", "source vide : fournissez le YAML ou le JSON de la règle")
	}
	out := &RuleValidation{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodPost, path: APIPrefix + "/rules/validate",
		rawBody: source, contentType: "application/yaml", out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// ReloadRules appelle `POST /api/v1/rules/reload` (capacité `admin:rules`).
func (c *Client) ReloadRules(ctx context.Context) (*ReloadResult, error) {
	out := &ReloadResult{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodPost, path: APIPrefix + "/rules/reload", body: map[string]any{}, out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// ListPolicies appelle `GET /api/v1/policies` (capacité `read:policies`).
func (c *Client) ListPolicies(ctx context.Context) (*Page[Policy], error) {
	out := &Page[Policy]{}
	if err := c.call(ctx, requestSpec{method: http.MethodGet, path: APIPrefix + "/policies", out: out}); err != nil {
		return nil, err
	}
	return out, nil
}

// ReloadPolicies appelle `POST /api/v1/policies/reload` (capacité `admin:policies`).
func (c *Client) ReloadPolicies(ctx context.Context) (*ReloadResult, error) {
	out := &ReloadResult{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodPost, path: APIPrefix + "/policies/reload", body: map[string]any{}, out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// ListPlaybooks appelle `GET /api/v1/playbooks` (capacité `read:rules`).
func (c *Client) ListPlaybooks(ctx context.Context) (*Page[Playbook], error) {
	out := &Page[Playbook]{}
	if err := c.call(ctx, requestSpec{method: http.MethodGet, path: APIPrefix + "/playbooks", out: out}); err != nil {
		return nil, err
	}
	return out, nil
}

/* ====================================================================================== */
/* §4.6 Actions (SOAR)                                                                     */
/* ====================================================================================== */

// PlanAction appelle `POST /api/v1/actions/plan` (capacité `execute:actions`) — **aucun effet de
// bord**. `dry_run` vaut `true` par défaut : la planification reste une simulation tant que
// `DryRun` (ou `WithDryRun(false)`) ne lève pas explicitement ce garde-fou.
func (c *Client) PlanAction(ctx context.Context, input PlanActionInput, opts ...CallOption) (*Action, error) {
	if strings.TrimSpace(input.FindingID) == "" {
		return nil, validationError("PlanAction", "finding_id requis")
	}
	if strings.TrimSpace(input.Playbook) == "" {
		return nil, validationError("PlanAction", "playbook requis")
	}
	callOpts := newCallOptions(opts...)
	dryRun := true
	if input.DryRun != nil {
		dryRun = *input.DryRun
	} else if callOpts.dryRun != nil {
		dryRun = *callOpts.dryRun
	}
	body := PlanActionInput{
		FindingID: input.FindingID,
		Playbook:  input.Playbook,
		Params:    input.Params,
		DryRun:    &dryRun,
	}
	out := &Action{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodPost, path: APIPrefix + "/actions/plan", body: body, out: out, opts: callOpts,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// ListActionsOptions filtre `GET /api/v1/actions` (contrat §4.6).
type ListActionsOptions struct {
	Status    string
	Playbook  string
	FindingID string
	Limit     int
	Cursor    string
}

// ListActions appelle `GET /api/v1/actions` (capacité `read:findings`).
func (c *Client) ListActions(ctx context.Context, opts ListActionsOptions) (*Page[Action], error) {
	query := url.Values{}
	setIfNotEmpty(query, "status", opts.Status)
	setIfNotEmpty(query, "playbook", opts.Playbook)
	setIfNotEmpty(query, "finding_id", opts.FindingID)
	setIfNotEmpty(query, "cursor", opts.Cursor)
	if opts.Limit > 0 {
		query.Set("limit", fmt.Sprintf("%d", opts.Limit))
	}
	out := &Page[Action]{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: APIPrefix + "/actions", query: query, out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// GetAction appelle `GET /api/v1/actions/{id}` (capacité `read:findings`).
func (c *Client) GetAction(ctx context.Context, actionID string) (*Action, error) {
	if strings.TrimSpace(actionID) == "" {
		return nil, validationError("GetAction", "action_id requis")
	}
	out := &Action{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: APIPrefix + "/actions/" + url.PathEscape(actionID), out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// ApproveAction appelle `POST /api/v1/actions/{id}/approve` (capacité `approve:actions`).
// Utilisez `WithComment` pour joindre un commentaire d'approbation.
func (c *Client) ApproveAction(ctx context.Context, actionID string, opts ...CallOption) (*Action, error) {
	if strings.TrimSpace(actionID) == "" {
		return nil, validationError("ApproveAction", "action_id requis")
	}
	callOpts := newCallOptions(opts...)
	body := map[string]any{}
	if callOpts.comment != "" {
		body["comment"] = callOpts.comment
	}
	out := &Action{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodPost,
		path:   APIPrefix + "/actions/" + url.PathEscape(actionID) + "/approve",
		body:   body, out: out, opts: callOpts,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// RejectAction appelle `POST /api/v1/actions/{id}/reject` (capacité `approve:actions`).
// Le rejet est **terminal**. Utilisez `WithReason` pour joindre un motif.
func (c *Client) RejectAction(ctx context.Context, actionID string, opts ...CallOption) (*Action, error) {
	if strings.TrimSpace(actionID) == "" {
		return nil, validationError("RejectAction", "action_id requis")
	}
	callOpts := newCallOptions(opts...)
	body := map[string]any{}
	if callOpts.reason != "" {
		body["reason"] = callOpts.reason
	}
	out := &Action{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodPost,
		path:   APIPrefix + "/actions/" + url.PathEscape(actionID) + "/reject",
		body:   body, out: out, opts: callOpts,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// ExecuteAction appelle `POST /api/v1/actions/{id}/execute` (capacité `execute:actions`).
//
// Le serveur refuse (`409`) une action encore `pending_approval`. L'appel n'est **pas** réessayé
// par défaut (POST) : fournissez `WithIdempotencyKey(...)` pour le rendre sûr à rejouer — le
// serveur déduplique alors l'opération.
func (c *Client) ExecuteAction(ctx context.Context, actionID string, opts ...CallOption) (*Action, error) {
	if strings.TrimSpace(actionID) == "" {
		return nil, validationError("ExecuteAction", "action_id requis")
	}
	callOpts := newCallOptions(opts...)
	body := map[string]any{}
	if callOpts.dryRun != nil {
		body["dry_run"] = *callOpts.dryRun
	}
	if callOpts.idempotencyKey != "" {
		body["idempotency_key"] = callOpts.idempotencyKey
	}
	out := &Action{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodPost,
		path:   APIPrefix + "/actions/" + url.PathEscape(actionID) + "/execute",
		body:   body, out: out, opts: callOpts,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// RollbackAction appelle `POST /api/v1/actions/{id}/rollback` (capacité `execute:actions`).
//
// Le serveur refuse (`409`) une action déjà `rolled_back`. Utilisez `WithReason` pour le motif et
// `WithIdempotencyKey` pour rendre l'appel réessayable.
func (c *Client) RollbackAction(ctx context.Context, actionID string, opts ...CallOption) (*Action, error) {
	if strings.TrimSpace(actionID) == "" {
		return nil, validationError("RollbackAction", "action_id requis")
	}
	callOpts := newCallOptions(opts...)
	body := map[string]any{}
	if callOpts.reason != "" {
		body["reason"] = callOpts.reason
	}
	if callOpts.idempotencyKey != "" {
		body["idempotency_key"] = callOpts.idempotencyKey
	}
	out := &Action{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodPost,
		path:   APIPrefix + "/actions/" + url.PathEscape(actionID) + "/rollback",
		body:   body, out: out, opts: callOpts,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

/* ====================================================================================== */
/* §4.7 Audit                                                                              */
/* ====================================================================================== */

// ListAuditOptions filtre `GET /api/v1/audit` (contrat §4.7).
type ListAuditOptions struct {
	Since  string
	Until  string
	Action string
	Actor  string
	Limit  int
	Cursor string
}

// ListAudit appelle `GET /api/v1/audit` (capacité `read:audit`).
func (c *Client) ListAudit(ctx context.Context, opts ListAuditOptions) (*Page[AuditRecord], error) {
	query := url.Values{}
	setIfNotEmpty(query, "since", opts.Since)
	setIfNotEmpty(query, "until", opts.Until)
	setIfNotEmpty(query, "action", opts.Action)
	setIfNotEmpty(query, "actor", opts.Actor)
	setIfNotEmpty(query, "cursor", opts.Cursor)
	if opts.Limit > 0 {
		query.Set("limit", fmt.Sprintf("%d", opts.Limit))
	}
	out := &Page[AuditRecord]{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: APIPrefix + "/audit", query: query, out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// VerifyAudit appelle `GET /api/v1/audit/verify` (capacité `read:audit`).
//
// Un `valid: false` n'est **pas** une erreur d'API : c'est un résultat de contrôle d'intégrité à
// traiter comme un incident (voir `BrokenAt`).
func (c *Client) VerifyAudit(ctx context.Context) (*AuditVerification, error) {
	out := &AuditVerification{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: APIPrefix + "/audit/verify", out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// ExportAudit appelle `GET /api/v1/audit/export?format=jsonl|cef` et retourne le flux brut
// destiné à un SIEM/SOAR.
func (c *Client) ExportAudit(ctx context.Context, format, since, until string) ([]byte, error) {
	if format == "" {
		format = "jsonl"
	}
	switch format {
	case "jsonl", "cef":
	default:
		return nil, validationError("ExportAudit", "format invalide : attendu jsonl ou cef")
	}
	query := url.Values{"format": []string{format}}
	setIfNotEmpty(query, "since", since)
	setIfNotEmpty(query, "until", until)
	var raw []byte
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: APIPrefix + "/audit/export", query: query,
		accept: "text/plain", rawOut: &raw,
	}); err != nil {
		return nil, err
	}
	return raw, nil
}

/* ====================================================================================== */
/* §4.8 Stats, collecteurs                                                                 */
/* ====================================================================================== */

// StatsOverview appelle `GET /api/v1/stats/overview` (capacité `read:stats`).
func (c *Client) StatsOverview(ctx context.Context) (*StatsOverview, error) {
	out := &StatsOverview{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodGet, path: APIPrefix + "/stats/overview", out: out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// ListCollectors appelle `GET /api/v1/collectors` (capacité `read:stats`).
func (c *Client) ListCollectors(ctx context.Context) (*Page[CollectorStatus], error) {
	out := &Page[CollectorStatus]{}
	if err := c.call(ctx, requestSpec{method: http.MethodGet, path: APIPrefix + "/collectors", out: out}); err != nil {
		return nil, err
	}
	return out, nil
}

// RunCollector appelle `POST /api/v1/collectors/{name}/run` (capacité `execute:actions`).
//
// Le run porte **uniquement** sur les cibles déclarées du tenant : le SDK n'expose aucune
// primitive de balayage arbitraire (contrat §10, « zéro capacité offensive »).
func (c *Client) RunCollector(ctx context.Context, name string) (map[string]any, error) {
	if strings.TrimSpace(name) == "" {
		return nil, validationError("RunCollector", "nom de collecteur requis")
	}
	out := map[string]any{}
	if err := c.call(ctx, requestSpec{
		method: http.MethodPost,
		path:   APIPrefix + "/collectors/" + url.PathEscape(name) + "/run",
		body:   map[string]any{}, out: &out,
	}); err != nil {
		return nil, err
	}
	return out, nil
}
