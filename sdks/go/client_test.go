package thotsecure

// Tests du SDK Go — **exécutables hors ligne**.
//
// Aucun accès réseau : l'API est simulée par `httptest.Server` (bibliothèque standard) et le flux
// WebSocket par un `net.Listener` local qui reproduit un handshake RFC 6455 et des trames
// fabriquées à la main (longueurs 126/127, masque, fragmentation).
//
// Couverture : construction d'URL, en-tête `X-API-Key`, sérialisation des corps et des filtres,
// mapping des erreurs du contrat §4.6, reprise sur 503 (avec et sans clé d'idempotence), découpage
// des lots d'ingestion, sonde `/readyz` non bloquante, handshake WebSocket et lecture de trames.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

/* ====================================================================================== */
/* Outils de test                                                                          */
/* ====================================================================================== */

// discardLogger journalise dans le vide : les tests ne doivent pas polluer leur sortie.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// jsonResponse écrit une réponse JSON avec le statut demandé.
//
// Les en-têtes supplémentaires sont fournis par paires (`"Retry-After", "1"`). Cette fonction
// n'appelle volontairement pas `t.Fatalf` : elle est exécutée depuis les goroutines du serveur de
// test (`go vet` interdit `t.Fatal` hors de la goroutine de test).
func jsonResponse(w http.ResponseWriter, status int, body string, headers ...string) {
	w.Header().Set("Content-Type", "application/json")
	for index := 0; index+1 < len(headers); index += 2 {
		w.Header().Set(headers[index], headers[index+1])
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// errorBody construit un corps d'erreur conforme au contrat §4.6.
func errorBody(code, message string) string {
	return fmt.Sprintf(`{"error":{"code":%q,"message":%q,"details":{}}}`, code, message)
}

// newTestClient construit un client pointé sur le serveur de test.
func newTestClient(t *testing.T, serverURL string, opts ...Option) *Client {
	t.Helper()
	base := []Option{
		WithBaseURL(serverURL),
		WithAPIKey("ao_test_key_0001"),
		WithTenantID("acme"),
		WithLogger(discardLogger()),
		WithBackoff(time.Millisecond, 5*time.Millisecond),
	}
	client, err := NewClient(append(base, opts...)...)
	if err != nil {
		t.Fatalf("NewClient : %v", err)
	}
	return client
}

// serverTextFrame fabrique une trame serveur **non masquée** (RFC 6455 : un serveur ne masque pas).
// `fin=false` produit volontairement une trame fragmentée.
func serverTextFrame(payload []byte, fin bool, masked bool) []byte {
	frame := make([]byte, 0, len(payload)+14)
	first := byte(opcodeText)
	if fin {
		first |= 0x80
	}
	frame = append(frame, first)

	maskBit := byte(0x00)
	if masked {
		maskBit = 0x80
	}
	switch {
	case len(payload) < 126:
		frame = append(frame, maskBit|byte(len(payload)))
	case len(payload) <= 0xFFFF:
		frame = append(frame, maskBit|126, byte(len(payload)>>8), byte(len(payload)))
	default:
		frame = append(frame, maskBit|127)
		var extended [8]byte
		binary.BigEndian.PutUint64(extended[:], uint64(len(payload)))
		frame = append(frame, extended[:]...)
	}

	if !masked {
		return append(frame, payload...)
	}
	key := [4]byte{0x37, 0xFA, 0x21, 0x3D}
	frame = append(frame, key[:]...)
	for index := 0; index < len(payload); index++ {
		frame = append(frame, payload[index]^key[index%4])
	}
	return frame
}

// startRawWSServer démarre un serveur WebSocket minimal sur une socket locale.
//
// `respond` reçoit la clé `Sec-WebSocket-Key` et retourne la réponse de handshake brute ;
// `frames` (optionnel) écrit ensuite les trames à destination du client.
func startRawWSServer(
	t *testing.T,
	respond func(key string) []byte,
	frames func(conn net.Conn),
) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("écoute locale impossible : %v", err)
	}
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		reader := bufio.NewReader(conn)
		key := ""
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			trimmed := strings.TrimRight(line, "\r\n")
			if trimmed == "" {
				break
			}
			if strings.HasPrefix(strings.ToLower(trimmed), "sec-websocket-key:") {
				key = strings.TrimSpace(trimmed[len("sec-websocket-key:"):])
			}
		}
		if _, err := conn.Write(respond(key)); err != nil {
			return
		}
		if frames != nil {
			frames(conn)
		}
		// Laisse au client le temps de consommer les trames avant la fermeture de la socket.
		time.Sleep(100 * time.Millisecond)
	}()

	url := "ws://" + listener.Addr().String() + WSPath
	return url, func() {
		_ = listener.Close()
		<-done
	}
}

// handshakeResponse fabrique la réponse 101 conforme (ou volontairement non conforme).
func handshakeResponse(key string, accept string, includeUpgrade bool) []byte {
	if accept == "" {
		accept = AcceptKey(key)
	}
	lines := []string{"HTTP/1.1 101 Switching Protocols"}
	if includeUpgrade {
		lines = append(lines, "Upgrade: websocket", "Connection: Upgrade")
	}
	lines = append(lines, "Sec-WebSocket-Accept: "+accept)
	return []byte(strings.Join(lines, "\r\n") + "\r\n\r\n")
}

/* ====================================================================================== */
/* URL, en-têtes, sérialisation                                                            */
/* ====================================================================================== */

func TestWhoamiURLAndHeaders(t *testing.T) {
	var gotPath, gotMethod, gotKey, gotAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotKey = r.Header.Get("X-API-Key")
		gotAccept = r.Header.Get("Accept")
		jsonResponse(w, http.StatusOK,
			`{"tenant_id":"acme","role":"responder","capabilities":["read:events"],`+
				`"autonomy_mode":"supervised","dry_run":true}`)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	who, err := client.Whoami(context.Background())
	if err != nil {
		t.Fatalf("Whoami : %v", err)
	}

	if gotPath != "/api/v1/auth/whoami" {
		t.Errorf("chemin = %q, attendu /api/v1/auth/whoami", gotPath)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("méthode = %q, attendue GET", gotMethod)
	}
	if gotKey != "ao_test_key_0001" {
		t.Errorf("en-tête X-API-Key = %q", gotKey)
	}
	if gotAccept != "application/json" {
		t.Errorf("en-tête Accept = %q", gotAccept)
	}
	if who.TenantID != "acme" || who.Role != "responder" || !who.DryRun {
		t.Errorf("décodage WhoAmI incorrect : %+v", who)
	}
}

func TestHealthzIsPublic(t *testing.T) {
	var gotKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-API-Key")
		jsonResponse(w, http.StatusOK, `{"status":"ok","version":"0.1.0","uptime_s":12}`)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	health, err := client.Healthz(context.Background())
	if err != nil {
		t.Fatalf("Healthz : %v", err)
	}
	if gotKey != "" {
		t.Errorf("une route publique ne doit pas porter de clé API (reçu %q)", gotKey)
	}
	if health.Status != "ok" || health.UptimeS != 12 {
		t.Errorf("décodage Healthz incorrect : %+v", health)
	}
}

func TestIngestEventSerialization(t *testing.T) {
	var body map[string]any
	var contentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("corps illisible : %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		jsonResponse(w, http.StatusAccepted,
			`{"accepted":1,"rejected":0,"event_ids":["e1"],"findings":[]}`)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	result, err := client.IngestEvent(context.Background(), EventInput{
		Kind:   "http.request",
		Labels: map[string]any{"src_ip": "203.0.113.9"},
	})
	if err != nil {
		t.Fatalf("IngestEvent : %v", err)
	}

	if contentType != "application/json" {
		t.Errorf("Content-Type = %q", contentType)
	}
	if body["tenant_id"] != "acme" {
		t.Errorf("tenant_id non renseigné depuis le client : %v", body["tenant_id"])
	}
	if body["kind"] != "http.request" {
		t.Errorf("kind mal sérialisé : %v", body["kind"])
	}
	labels, ok := body["labels"].(map[string]any)
	if !ok || labels["src_ip"] != "203.0.113.9" {
		t.Errorf("labels mal sérialisés : %v", body["labels"])
	}
	if result.Accepted != 1 || len(result.EventIDs) != 1 || result.EventIDs[0] != "e1" {
		t.Errorf("décodage IngestResult incorrect : %+v", result)
	}
}

func TestListFindingsQueryAndDecoding(t *testing.T) {
	var query map[string][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query()
		jsonResponse(w, http.StatusOK, `{"items":[{"finding_id":"f1","risk_score":78.5,`+
			`"severity":"high","status":"open","tags":["web"],"mitre":["T1190"],"count":7}],`+
			`"next_cursor":"c1"}`)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	page, err := client.ListFindings(context.Background(), ListFindingsOptions{
		Status:   "open",
		Severity: "high",
		MinRisk:  70,
		Sort:     "risk_score",
		Limit:    25,
	})
	if err != nil {
		t.Fatalf("ListFindings : %v", err)
	}

	if query["status"][0] != "open" || query["severity"][0] != "high" {
		t.Errorf("filtres mal sérialisés : %v", query)
	}
	if query["min_risk"][0] != "70" || query["sort"][0] != "risk_score" || query["limit"][0] != "25" {
		t.Errorf("filtres numériques mal sérialisés : %v", query)
	}
	if _, present := query["cursor"]; present {
		t.Errorf("cursor ne devait pas être envoyé : %v", query)
	}
	if len(page.Items) != 1 || page.Items[0].FindingID != "f1" || page.Items[0].RiskScore != 78.5 {
		t.Errorf("décodage de page incorrect : %+v", page.Items)
	}
	if page.NextCursor == nil || *page.NextCursor != "c1" {
		t.Errorf("curseur de page non décodé : %v", page.NextCursor)
	}
}

func TestListEventsRejectsLimitAboveContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("aucun appel réseau ne devait partir pour un limit invalide")
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	_, err := client.ListEvents(context.Background(), ListEventsOptions{Limit: 501})
	if err == nil {
		t.Fatal("limit 501 devait être refusé (contrat §4.3 : ≤ 500)")
	}
	if apiErr, ok := AsAPIError(err); !ok || !apiErr.IsValidation() {
		t.Errorf("erreur attendue de validation, reçu : %v", err)
	}
}

func TestIngestEventsChunksBatches(t *testing.T) {
	var batches []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Events []EventInput `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("corps illisible : %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		batches = append(batches, len(payload.Events))
		for _, event := range payload.Events {
			if event.TenantID != "acme" {
				t.Errorf("tenant_id manquant dans un lot : %+v", event)
			}
		}
		jsonResponse(w, http.StatusAccepted,
			`{"accepted":2,"rejected":0,"event_ids":["e"],"findings":[]}`)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	callbacks := 0
	result, err := client.IngestEvents(context.Background(),
		[]EventInput{{Kind: "log.line"}, {Kind: "log.line"}, {Kind: "log.line"}},
		WithBatchSize(2),
		WithBatchCallback(func(*IngestResult) error {
			callbacks++
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("IngestEvents : %v", err)
	}

	if len(batches) != 2 || batches[0] != 2 || batches[1] != 1 {
		t.Errorf("découpage en lots incorrect : %v", batches)
	}
	if callbacks != 2 {
		t.Errorf("rappel de lot appelé %d fois, attendu 2", callbacks)
	}
	if result.Accepted != 4 || len(result.EventIDs) != 2 {
		t.Errorf("fusion des réponses incorrecte : %+v", result)
	}
}

/* ====================================================================================== */
/* Mapping des erreurs (§4.6)                                                              */
/* ====================================================================================== */

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		status  int
		code    string
		check   func(*APIError) bool
		message string
	}{
		{http.StatusUnauthorized, CodeUnauthenticated, (*APIError).IsUnauthenticated, "401"},
		{http.StatusForbidden, CodeForbidden, (*APIError).IsForbidden, "403"},
		{http.StatusNotFound, CodeNotFound, (*APIError).IsNotFound, "404"},
		{http.StatusConflict, CodeConflict, (*APIError).IsConflict, "409"},
		{http.StatusUnprocessableEntity, CodeUnprocessable, (*APIError).IsValidation, "422"},
		{http.StatusTooManyRequests, CodeRateLimited, (*APIError).IsRateLimited, "429"},
	}

	for _, testCase := range cases {
		t.Run(testCase.message, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				jsonResponse(w, testCase.status, errorBody(testCase.code, "refus "+testCase.message))
			}))
			defer server.Close()

			client := newTestClient(t, server.URL)
			_, err := client.GetFinding(context.Background(), "f1")
			if err == nil {
				t.Fatalf("un statut %d devait produire une erreur", testCase.status)
			}

			apiErr, ok := AsAPIError(err)
			if !ok {
				t.Fatalf("erreur non typée : %v (%T)", err, err)
			}
			if apiErr.StatusCode != testCase.status {
				t.Errorf("StatusCode = %d, attendu %d", apiErr.StatusCode, testCase.status)
			}
			if apiErr.Code != testCase.code {
				t.Errorf("Code = %q, attendu %q", apiErr.Code, testCase.code)
			}
			if !testCase.check(apiErr) {
				t.Errorf("prédicat %s faux pour %v", testCase.message, err)
			}
			if apiErr.Message != "refus "+testCase.message {
				t.Errorf("Message = %q", apiErr.Message)
			}
			// La clé API ne doit jamais apparaître dans une erreur.
			if strings.Contains(err.Error(), "ao_test_key_0001") {
				t.Errorf("la clé API fuit dans l'erreur : %v", err)
			}
		})
	}
}

func TestErrorMappingWithoutContractBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "<html>502 Bad Gateway</html>")
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	_, err := client.StatsOverview(context.Background())
	if err == nil {
		t.Fatal("502 devait produire une erreur")
	}
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("erreur non typée : %v", err)
	}
	if apiErr.StatusCode != http.StatusBadGateway {
		t.Errorf("StatusCode = %d", apiErr.StatusCode)
	}
	if !strings.Contains(apiErr.Message, "Bad Gateway") {
		t.Errorf("le corps brut devait servir de message : %q", apiErr.Message)
	}
}

func TestRateLimitRetryAfterIsHonoured(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			jsonResponse(w, http.StatusTooManyRequests, errorBody(CodeRateLimited, "trop de requêtes"),
				"Retry-After", "1")
			return
		}
		jsonResponse(w, http.StatusOK, `{"items":[]}`)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	start := time.Now()
	if _, err := client.ListEvents(context.Background(), ListEventsOptions{}); err != nil {
		t.Fatalf("ListEvents : %v", err)
	}
	if attempts != 2 {
		t.Errorf("tentatives = %d, attendu 2", attempts)
	}
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Errorf("Retry-After de 1 s non respecté (attente observée : %v)", elapsed)
	}
}

/* ====================================================================================== */
/* Reprise                                                                                 */
/* ====================================================================================== */

func TestRetryOn503ThenSuccess(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			jsonResponse(w, http.StatusServiceUnavailable, errorBody(CodeInternalError, "indisponible"))
			return
		}
		jsonResponse(w, http.StatusOK, `{"items":[{"event_id":"e1"}],"next_cursor":null}`)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	page, err := client.ListEvents(context.Background(), ListEventsOptions{})
	if err != nil {
		t.Fatalf("ListEvents : %v", err)
	}
	if attempts != 2 {
		t.Errorf("tentatives = %d, attendu 2 (reprise sur 503)", attempts)
	}
	if len(page.Items) != 1 || page.Items[0].EventID != "e1" {
		t.Errorf("décodage après reprise incorrect : %+v", page.Items)
	}
}

func TestNoRetryOnPostWithoutIdempotencyKey(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		jsonResponse(w, http.StatusServiceUnavailable, errorBody(CodeInternalError, "indisponible"))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	_, err := client.ExecuteAction(context.Background(), "a1")
	if err == nil {
		t.Fatal("ExecuteAction devait échouer")
	}
	if attempts != 1 {
		t.Errorf("tentatives = %d, attendu 1 : un POST sans clé d'idempotence ne doit jamais être rejoué", attempts)
	}
}

func TestRetryOnPostWithIdempotencyKey(t *testing.T) {
	attempts := 0
	var gotKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		gotKey = r.Header.Get("Idempotency-Key")
		if attempts == 1 {
			jsonResponse(w, http.StatusServiceUnavailable, errorBody(CodeInternalError, "indisponible"))
			return
		}
		jsonResponse(w, http.StatusOK, `{"action_id":"a1","status":"succeeded","tenant_id":"acme"}`)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	action, err := client.ExecuteAction(context.Background(), "a1",
		WithIdempotencyKey("acme:block-source-ip:203.0.113.9:1739527200"))
	if err != nil {
		t.Fatalf("ExecuteAction : %v", err)
	}
	if attempts != 2 {
		t.Errorf("tentatives = %d, attendu 2 avec clé d'idempotence", attempts)
	}
	if gotKey != "acme:block-source-ip:203.0.113.9:1739527200" {
		t.Errorf("en-tête Idempotency-Key = %q", gotKey)
	}
	if action.Status != "succeeded" {
		t.Errorf("décodage Action incorrect : %+v", action)
	}
}

func TestContextCancellationStopsCall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		jsonResponse(w, http.StatusOK, `{"items":[]}`)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	_, err := client.ListEvents(ctx, ListEventsOptions{})
	if err == nil {
		t.Fatal("un contexte expiré devait interrompre l'appel")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("erreur attendue : context.DeadlineExceeded, reçu %v", err)
	}
}

/* ====================================================================================== */
/* Sondes et cas particuliers                                                              */
/* ====================================================================================== */

func TestReadyzUnavailableDoesNotError(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		jsonResponse(w, http.StatusServiceUnavailable, errorBody(CodeInternalError, "bus indisponible"))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	ready, err := client.Readyz(context.Background())
	if err != nil {
		t.Fatalf("Readyz ne doit pas lever sur 503 : %v", err)
	}
	if ready.HTTPStatus != http.StatusServiceUnavailable || ready.Status != "unavailable" {
		t.Errorf("état /readyz incorrect : %+v", ready)
	}
	if !strings.Contains(ready.Error, "bus indisponible") {
		t.Errorf("message d'indisponibilité manquant : %+v", ready)
	}
	if attempts != 1 {
		t.Errorf("tentatives = %d : une sonde ne doit pas être réessayée", attempts)
	}
}

func TestRevokeKeyAcceptsNoContent(t *testing.T) {
	var gotMethod, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	if err := client.RevokeKey(context.Background(), "k1"); err != nil {
		t.Fatalf("RevokeKey : %v", err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/api/v1/keys/k1" {
		t.Errorf("appel incorrect : %s %s", gotMethod, gotPath)
	}
}

func TestClientNeverLeaksAPIKey(t *testing.T) {
	client := newTestClient(t, "http://127.0.0.1:8080")
	if !client.APIKeyConfigured() {
		t.Error("APIKeyConfigured devrait être vrai")
	}
	if strings.Contains(client.String(), "ao_test_key_0001") {
		t.Errorf("String() expose la clé API : %s", client.String())
	}
	redacted := redactURL("http://127.0.0.1:8080/api/v1/ws/stream?api_key=ao_test_key_0001&tenant_id=acme")
	if strings.Contains(redacted, "ao_test_key_0001") {
		t.Errorf("redactURL n'a pas masqué la clé : %s", redacted)
	}
	if !strings.Contains(redacted, "api_key=***") {
		t.Errorf("masquage inattendu : %s", redacted)
	}
}

func TestNewClientRejectsInvalidBaseURL(t *testing.T) {
	if _, err := NewClient(WithBaseURL("127.0.0.1:8080")); err == nil {
		t.Fatal("une base URL sans schéma devait être refusée")
	}
}

/* ====================================================================================== */
/* WebSocket : handshake et trames                                                         */
/* ====================================================================================== */

func TestAcceptKeyMatchesRFC6455Vector(t *testing.T) {
	// Vecteur de test de la RFC 6455 §1.3.
	if got := AcceptKey("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Errorf("AcceptKey = %q, attendu s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", got)
	}
}

func TestNewStreamURL(t *testing.T) {
	url, err := NewStreamURL("https://thot.example.org", "ao_secret", "acme", "")
	if err != nil {
		t.Fatalf("NewStreamURL : %v", err)
	}
	if !strings.HasPrefix(url, "wss://thot.example.org"+WSPath) {
		t.Errorf("URL inattendue : %s", url)
	}
	if !strings.Contains(url, "api_key=ao_secret") || !strings.Contains(url, "tenant_id=acme") {
		t.Errorf("paramètres manquants : %s", url)
	}

	prefixed, err := NewStreamURL("http://127.0.0.1:8080/aegis", "", "acme", "")
	if err != nil {
		t.Fatalf("NewStreamURL : %v", err)
	}
	if !strings.HasPrefix(prefixed, "ws://127.0.0.1:8080/aegis"+WSPath) {
		t.Errorf("préfixe de chemin non conservé : %s", prefixed)
	}

	if _, err := NewStreamURL("ftp://exemple", "", "", ""); err == nil {
		t.Error("un schéma non supporté devait être refusé")
	}
}

func TestDialWSReadsTextFrames(t *testing.T) {
	cases := []struct {
		name     string
		payload  string
		masked   bool
		expected string
	}{
		{"courte (longueur < 126)", `{"type":"heartbeat","data":{}}`, false, "heartbeat"},
		{"longueur étendue 126", `{"type":"finding","data":{"pad":"` + strings.Repeat("x", 200) + `"}}`, false, "finding"},
		{"longueur étendue 127", `{"type":"event","data":{"pad":"` + strings.Repeat("y", 70000) + `"}}`, false, "event"},
		{"trame masquée par le serveur", `{"type":"audit","data":{}}`, true, "audit"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			url, stop := startRawWSServer(t,
				func(key string) []byte { return handshakeResponse(key, "", true) },
				func(conn net.Conn) {
					_, _ = conn.Write(serverTextFrame([]byte(testCase.payload), true, testCase.masked))
				},
			)
			defer stop()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, err := DialWS(ctx, url, WithWSLogger(discardLogger()))
			if err != nil {
				t.Fatalf("DialWS : %v", err)
			}
			defer func() { _ = conn.Close() }()

			frame, err := conn.ReadFrame(ctx)
			if err != nil {
				t.Fatalf("ReadFrame : %v", err)
			}
			if frame.Type != testCase.expected {
				t.Errorf("type de trame = %q, attendu %q", frame.Type, testCase.expected)
			}
			if frame.Raw["type"] != testCase.expected {
				t.Errorf("objet brut incorrect : %+v", frame.Raw)
			}
		})
	}
}

func TestDialWSRejectsInvalidAcceptHeader(t *testing.T) {
	url, stop := startRawWSServer(t,
		func(key string) []byte {
			// Réponse 101 avec un Sec-WebSocket-Accept volontairement faux (proxy mal configuré).
			return handshakeResponse(key, "c2VydmV1ci1ub24tY29uZm9ybWU=", true)
		},
		nil,
	)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := DialWS(ctx, url, WithWSLogger(discardLogger()))
	if err == nil {
		_ = conn.Close()
		t.Fatal("un Sec-WebSocket-Accept invalide devait être refusé")
	}
	if !strings.Contains(err.Error(), "Sec-WebSocket-Accept") {
		t.Errorf("message d'erreur inattendu : %v", err)
	}
}

func TestDialWSReportsHandshakeRefusal(t *testing.T) {
	url, stop := startRawWSServer(t,
		func(string) []byte {
			return []byte("HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n" +
				errorBody(CodeUnauthenticated, "clé inconnue"))
		},
		nil,
	)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := DialWS(ctx, url, WithWSLogger(discardLogger()))
	if err == nil {
		_ = conn.Close()
		t.Fatal("un handshake 401 devait être refusé")
	}
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("erreur non typée : %v (%T)", err, err)
	}
	if !apiErr.IsUnauthenticated() {
		t.Errorf("erreur attendue : unauthenticated, reçu %v", err)
	}
}

func TestReadTextMessageRejectsFragmentedFrame(t *testing.T) {
	url, stop := startRawWSServer(t,
		func(key string) []byte { return handshakeResponse(key, "", true) },
		func(conn net.Conn) {
			// FIN=0 : la trame est fragmentée, ce que ce client minimal refuse explicitement.
			_, _ = conn.Write(serverTextFrame([]byte(`{"type":"event"`), false, false))
		},
	)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := DialWS(ctx, url, WithWSLogger(discardLogger()))
	if err != nil {
		t.Fatalf("DialWS : %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ReadTextMessage(ctx); !errors.Is(err, ErrFragmentedFrame) {
		t.Errorf("erreur attendue ErrFragmentedFrame, reçu %v", err)
	}
}

func TestReadTextMessageRejectsOversizedFrame(t *testing.T) {
	url, stop := startRawWSServer(t,
		func(key string) []byte { return handshakeResponse(key, "", true) },
		func(conn net.Conn) {
			// En-tête annonçant 16 Mio + 1 octet : refusé avant toute lecture de charge utile.
			header := []byte{0x81, 127, 0, 0, 0, 0, 1, 0, 0, 1}
			_, _ = conn.Write(header)
		},
	)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := DialWS(ctx, url, WithWSLogger(discardLogger()))
	if err != nil {
		t.Fatalf("DialWS : %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ReadTextMessage(ctx); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("erreur attendue ErrFrameTooLarge, reçu %v", err)
	}
}

func TestReadTextMessageHandlesServerClose(t *testing.T) {
	url, stop := startRawWSServer(t,
		func(key string) []byte { return handshakeResponse(key, "", true) },
		func(conn net.Conn) {
			payload := []byte{0x03, 0xE8} // 1000 = normal closure
			frame := []byte{0x88, byte(len(payload))}
			frame = append(frame, payload...)
			_, _ = conn.Write(frame)
		},
	)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := DialWS(ctx, url, WithWSLogger(discardLogger()))
	if err != nil {
		t.Fatalf("DialWS : %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ReadTextMessage(ctx); !errors.Is(err, ErrWSClosed) {
		t.Errorf("erreur attendue ErrWSClosed, reçu %v", err)
	}
}

func TestEncodeClientFrameMasksAndEncodesLengths(t *testing.T) {
	short, err := encodeClientFrame(opcodeText, []byte("bonjour"))
	if err != nil {
		t.Fatalf("encodeClientFrame : %v", err)
	}
	if short[0] != 0x81 {
		t.Errorf("premier octet = 0x%X, attendu 0x81 (FIN + texte)", short[0])
	}
	if short[1]&0x80 == 0 {
		t.Error("les trames client doivent être masquées (bit MASK à 1)")
	}
	if short[1]&0x7F != 7 {
		t.Errorf("longueur annoncée = %d, attendue 7", short[1]&0x7F)
	}
	if len(short) != 2+4+7 {
		t.Errorf("taille de trame = %d, attendue 13", len(short))
	}

	long, err := encodeClientFrame(opcodeText, bytes.Repeat([]byte("a"), 300))
	if err != nil {
		t.Fatalf("encodeClientFrame : %v", err)
	}
	if long[1]&0x7F != 126 {
		t.Errorf("marqueur de longueur = %d, attendu 126", long[1]&0x7F)
	}
	if int(binary.BigEndian.Uint16(long[2:4])) != 300 {
		t.Errorf("longueur étendue mal encodée : %d", binary.BigEndian.Uint16(long[2:4]))
	}
}

func TestDecodeFrameTolerantToNonJSON(t *testing.T) {
	frame, err := DecodeFrame([]byte("pas du json"))
	if err != nil {
		t.Fatalf("DecodeFrame : %v", err)
	}
	if frame.Type != FrameTypeRaw {
		t.Errorf("type = %q, attendu raw", frame.Type)
	}

	valid, err := DecodeFrame([]byte(`{"type":"finding","data":{"finding_id":"f1"}}`))
	if err != nil {
		t.Fatalf("DecodeFrame : %v", err)
	}
	var finding Finding
	if err := valid.UnmarshalData(&finding); err != nil {
		t.Fatalf("UnmarshalData : %v", err)
	}
	if finding.FindingID != "f1" {
		t.Errorf("décodage de la charge utile incorrect : %+v", finding)
	}
}
