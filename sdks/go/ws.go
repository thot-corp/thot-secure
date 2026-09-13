package thotsecure

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

/*
Client WebSocket **minimal mais correct** du flux temps réel (contrat §4.8).

Objectifs et limites, explicitement assumés :

  - le handshake HTTP/1.1 est écrit à la main (en-têtes `Upgrade`, `Connection`,
    `Sec-WebSocket-Key` en base64, `Sec-WebSocket-Version: 13`) et `Sec-WebSocket-Accept` est
    **vérifié** (SHA-1 de la clé concaténée au GUID RFC 6455) : un serveur non conforme ou un
    proxy mal configuré est détecté immédiatement ;
  - les trames texte sont lues avec gestion du **masque** et des longueurs étendues 126/127,
    plafonnées par `WithWSMaxFrameBytes` (16 Mio par défaut) ;
  - la **fragmentation n'est pas assemblée** : une trame `FIN=0`, une continuation ou une
    réassemblage nécessaire produisent l'erreur explicite `ErrFragmentedFrame` plutôt qu'un
    message tronqué livré silencieusement (corruption invisible = pire qu'une erreur) ;
  - `ping` reçu ⇒ `pong` renvoyé automatiquement ; `pong` reçu ⇒ ignoré ; `close` reçu ⇒
    réponse `close` puis erreur `ErrWSClosed` ;
  - le client **masque** toutes ses trames sortantes, comme l'exige la RFC 6455 pour un client ;
  - ce n'est **pas** un client complet (pas de `permessage-deflate`, pas de fragmentation, pas de
    reconnexion automatique) : pour un flux long en production, enveloppez `ReadTextMessage` dans
    votre propre boucle de reconnexion, ou utilisez le SDK Python qui embarque une reconnexion
    avec backoff.
*/

/* ====================================================================================== */
/* Constantes                                                                              */
/* ====================================================================================== */

const (
	// WSPath est le chemin du flux temps réel (contrat §4.8).
	WSPath = "/api/v1/ws/stream"
	// WSGUID est la constante magique du handshake RFC 6455.
	WSGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	// WSMaxFrameBytes est la taille maximale acceptée pour une trame (16 Mio).
	WSMaxFrameBytes = 16 << 20
	// DefaultWSHandshakeTimeout est le délai maximal du handshake.
	DefaultWSHandshakeTimeout = 10 * time.Second
)

// Types de trame documentés par le contrat §4.8.
const (
	FrameTypeEvent     = "event"
	FrameTypeFinding   = "finding"
	FrameTypeAction    = "action"
	FrameTypeAudit     = "audit"
	FrameTypeHeartbeat = "heartbeat"
	// FrameTypeHello est la trame d'accusé de mise en relation émise à l'ouverture.
	FrameTypeHello = "hello"
	// FrameTypeRaw est utilisée lorsqu'un message reçu n'est pas du JSON conforme au contrat.
	FrameTypeRaw = "raw"
	// FrameTypeUnknown est utilisée lorsqu'un message JSON n'a pas de champ `type` exploitable.
	FrameTypeUnknown = "unknown"
)

// FrameTypes liste les types de trame applicatifs du contrat.
var FrameTypes = []string{
	FrameTypeEvent, FrameTypeFinding, FrameTypeAction, FrameTypeAudit, FrameTypeHeartbeat,
}

// Opcodes RFC 6455 utilisés.
const (
	opcodeContinuation byte = 0x0
	opcodeText         byte = 0x1
	opcodeBinary       byte = 0x2
	opcodeClose        byte = 0x8
	opcodePing         byte = 0x9
	opcodePong         byte = 0xA
)

// Erreurs du client WebSocket.
var (
	// ErrFragmentedFrame : la fragmentation n'est pas prise en charge par ce client minimal.
	ErrFragmentedFrame = errors.New(
		"thotsecure: trame fragmentée : la fragmentation n'est pas assemblée par ce client WebSocket " +
			"minimal (assemblez le message côté serveur, ou utilisez un client complet)")
	// ErrUnexpectedOpcode : opcode non géré pour ce flux (binaire, réservé).
	ErrUnexpectedOpcode = errors.New("thotsecure: opcode de trame inattendu")
	// ErrFrameTooLarge : trame au-delà de la limite configurée.
	ErrFrameTooLarge = errors.New("thotsecure: trame trop volumineuse")
	// ErrWSClosed : le flux a été fermé (par le serveur ou par un appel à Close).
	ErrWSClosed = errors.New("thotsecure: flux WebSocket fermé")
)

/* ====================================================================================== */
/* Handshake : fonctions pures (testables hors ligne)                                      */
/* ====================================================================================== */

// AcceptKey calcule `Sec-WebSocket-Accept` = base64(sha1(key + GUID)) — RFC 6455 §4.2.2.
func AcceptKey(secWebSocketKey string) string {
	digest := sha1.Sum([]byte(secWebSocketKey + WSGUID))
	return base64.StdEncoding.EncodeToString(digest[:])
}

// NewStreamURL construit l'URL `ws://` / `wss://` du flux, avec `api_key` et `tenant_id`.
//
// `http://` → `ws://`, `https://` → `wss://`. Un éventuel préfixe de chemin (déploiement derrière
// un reverse-proxy) est conservé.
//
// ⚠️ L'URL retournée **contient la clé API** : journalisez-la via `redactURL`.
func NewStreamURL(baseURL, apiKey, tenantID, path string) (string, error) {
	raw := strings.TrimSpace(baseURL)
	if raw == "" {
		return "", validationError("NewStreamURL", "baseURL requis")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", validationError("NewStreamURL", "URL de base invalide : "+baseURL)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https", "wss":
		parsed.Scheme = "wss"
	case "http", "ws":
		parsed.Scheme = "ws"
	default:
		return "", validationError("NewStreamURL",
			"schéma non supporté « "+parsed.Scheme+" » : attendu http, https, ws ou wss")
	}
	if path == "" {
		path = WSPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + path
	query := parsed.Query()
	if apiKey != "" {
		query.Set("api_key", apiKey)
	}
	if tenantID != "" {
		query.Set("tenant_id", tenantID)
	}
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""
	return parsed.String(), nil
}

/* ====================================================================================== */
/* Trames applicatives                                                                     */
/* ====================================================================================== */

// StreamFrame est une trame applicative décodée : `{"type":…,"data":…}` (contrat §4.8).
type StreamFrame struct {
	// Type ∈ event | finding | action | audit | heartbeat | hello | raw | unknown.
	Type string
	// Data est la charge utile brute de `data` (à décoder avec `UnmarshalData`).
	Data json.RawMessage
	// Raw est l'objet JSON complet reçu.
	Raw map[string]any
	// ReceivedAt est l'horodatage local de réception (UTC).
	ReceivedAt time.Time
}

// UnmarshalData décode `Data` dans la cible fournie (par exemple `*Finding`).
func (f *StreamFrame) UnmarshalData(target any) error {
	if f == nil || len(f.Data) == 0 {
		return errors.New("thotsecure: trame sans charge utile `data`")
	}
	return json.Unmarshal(f.Data, target)
}

// DecodeFrame décode un message texte du flux en `StreamFrame`.
//
// Un message non JSON n'est pas une erreur fatale : il est retourné avec
// `Type: FrameTypeRaw`, ce qui permet de journaliser le contenu brut sans casser le flux.
func DecodeFrame(payload []byte) (*StreamFrame, error) {
	frame := &StreamFrame{ReceivedAt: time.Now().UTC()}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		frame.Type = FrameTypeRaw
		frame.Data = append(json.RawMessage(nil), payload...)
		frame.Raw = map[string]any{}
		return frame, nil
	}
	frame.Raw = decoded
	if value, ok := decoded["type"].(string); ok && value != "" {
		frame.Type = value
	} else {
		frame.Type = FrameTypeUnknown
	}
	if data, ok := decoded["data"]; ok {
		if encoded, err := json.Marshal(data); err == nil {
			frame.Data = encoded
		}
	}
	return frame, nil
}

/* ====================================================================================== */
/* Options de connexion                                                                    */
/* ====================================================================================== */

type wsOptions struct {
	header           http.Header
	tlsConfig        *tls.Config
	insecureTLS      bool
	dialer           *net.Dialer
	handshakeTimeout time.Duration
	maxFrameBytes    int
	logger           *slog.Logger
}

// WSOption configure une connexion WebSocket.
type WSOption func(*wsOptions)

// WithWSHeader ajoute des en-têtes HTTP au handshake (par exemple un `Origin` ou un jeton).
func WithWSHeader(header http.Header) WSOption {
	return func(o *wsOptions) {
		if o.header == nil {
			o.header = http.Header{}
		}
		for name, values := range header {
			for _, value := range values {
				o.header.Add(name, value)
			}
		}
	}
}

// WithWSTLSConfig fixe la configuration TLS du transport `wss://`.
func WithWSTLSConfig(config *tls.Config) WSOption {
	return func(o *wsOptions) {
		if config != nil {
			o.tlsConfig = config
		}
	}
}

// WithWSInsecureTLS désactive la vérification du certificat TLS du flux.
//
// ⚠️ **DANGEREUX** : sans vérification, un tiers en position d'homme du milieu peut lire la clé
// API (transmise en paramètre d'URL) et injecter de fausses trames. À réserver à un laboratoire
// isolé ; la désactivation journalise un avertissement bruyant.
func WithWSInsecureTLS() WSOption {
	return func(o *wsOptions) { o.insecureTLS = true }
}

// WithWSDialer injecte le dialer TCP (proxy, tests, délais).
func WithWSDialer(dialer *net.Dialer) WSOption {
	return func(o *wsOptions) {
		if dialer != nil {
			o.dialer = dialer
		}
	}
}

// WithWSHandshakeTimeout fixe le délai maximal du handshake (défaut 10 s).
func WithWSHandshakeTimeout(timeout time.Duration) WSOption {
	return func(o *wsOptions) {
		if timeout > 0 {
			o.handshakeTimeout = timeout
		}
	}
}

// WithWSMaxFrameBytes plafonne la taille d'une trame acceptée (défaut `WSMaxFrameBytes`).
func WithWSMaxFrameBytes(size int) WSOption {
	return func(o *wsOptions) {
		if size > 0 {
			o.maxFrameBytes = size
		}
	}
}

// WithWSLogger injecte un journal `log/slog`.
func WithWSLogger(logger *slog.Logger) WSOption {
	return func(o *wsOptions) {
		if logger != nil {
			o.logger = logger
		}
	}
}

/* ====================================================================================== */
/* Connexion                                                                               */
/* ====================================================================================== */

// WSConn est une connexion WebSocket établie (handshake validé).
type WSConn struct {
	conn       net.Conn
	reader     *bufio.Reader
	writer     *bufio.Writer
	rawURL     string
	maxFrame   int
	logger     *slog.Logger
	closedOnce bool
}

// DialWS ouvre une connexion WebSocket vers `rawURL` (schéma `ws://` ou `wss://`).
//
// Le handshake est effectué à la main et `Sec-WebSocket-Accept` est vérifié : une réponse autre
// que `101` produit une `*APIError` (401 → `unauthenticated`, 403 → `forbidden`).
func DialWS(ctx context.Context, rawURL string, opts ...WSOption) (*WSConn, error) {
	options := wsOptions{
		handshakeTimeout: DefaultWSHandshakeTimeout,
		maxFrameBytes:    WSMaxFrameBytes,
		logger:           slog.Default(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" {
		return nil, validationError("DialWS", "URL WebSocket invalide")
	}
	var secure bool
	switch strings.ToLower(parsed.Scheme) {
	case "wss", "https":
		secure = true
	case "ws", "http":
		secure = false
	default:
		return nil, validationError("DialWS",
			"schéma non supporté « "+parsed.Scheme+" » : attendu ws ou wss")
	}

	dialHost := parsed.Host
	if parsed.Port() == "" {
		if secure {
			dialHost = net.JoinHostPort(parsed.Hostname(), "443")
		} else {
			dialHost = net.JoinHostPort(parsed.Hostname(), "80")
		}
	}
	dialer := options.dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: options.handshakeTimeout}
	}

	conn, err := dialer.DialContext(ctx, "tcp", dialHost)
	if err != nil {
		return nil, transportError("GET", redactURL(rawURL),
			"connexion WebSocket impossible vers "+dialHost+" : "+err.Error(), err)
	}

	if secure {
		config := options.tlsConfig
		if config == nil {
			config = &tls.Config{}
		} else {
			config = config.Clone()
		}
		if config.ServerName == "" {
			config.ServerName = parsed.Hostname()
		}
		if options.insecureTLS {
			// #nosec G402 — désactivation explicite, jamais par défaut.
			config.InsecureSkipVerify = true
			options.logger.Warn(
				"thotsecure: ATTENTION — la vérification du certificat TLS est DÉSACTIVÉE sur le " +
					"flux WebSocket (WithWSInsecureTLS) : la clé API transmise en paramètre d'URL " +
					"peut être interceptée. À réserver à un laboratoire isolé.")
		}
		tlsConn := tls.Client(conn, config)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, transportError("GET", redactURL(rawURL), "échec TLS : "+err.Error(), err)
		}
		conn = tlsConn
	}

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		_ = conn.Close()
		return nil, transportError("GET", redactURL(rawURL), "génération de la clé WebSocket impossible : "+err.Error(), err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	pathAndQuery := parsed.RequestURI()
	if pathAndQuery == "" {
		pathAndQuery = "/"
	}
	lines := []string{
		"GET " + pathAndQuery + " HTTP/1.1",
		"Host: " + parsed.Host,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Key: " + key,
		"Sec-WebSocket-Version: 13",
		"User-Agent: " + DefaultUserAgent,
	}
	for name, values := range options.header {
		for _, value := range values {
			lines = append(lines, name+": "+value)
		}
	}
	request := strings.Join(lines, "\r\n") + "\r\n\r\n"

	if err := conn.SetWriteDeadline(time.Now().Add(options.handshakeTimeout)); err != nil {
		_ = conn.Close()
		return nil, transportError("GET", redactURL(rawURL), "délai d'écriture indisponible : "+err.Error(), err)
	}
	if _, err := io.WriteString(conn, request); err != nil {
		_ = conn.Close()
		return nil, transportError("GET", redactURL(rawURL), "handshake WebSocket interrompu : "+err.Error(), err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(options.handshakeTimeout)); err != nil {
		_ = conn.Close()
		return nil, transportError("GET", redactURL(rawURL), "délai de lecture indisponible : "+err.Error(), err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := readHTTPLine(reader)
	if err != nil {
		_ = conn.Close()
		return nil, transportError("GET", redactURL(rawURL), "réponse de handshake illisible : "+err.Error(), err)
	}
	status, err := parseStatusLine(statusLine)
	if err != nil {
		_ = conn.Close()
		return nil, &APIError{
			Code:    CodeInternalError,
			Message: "réponse de handshake illisible : " + statusLine,
			Method:  "GET",
			URL:     redactURL(rawURL),
			Cause:   err,
		}
	}
	headers := map[string]string{}
	for {
		line, err := readHTTPLine(reader)
		if err != nil {
			_ = conn.Close()
			return nil, transportError("GET", redactURL(rawURL), "en-têtes de handshake illisibles : "+err.Error(), err)
		}
		if line == "" {
			break
		}
		index := strings.Index(line, ":")
		if index <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:index]))
		value := strings.TrimSpace(line[index+1:])
		headers[name] = value
	}

	if status != http.StatusSwitchingProtocols {
		_ = conn.Close()
		code := codeForStatus(status)
		if status == http.StatusUnauthorized {
			code = CodeUnauthenticated
		}
		if status == http.StatusForbidden {
			code = CodeForbidden
		}
		return nil, &APIError{
			StatusCode: status,
			Code:       code,
			Message:    fmt.Sprintf("handshake WebSocket refusé (HTTP %d)", status),
			Method:     "GET",
			URL:        redactURL(rawURL),
		}
	}
	if !strings.Contains(strings.ToLower(headers["upgrade"]), "websocket") {
		_ = conn.Close()
		return nil, &APIError{
			StatusCode: status,
			Code:       CodeInternalError,
			Message:    "en-tête `Upgrade: websocket` absent du handshake",
			Method:     "GET",
			URL:        redactURL(rawURL),
		}
	}
	if received := strings.TrimSpace(headers["sec-websocket-accept"]); received != AcceptKey(key) {
		_ = conn.Close()
		return nil, &APIError{
			StatusCode: status,
			Code:       CodeInternalError,
			Message: "Sec-WebSocket-Accept invalide : le pair n'est pas un WebSocket conforme " +
				"RFC 6455 (proxy mal configuré ?)",
			Method: "GET",
			URL:    redactURL(rawURL),
		}
	}

	// Les délais du handshake ne doivent pas s'appliquer au flux : on les efface.
	_ = conn.SetDeadline(time.Time{})
	options.logger.Debug("thotsecure: flux WebSocket connecté", "url", redactURL(rawURL))

	return &WSConn{
		conn:     conn,
		reader:   reader,
		writer:   bufio.NewWriter(conn),
		rawURL:   rawURL,
		maxFrame: options.maxFrameBytes,
		logger:   options.logger,
	}, nil
}

/* ====================================================================================== */
/* Lecture et écriture de trames                                                           */
/* ====================================================================================== */

// frameHeader décrit l'en-tête décodé d'une trame RFC 6455.
type frameHeader struct {
	fin    bool
	opcode byte
	masked bool
	length int64
	mask   [4]byte
}

// ReadTextMessage lit le prochain message texte complet.
//
// Les `ping` reçus sont acquittés automatiquement, les `pong` sont ignorés, un `close` provoque
// une réponse `close` puis l'erreur `ErrWSClosed`. La fragmentation produit
// `ErrFragmentedFrame` (erreur explicite, jamais de message tronqué silencieux).
func (c *WSConn) ReadTextMessage(ctx context.Context) (string, error) {
	if c == nil || c.conn == nil {
		return "", ErrWSClosed
	}
	if c.closedOnce {
		return "", ErrWSClosed
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetReadDeadline(deadline)
	} else {
		_ = c.conn.SetReadDeadline(time.Time{})
	}

	for {
		header, err := c.readFrameHeader()
		if err != nil {
			return "", c.wrapReadError(err)
		}

		payload := make([]byte, header.length)
		if header.length > 0 {
			if _, err := io.ReadFull(c.reader, payload); err != nil {
				return "", c.wrapReadError(err)
			}
		}
		if header.masked {
			// Un serveur ne devrait pas masquer ses trames ; on les démystifie tout de même
			// plutôt que de livrer un contenu corrompu.
			for index := range payload {
				payload[index] ^= header.mask[index%4]
			}
		}

		switch header.opcode {
		case opcodePing:
			if err := c.WritePong(ctx, payload); err != nil {
				return "", err
			}
			continue
		case opcodePong:
			continue
		case opcodeClose:
			code := 1000
			if len(payload) >= 2 {
				code = int(binary.BigEndian.Uint16(payload[:2]))
			}
			c.closedOnce = true
			_ = c.WriteClose(ctx, 1000, "")
			return "", fmt.Errorf("%w (code %d)", ErrWSClosed, code)
		case opcodeContinuation:
			return "", ErrFragmentedFrame
		case opcodeText:
			if !header.fin {
				return "", ErrFragmentedFrame
			}
			return string(payload), nil
		case opcodeBinary:
			if !header.fin {
				return "", ErrFragmentedFrame
			}
			return "", fmt.Errorf("%w : opcode binaire (0x2) reçu, le flux du contrat §4.8 "+
				"est du texte JSON", ErrUnexpectedOpcode)
		default:
			return "", fmt.Errorf("%w : opcode 0x%X", ErrUnexpectedOpcode, header.opcode)
		}
	}
}

// ReadFrame lit le prochain message et le décode en `StreamFrame`.
func (c *WSConn) ReadFrame(ctx context.Context) (*StreamFrame, error) {
	text, err := c.ReadTextMessage(ctx)
	if err != nil {
		return nil, err
	}
	return DecodeFrame([]byte(text))
}

// readFrameHeader lit l'en-tête d'une trame (longueurs 126/127 et masque gérés).
func (c *WSConn) readFrameHeader() (frameHeader, error) {
	var header frameHeader
	head := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, head); err != nil {
		return header, err
	}
	header.fin = head[0]&0x80 != 0
	if head[0]&0x70 != 0 {
		return header, errors.New("trame invalide : bits RSV non nuls (extensions non négociées)")
	}
	header.opcode = head[0] & 0x0F
	header.masked = head[1]&0x80 != 0
	length := int64(head[1] & 0x7F)
	switch length {
	case 126:
		extended := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, extended); err != nil {
			return header, err
		}
		length = int64(binary.BigEndian.Uint16(extended))
	case 127:
		extended := make([]byte, 8)
		if _, err := io.ReadFull(c.reader, extended); err != nil {
			return header, err
		}
		value := binary.BigEndian.Uint64(extended)
		if value > uint64(c.maxFrame) {
			return header, fmt.Errorf("%w : %d octets annoncés (max %d)", ErrFrameTooLarge, value, c.maxFrame)
		}
		length = int64(value)
	}
	if length > int64(c.maxFrame) {
		return header, fmt.Errorf("%w : %d octets annoncés (max %d)", ErrFrameTooLarge, length, c.maxFrame)
	}
	if header.masked {
		if _, err := io.ReadFull(c.reader, header.mask[:]); err != nil {
			return header, err
		}
	}
	header.length = length
	return header, nil
}

// WriteText envoie un message texte (trame masquée, comme l'exige la RFC 6455 côté client).
func (c *WSConn) WriteText(ctx context.Context, text string) error {
	return c.writeFrame(ctx, opcodeText, []byte(text))
}

// WritePing envoie une trame `ping` (opcode 0x9).
func (c *WSConn) WritePing(ctx context.Context, payload []byte) error {
	return c.writeFrame(ctx, opcodePing, payload)
}

// WritePong envoie une trame `pong` (opcode 0xA).
func (c *WSConn) WritePong(ctx context.Context, payload []byte) error {
	return c.writeFrame(ctx, opcodePong, payload)
}

// WriteClose envoie une trame `close` (opcode 0x8) avec un code RFC 6455.
func (c *WSConn) WriteClose(ctx context.Context, code int, reason string) error {
	if len(reason) > 123 {
		reason = reason[:123]
	}
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload[:2], uint16(code))
	copy(payload[2:], reason)
	return c.writeFrame(ctx, opcodeClose, payload)
}

// writeFrame encode et écrit une trame masquée.
func (c *WSConn) writeFrame(ctx context.Context, opcode byte, payload []byte) error {
	if c == nil || c.conn == nil {
		return ErrWSClosed
	}
	if len(payload) > c.maxFrame {
		return fmt.Errorf("%w : %d octets (max %d)", ErrFrameTooLarge, len(payload), c.maxFrame)
	}
	frame, err := encodeClientFrame(opcode, payload)
	if err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetWriteDeadline(deadline)
	} else {
		_ = c.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	}
	if _, err := c.writer.Write(frame); err != nil {
		return c.wrapReadError(err)
	}
	if err := c.writer.Flush(); err != nil {
		return c.wrapReadError(err)
	}
	return nil
}

// encodeClientFrame construit une trame RFC 6455 masquée (FIN=1), longueurs 126/127 comprises.
func encodeClientFrame(opcode byte, payload []byte) ([]byte, error) {
	length := len(payload)
	frame := make([]byte, 0, length+14)
	frame = append(frame, 0x80|(opcode&0x0F))

	switch {
	case length < 126:
		frame = append(frame, 0x80|byte(length))
	case length <= 0xFFFF:
		frame = append(frame, 0x80|126, byte(length>>8), byte(length))
	default:
		frame = append(frame, 0x80|127)
		var extended [8]byte
		binary.BigEndian.PutUint64(extended[:], uint64(length))
		frame = append(frame, extended[:]...)
	}

	var key [4]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, fmt.Errorf("thotsecure: génération du masque impossible : %w", err)
	}
	frame = append(frame, key[:]...)
	for index := 0; index < length; index++ {
		frame = append(frame, payload[index]^key[index%4])
	}
	return frame, nil
}

// Close ferme proprement la connexion (trame `close` puis fermeture du socket).
func (c *WSConn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	if !c.closedOnce {
		c.closedOnce = true
		_ = c.WriteClose(context.Background(), 1000, "client closed")
	}
	return c.conn.Close()
}

// RemoteAddr retourne l'adresse du pair (utile pour les journaux).
func (c *WSConn) RemoteAddr() string {
	if c == nil || c.conn == nil || c.conn.RemoteAddr() == nil {
		return ""
	}
	return c.conn.RemoteAddr().String()
}

// wrapReadError enrichit une erreur de lecture (annulation, fermeture, erreur réseau).
func (c *WSConn) wrapReadError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		c.closedOnce = true
		return fmt.Errorf("%w : connexion interrompue par le pair", ErrWSClosed)
	}
	if apiErr, ok := AsAPIError(err); ok {
		return apiErr
	}
	url := ""
	if c != nil {
		url = redactURL(c.rawURL)
	}
	return transportError("GET", url, "lecture WebSocket impossible : "+err.Error(), err)
}

/* ====================================================================================== */
/* Aides de parsing HTTP                                                                   */
/* ====================================================================================== */

// readHTTPLine lit une ligne d'en-tête HTTP (sans le CRLF final).
func readHTTPLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// parseStatusLine extrait le code de statut d'une ligne `HTTP/1.1 101 Switching Protocols`.
func parseStatusLine(line string) (int, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, errors.New("ligne de statut incomplète")
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, fmt.Errorf("code de statut illisible (%q) : %w", fields[1], err)
	}
	return code, nil
}
