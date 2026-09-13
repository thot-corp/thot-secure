// Commande thotsecure-healthcheck — sonde de disponibilité et de sûreté pour orchestrateur.
//
// Elle interroge les routes publiques du contrat d'interface v0.1.0
// (docs/architecture/api-contract.md §4.1) :
//
//	GET /healthz  → {"status":"ok","version":"0.1.0","uptime_s":12}   (le processus vit)
//	GET /readyz   → vérifie DB + bus + règles → 200 ou 503            (il peut servir)
//	GET /metrics  → exposition Prometheus (option -metrics)           (il est sain)
//
// Codes de sortie (compatibles Kubernetes `exec`, systemd, Nagios/Icinga) :
//
//	0  prêt      : /healthz et /readyz répondent 200 (et les métriques requises sont saines)
//	1  non prêt  : un contrôle a échoué, un composant est dégradé, ou la chaîne d'audit est
//	               signalée rompue (thotsecure_audit_chain_valid == 0)
//	2  usage     : arguments invalides (URL malformée, délai négatif…)
//
// La commande est **en lecture seule** : uniquement des GET sur les routes publiques, aucune
// authentification, aucun secret manipulé, aucune modification. Bibliothèque standard seulement,
// pour rester utilisable comme sonde dans n'importe quel conteneur minimal.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	probeUserAgent = "thotsecure-healthcheck/0.1.0 (+https://github.com/thotsecure/thot-secure)"
	probeVersion   = "0.1.0"
	defaultBaseURL = "http://127.0.0.1:8080"

	exitReady    = 0
	exitNotReady = 1
	exitUsage    = 2

	// maxBodyBytes borne la lecture : une sonde ne doit jamais être le maillon qui sature la
	// mémoire à cause d'une réponse géante (ou malveillante) de l'instance interrogée.
	maxBodyBytes = 1 << 20

	// probeTotalTimeoutPad : marge ajoutée au délai global pour laisser chaque requête échouer
	// proprement sur son propre délai avant l'expiration du contexte.
	probeTotalTimeoutPad = 2 * time.Second

	probeRequestTimeout = 5 * time.Second
)

// Métriques dont l'absence ou la valeur nulle doit alerter.
const (
	metricUp            = "thotsecure_up"
	metricAuditChain    = "thotsecure_audit_chain_valid"
	defaultRequirements = metricAuditChain + "," + metricUp
)

// checkResult décrit un contrôle unitaire (un composant de /readyz, une métrique…).
type checkResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// probeResult décrit le résultat brut d'un appel de sonde.
type probeResult struct {
	Name       string         `json:"name"`
	URL        string         `json:"url"`
	HTTPStatus int            `json:"http_status"`
	OK         bool           `json:"ok"`
	DurationMS float64        `json:"duration_ms"`
	Body       map[string]any `json:"body,omitempty"`
	Raw        string         `json:"raw,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// healthReport est la structure complète du rapport (mode -json et affichage humain).
type healthReport struct {
	Target         string        `json:"target"`
	Version        string        `json:"version,omitempty"`
	UptimeS        *float64      `json:"uptime_s,omitempty"`
	DryRun         *bool         `json:"dry_run,omitempty"`
	Autonomy       string        `json:"autonomy,omitempty"`
	Healthz        *probeResult  `json:"healthz,omitempty"`
	Readyz         *probeResult  `json:"readyz,omitempty"`
	Degraded       []checkResult `json:"degraded_checks"`
	MetricsChecked bool          `json:"metrics_checked"`
	Metrics        []checkResult `json:"metrics,omitempty"`
	IsReady        bool          `json:"ready"`
	Reasons        []string      `json:"reasons"`
}

func main() {
	os.Exit(run())
}

// run analyse les arguments, exécute les sondes et retourne le code de sortie.
func run() int {
	var (
		baseURL      = flag.String("url", envFirst("THOT_SECURE_URL", "THOT_URL", "THOT_URL"), "base de l'API à sonder (défaut : $env:THOT_SECURE_URL, sinon "+defaultBaseURL+")")
		timeout      = flag.Duration("timeout", probeRequestTimeout, "délai d'attente par requête http")
		withMetrics  = flag.Bool("metrics", false, "récupère /metrics et vérifie les métriques clés")
		lenient      = flag.Bool("metrics-lenient", false, "avec -metrics : une métrique absente est un avertissement, pas un échec")
		requirements = flag.String("require-metrics", defaultRequirements, "métriques exigées, séparées par des virgules (utilisé avec -metrics)")
		asJSON       = flag.Bool("json", false, "rapport JSON sur stdout (automatisation)")
		verbose      = flag.Bool("verbose", false, "affiche les corps de réponse tronqués")
		insecure     = flag.Bool("insecure", false, "ne vérifie pas le certificat TLS (instance locale autosignée uniquement)")
		showVersion  = flag.Bool("version", false, "affiche la version de la sonde et sort")
	)

	flag.Usage = func() {
		writer := flag.CommandLine.Output()
		fmt.Fprintf(writer, "Sonde de disponibilité Thot Secure (bibliothèque standard uniquement).\n\n")
		fmt.Fprintf(writer, "Usage : %s [options]\n\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(writer, "\nCodes de sortie : 0 prêt, 1 non prêt, 2 usage.\n")
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("thotsecure-healthcheck %s\n", probeVersion)
		return exitReady
	}

	resolved := strings.TrimSpace(*baseURL)
	if resolved == "" {
		resolved = defaultBaseURL
	}
	resolved = strings.TrimRight(resolved, "/")

	parsed, err := url.Parse(resolved)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		fmt.Fprintf(os.Stderr, "URL invalide : %q (attendu http://hôte:port)\n", resolved)
		return exitUsage
	}
	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "-timeout doit être strictement positif")
		return exitUsage
	}

	wanted := splitList(*requirements)
	if *withMetrics && len(wanted) == 0 {
		fmt.Fprintln(os.Stderr, "-require-metrics est vide : indiquez au moins une métrique ou retirez -metrics")
		return exitUsage
	}

	transport := http.DefaultTransport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		cloned := base.Clone()
		if *insecure {
			fmt.Fprintln(os.Stderr, "avertissement : -insecure désactive la vérification du certificat TLS — à réserver à une instance locale")
			cloned.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // option explicite et documentée
		}
		transport = cloned
	}

	client := &http.Client{Timeout: *timeout, Transport: transport}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout+probeTotalTimeoutPad)
	defer cancel()

	report := buildReport(ctx, client, resolved, *withMetrics, wanted, *lenient)
	printReport(os.Stdout, report, *asJSON, *verbose)

	if report.IsReady {
		return exitReady
	}
	return exitNotReady
}

// buildReport exécute toutes les sondes et construit le rapport.
func buildReport(ctx context.Context, client *http.Client, baseURL string, withMetrics bool, wanted []string, lenient bool) healthReport {
	report := healthReport{
		Target:   baseURL,
		Degraded: []checkResult{},
		Reasons:  []string{},
	}

	health := probe(ctx, client, "healthz", baseURL+"/healthz")
	report.Healthz = &health
	applyVersionFields(&report, health.Body)

	// /readyz est interrogé après /healthz : inutile de tester la préparation si le processus
	// ne répond même pas.
	ready := probe(ctx, client, "readyz", baseURL+"/readyz")
	report.Readyz = &ready
	report.Degraded = degradedChecks(ready.Body)

	if !health.OK {
		report.Reasons = append(report.Reasons, describeFailure("healthz", health))
	}
	if !ready.OK {
		report.Reasons = append(report.Reasons, describeFailure("readyz", ready))
	}
	for _, degraded := range report.Degraded {
		report.Reasons = append(report.Reasons, fmt.Sprintf("contrôle dégradé %s : %s", degraded.Name, degraded.Detail))
	}

	if withMetrics {
		report.MetricsChecked = true
		metrics := probe(ctx, client, "metrics", baseURL+"/metrics")
		results, reasons := checkMetrics(metrics, wanted, lenient)
		report.Metrics = results
		report.Reasons = append(report.Reasons, reasons...)
	}

	report.IsReady = len(report.Reasons) == 0
	return report
}

// probe appelle une route et normalise le résultat (statut, corps, durée, erreur).
func probe(ctx context.Context, client *http.Client, name, target string) probeResult {
	result := probeResult{Name: name, URL: target}
	start := time.Now()
	status, body, err := httpGet(ctx, client, target)
	result.DurationMS = float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.HTTPStatus = status
	result.Raw = truncate(string(body), 600)
	result.Body = decodeObject(body)
	result.OK = status == http.StatusOK
	if name == "healthz" && result.OK && result.Body != nil {
		if value, ok := result.Body["status"].(string); ok && value != "" && !strings.EqualFold(value, "ok") {
			// 200 avec un statut métier non « ok » : on ne fait pas semblant.
			result.OK = false
		}
	}
	return result
}

// httpGet exécute un GET en lecture seule, borné en taille.
func httpGet(ctx context.Context, client *http.Client, target string) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("User-Agent", probeUserAgent)
	request.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.1")

	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	if err != nil {
		return response.StatusCode, body, err
	}
	return response.StatusCode, body, nil
}

// decodeObject décode un corps JSON objet ; retourne nil si le corps n'est pas un objet JSON.
func decodeObject(raw []byte) map[string]any {
	trimmed := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(trimmed, "{") {
		return nil
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil
	}
	return object
}

// applyVersionFields récupère version, uptime, dry_run et mode d'autonomie quand l'instance les
// annonce (facultatif : la sonde fonctionne avec un corps minimal).
func applyVersionFields(report *healthReport, body map[string]any) {
	if body == nil {
		return
	}
	if value, ok := body["version"].(string); ok {
		report.Version = value
	}
	if value, ok := body["uptime_s"].(float64); ok {
		seconds := value
		report.UptimeS = &seconds
	}
	if value, ok := body["dry_run"].(bool); ok {
		dryRun := value
		report.DryRun = &dryRun
	}
	for _, key := range []string{"autonomy", "mode", "tenant_mode"} {
		if value, ok := body[key].(string); ok && value != "" {
			report.Autonomy = value
			break
		}
	}
}

// degradedChecks extrait les composants en échec d'un corps /readyz.
//
// Le contrat ne fige pas la forme exacte du corps : la sonde accepte plusieurs conventions
// (`checks`, `components`, `dependencies`, `subsystems`) et plusieurs représentations de valeur
// (booléen, chaîne d'état, objet `{"ok": false, "error": "…"}`).
func degradedChecks(body map[string]any) []checkResult {
	container := firstMap(body, "checks", "components", "dependencies", "subsystems")
	if container == nil {
		return []checkResult{}
	}

	names := make([]string, 0, len(container))
	for name := range container {
		names = append(names, name)
	}
	sort.Strings(names) // sortie déterministe : indispensable pour comparer deux exécutions

	degraded := make([]checkResult, 0, len(names))
	for _, name := range names {
		if ok, detail := evaluateCheck(container[name]); !ok {
			degraded = append(degraded, checkResult{Name: name, OK: false, Detail: detail})
		}
	}
	return degraded
}

// evaluateCheck interprète la valeur d'un composant : (sain ?, détail lisible).
func evaluateCheck(value any) (bool, string) {
	switch typed := value.(type) {
	case nil:
		return false, "valeur absente (null)"
	case bool:
		if typed {
			return true, "ok"
		}
		return false, "signalé en échec (false)"
	case string:
		normalized := strings.ToLower(strings.TrimSpace(typed))
		switch normalized {
		case "ok", "up", "ready", "healthy", "true", "1", "pass", "passed":
			return true, typed
		case "":
			return false, "état vide"
		default:
			return false, typed
		}
	case float64:
		if typed == 0 {
			return false, "valeur 0"
		}
		return true, strconv.FormatFloat(typed, 'f', -1, 64)
	case map[string]any:
		if inner, ok := typed["ok"].(bool); ok {
			if inner {
				return true, "ok"
			}
			if message, ok := typed["error"].(string); ok && message != "" {
				return false, message
			}
			return false, "objet marqué ok=false"
		}
		for _, key := range []string{"status", "state", "health"} {
			if raw, ok := typed[key].(string); ok {
				return evaluateCheck(raw)
			}
		}
		if healthy, ok := typed["healthy"].(bool); ok {
			return evaluateCheck(healthy)
		}
		if message, ok := typed["error"].(string); ok && message != "" {
			return false, message
		}
		return true, "objet sans état explicite"
	default:
		return true, fmt.Sprintf("%v", typed)
	}
}

// firstMap retourne le premier sous-objet trouvé parmi *keys*.
func firstMap(body map[string]any, keys ...string) map[string]any {
	if body == nil {
		return nil
	}
	for _, key := range keys {
		if inner, ok := body[key].(map[string]any); ok {
			return inner
		}
	}
	return nil
}

// metricSample est une valeur de métrique Prometheus (texte).
type metricSample struct {
	Value    float64
	HasValue bool
}

// checkMetrics vérifie la présence et la valeur des métriques clés exposées par /metrics.
//
// Deux métriques portent une signification de sûreté, pas seulement de disponibilité :
//
//	thotsecure_up                == 1 : le service s'estime en service
//	thotsecure_audit_chain_valid == 1 : la chaîne de journalisation d'audit est INTÈGRE
//
// Une chaîne d'audit rompue (0) est un **incident majeur** : le journal a été altéré ou tronqué.
// La sonde le signale en clair et force le code de sortie 1, même si /readyz répond 200.
func checkMetrics(metrics probeResult, wanted []string, lenient bool) ([]checkResult, []string) {
	results := make([]checkResult, 0, len(wanted))
	reasons := make([]string, 0, len(wanted)+1)

	if metrics.Error != "" {
		reasons = append(reasons, fmt.Sprintf("/metrics injoignable : %s", metrics.Error))
		return results, reasons
	}
	if metrics.HTTPStatus != http.StatusOK {
		reasons = append(reasons, fmt.Sprintf("/metrics a répondu HTTP %d", metrics.HTTPStatus))
		return results, reasons
	}

	samples := parseMetrics(metrics.Raw)
	for _, name := range wanted {
		sample, present := samples[name]
		switch {
		case !present:
			detail := "métrique absente de l'exposition"
			results = append(results, checkResult{Name: name, OK: lenient, Detail: detail})
			if !lenient {
				reasons = append(reasons, fmt.Sprintf("métrique requise absente : %s", name))
			}
		case !sample.HasValue:
			detail := "métrique déclarée sans valeur exploitable"
			results = append(results, checkResult{Name: name, OK: false, Detail: detail})
			reasons = append(reasons, fmt.Sprintf("%s : %s", name, detail))
		case sample.Value == 0:
			detail := "valeur 0"
			if name == metricAuditChain {
				detail = "CHAÎNE D'AUDIT ROMPUE — incident majeur : le journal chaîné a été altéré ou tronqué ; conservez les sauvegardes et ouvrez un incident"
			}
			if name == metricUp {
				detail = "le service s'annonce hors service (voir /readyz)"
			}
			results = append(results, checkResult{Name: name, OK: false, Detail: detail})
			reasons = append(reasons, fmt.Sprintf("%s = 0 (%s)", name, detail))
		default:
			results = append(results, checkResult{
				Name:   name,
				OK:     true,
				Detail: strconv.FormatFloat(sample.Value, 'f', -1, 64),
			})
		}
	}
	return results, reasons
}

// parseMetrics lit l'exposition texte Prometheus et indexe les séries par nom.
//
// Les lignes `# HELP` / `# TYPE` sont ignorées, les étiquettes `{…}` sont retirées, et la valeur
// est la première colonne convertible en flottant après le nom.
func parseMetrics(text string) map[string]metricSample {
	samples := make(map[string]metricSample)
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if open := strings.IndexByte(line, '{'); open >= 0 {
			if closeIndex := strings.IndexByte(line, '}'); closeIndex > open {
				// "nom{étiquettes} valeur" → "nom valeur"
				line = line[:open] + line[closeIndex+1:]
			}
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if name == "" {
			continue
		}
		sample := metricSample{}
		if len(fields) >= 2 {
			if value, err := strconv.ParseFloat(fields[1], 64); err == nil {
				sample.Value = value
				sample.HasValue = true
			}
		}
		if _, exists := samples[name]; !exists {
			samples[name] = sample
		}
	}
	return samples
}

// describeFailure reformule l'échec d'une sonde en une raison lisible.
func describeFailure(name string, result probeResult) string {
	switch {
	case result.Error != "":
		return fmt.Sprintf("%s injoignable : %s", name, result.Error)
	case result.HTTPStatus == http.StatusServiceUnavailable:
		return fmt.Sprintf("%s a répondu 503 (service non prêt : DB, bus ou règles indisponibles)", name)
	case result.HTTPStatus == 0:
		return fmt.Sprintf("%s n'a renvoyé aucun statut HTTP exploitable", name)
	default:
		return fmt.Sprintf("%s a répondu HTTP %d", name, result.HTTPStatus)
	}
}

// printReport affiche le rapport : une première ligne lisible par un superviseur
// (Nagios/Icinga, journal systemd), puis le détail des contrôles dégradés.
func printReport(writer io.Writer, report healthReport, asJSON bool, verbose bool) {
	if asJSON {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "écriture du rapport JSON impossible : %v\n", err)
		}
		return
	}

	status := "OK"
	if !report.IsReady {
		status = "CRITICAL"
	}

	summary := fmt.Sprintf("%s - %s", status, report.Target)
	if report.Version != "" {
		summary += fmt.Sprintf(" version %s", report.Version)
	}
	if report.Healthz != nil {
		summary += fmt.Sprintf(" | healthz=%d (%.1f ms)", report.Healthz.HTTPStatus, report.Healthz.DurationMS)
	}
	if report.Readyz != nil {
		summary += fmt.Sprintf(" readyz=%d (%.1f ms)", report.Readyz.HTTPStatus, report.Readyz.DurationMS)
	}
	if report.IsReady {
		summary += " | prêt"
	} else {
		summary += fmt.Sprintf(" | NON PRÊT (%d raison(s))", len(report.Reasons))
	}
	fmt.Fprintln(writer, summary)

	if report.DryRun != nil && *report.DryRun {
		fmt.Fprintln(writer, "  info : l'instance est en dry_run (aucune action réelle n'est exécutée)")
	}
	if report.Autonomy != "" {
		fmt.Fprintf(writer, "  info : mode d'autonomie « %s »\n", report.Autonomy)
	}
	if report.Healthz != nil && report.Healthz.Error != "" {
		fmt.Fprintf(writer, "  healthz : %s\n", report.Healthz.Error)
	}
	if report.Readyz != nil && report.Readyz.Error != "" {
		fmt.Fprintf(writer, "  readyz  : %s\n", report.Readyz.Error)
	}

	if len(report.Degraded) > 0 {
		fmt.Fprintf(writer, "  contrôles dégradés (%d) :\n", len(report.Degraded))
		for _, check := range report.Degraded {
			fmt.Fprintf(writer, "    - %s : %s\n", check.Name, check.Detail)
		}
	}

	if report.MetricsChecked && len(report.Metrics) > 0 {
		fmt.Fprintln(writer, "  métriques :")
		for _, metric := range report.Metrics {
			mark := "ok"
			if !metric.OK {
				mark = "ÉCHEC"
			}
			fmt.Fprintf(writer, "    - %s = %s (%s)\n", metric.Name, metric.Detail, mark)
		}
	}

	if len(report.Reasons) > 0 {
		fmt.Fprintln(writer, "  raisons :")
		for _, reason := range report.Reasons {
			fmt.Fprintf(writer, "    - %s\n", reason)
		}
	}

	if verbose {
		if report.Healthz != nil && report.Healthz.Raw != "" {
			fmt.Fprintf(writer, "  --- /healthz ---\n%s\n", report.Healthz.Raw)
		}
		if report.Readyz != nil && report.Readyz.Raw != "" {
			fmt.Fprintf(writer, "  --- /readyz ---\n%s\n", report.Readyz.Raw)
		}
	}
}

// envFirst retourne la première variable d'environnement non vide parmi *names*.
func envFirst(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

// splitList découpe une liste séparée par des virgules, en ignorant les éléments vides.
func splitList(value string) []string {
	items := make([]string, 0, 4)
	for _, part := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}

// truncate borne une chaîne pour l'affichage (les corps de réponse peuvent être longs).
func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…(tronqué)"
}
