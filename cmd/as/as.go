package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

type GrantReq struct {
	Client struct {
		Key struct {
			Proof string `json:"proof"`
			JWK   JWK    `json:"jwk"`
		} `json:"key"`
	} `json:"client"`
}

type GrantResp struct {
	AccessToken struct {
		Value string `json:"value"`
	} `json:"access_token"`
}

type IntrospectReq struct {
	Token string `json:"token"`
}

type IntrospectResp struct {
	Active bool `json:"active"`
	Key    struct {
		Kid string `json:"kid"`
		JWK JWK    `json:"jwk"`
	} `json:"key"`
}

// in-memory stores
var (
	mu            sync.Mutex
	tokenBindings = map[string]struct {
		Kid string
		JWK JWK
	}{}
	clientKeys = map[string]JWK{}
	nonceSeen  = map[string]time.Time{}
)

func main() {
	http.HandleFunc("/gnap/tx", handleGrant)         // client -> AS
	http.HandleFunc("/introspect", handleIntrospect) // RS -> AS
	http.HandleFunc("/rotate-key", handleRotate)     // client -> AS (dual-signed)

	log.Println("AS on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func handleGrant(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))

	// must have content-digest
	cdWant := r.Header.Get("Content-Digest")
	cdGot := contentDigestSHA256(body)
	if cdWant == "" || cdWant != cdGot {
		http.Error(w, "bad Content-Digest", http.StatusBadRequest)
		return
	}

	var gr GrantReq
	if err := json.Unmarshal(body, &gr); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if gr.Client.Key.Proof != "httpsig" {
		http.Error(w, "proof must be httpsig", http.StatusUnauthorized)
		return
	}
	jwk := gr.Client.Key.JWK
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.Alg != "EdDSA" || jwk.Kid == "" || jwk.X == "" {
		http.Error(w, "bad jwk", http.StatusUnauthorized)
		return
	}

	// verify httpsig using the JWK in the body
	sigInputs, err := parseSignatureInputHeader(r.Header.Get("Signature-Input"))
	if err != nil {
		http.Error(w, "bad Signature-Input", http.StatusUnauthorized)
		return
	}
	sigs, err := parseSignatureHeader(r.Header.Get("Signature"))
	if err != nil {
		http.Error(w, "bad Signature", http.StatusUnauthorized)
		return
	}
	// expect single label: sig1
	si, ok := sigInputs["sig1"]
	if !ok {
		http.Error(w, "missing sig1", http.StatusUnauthorized)
		return
	}
	sb, err := buildBaseGrant(r, cdGot, si.Covered, si.Params)
	if err != nil {
		http.Error(w, "bad base", http.StatusUnauthorized)
		return
	}
	params := parseParams(si.Params)
	if params["tag"] != "gnap" || params["created"] == "" || params["nonce"] == "" || params["keyid"] == "" {
		http.Error(w, "missing params", http.StatusUnauthorized)
		return
	}
	if params["keyid"] != jwk.Kid {
		http.Error(w, "keyid != jwk.kid", http.StatusUnauthorized)
		return
	}
	if err := checkFresh(params["created"]); err != nil {
		http.Error(w, "stale created", http.StatusUnauthorized)
		return
	}
	if replay(params["nonce"]) {
		http.Error(w, "replay nonce", http.StatusUnauthorized)
		return
	}
	pub, err := ed25519FromJWK(jwk)
	if err != nil {
		http.Error(w, "bad jwk x", http.StatusUnauthorized)
		return
	}
	if !verifySig("sig1", sigs, pub, sb) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}

	// bind token to key
	token := "TKN-" + randomB64(18)
	mu.Lock()
	tokenBindings[token] = struct {
		Kid string
		JWK JWK
	}{Kid: jwk.Kid, JWK: jwk}
	clientKeys[jwk.Kid] = jwk
	mu.Unlock()

	var resp GrantResp
	resp.AccessToken.Value = token
	writeJSON(w, resp)
}

func handleIntrospect(w http.ResponseWriter, r *http.Request) {
	var iq IntrospectReq
	if err := json.NewDecoder(r.Body).Decode(&iq); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	mu.Lock()
	b, ok := tokenBindings[iq.Token]
	mu.Unlock()
	var out IntrospectResp
	if !ok {
		out.Active = false
		writeJSON(w, out)
		return
	}
	out.Active = true
	out.Key.Kid = b.Kid
	out.Key.JWK = b.JWK
	writeJSON(w, out)
}

// key rotation with dual signatures
func handleRotate(w http.ResponseWriter, r *http.Request) {
	// must carry Authorization and body with new JWK
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "GNAP ") {
		http.Error(w, "missing auth", http.StatusUnauthorized)
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "GNAP"))

	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	cdWant := r.Header.Get("Content-Digest")
	cdGot := contentDigestSHA256(body)
	if cdWant == "" || cdWant != cdGot {
		http.Error(w, "bad Content-Digest", http.StatusBadRequest)
		return
	}
	var payload struct {
		Key struct {
			Proof string `json:"proof"`
			JWK   JWK    `json:"jwk"`
		} `json:"key"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	newJWK := payload.Key.JWK
	if newJWK.Kty != "OKP" || newJWK.Crv != "Ed25519" || newJWK.Alg != "EdDSA" || newJWK.Kid == "" || newJWK.X == "" {
		http.Error(w, "bad new jwk", http.StatusUnauthorized)
		return
	}

	// fetch old binding
	mu.Lock()
	binding, ok := tokenBindings[token]
	mu.Unlock()
	if !ok {
		http.Error(w, "unknown token", http.StatusUnauthorized)
		return
	}
	oldJWK := binding.JWK

	// parse two signatures: old-key and new-key
	sigInputs, err := parseSignatureInputHeader(r.Header.Get("Signature-Input"))
	if err != nil {
		http.Error(w, "bad Signature-Input", http.StatusUnauthorized)
		return
	}
	sigs, err := parseSignatureHeader(r.Header.Get("Signature"))
	if err != nil {
		http.Error(w, "bad Signature", http.StatusUnauthorized)
		return
	}
	siOld, ok1 := sigInputs["old-key"]
	siNew, ok2 := sigInputs["new-key"]
	if !ok1 || !ok2 {
		http.Error(w, "need old-key and new-key", http.StatusUnauthorized)
		return
	}
	// verify old-key signature first
	baseOld, err := buildBaseRotateOld(r, cdGot, siOld.Covered, siOld.Params)
	if err != nil {
		http.Error(w, "bad base old", http.StatusUnauthorized)
		return
	}
	pOld := parseParams(siOld.Params)
	if pOld["tag"] != "gnap" || pOld["keyid"] != oldJWK.Kid || pOld["created"] == "" || pOld["nonce"] == "" {
		http.Error(w, "old-key params", http.StatusUnauthorized)
		return
	}
	if err := checkFresh(pOld["created"]); err != nil || replay(pOld["nonce"]) {
		http.Error(w, "old-key freshness/replay", http.StatusUnauthorized)
		return
	}
	oldPub, err := ed25519FromJWK(oldJWK)
	if err != nil || !verifySig("old-key", sigs, oldPub, baseOld) {
		http.Error(w, "old-key verify", http.StatusUnauthorized)
		return
	}

	// verify new-key signature which must cover prior Signature and Signature-Input
	baseNew, err := buildBaseRotateNew(r, cdGot, siNew.Covered, siNew.Params, "old-key", sigInputs, sigs)
	if err != nil {
		http.Error(w, "bad base new", http.StatusUnauthorized)
		return
	}
	pNew := parseParams(siNew.Params)
	if pNew["tag"] != "gnap-rotate" || pNew["keyid"] != newJWK.Kid || pNew["created"] == "" || pNew["nonce"] == "" {
		http.Error(w, "new-key params", http.StatusUnauthorized)
		return
	}
	if err := checkFresh(pNew["created"]); err != nil || replay(pNew["nonce"]) {
		http.Error(w, "new-key freshness/replay", http.StatusUnauthorized)
		return
	}
	newPub, err := ed25519FromJWK(newJWK)
	if err != nil || !verifySig("new-key", sigs, newPub, baseNew) {
		http.Error(w, "new-key verify", http.StatusUnauthorized)
		return
	}

	// update binding to new key
	mu.Lock()
	tokenBindings[token] = struct {
		Kid string
		JWK JWK
	}{Kid: newJWK.Kid, JWK: newJWK}
	mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// helpers

func buildBaseGrant(r *http.Request, cd, covered, params string) (string, error) {
	expect := `("@method" "@target-uri" "content-digest")`
	if covered != expect {
		return "", errors.New("wrong covered")
	}
	tu := targetURI(r)
	lines := []string{
		fmt.Sprintf("\"@method\": %s", r.Method),
		fmt.Sprintf("\"@target-uri\": %s", tu),
		fmt.Sprintf("\"content-digest\": %s", cd),
		fmt.Sprintf("\"@signature-params\": %s%s", covered, params),
	}
	return strings.Join(lines, "\n"), nil
}

func buildBaseRotateOld(r *http.Request, cd, covered, params string) (string, error) {
	expect := `("@method" "@target-uri" "content-digest" "authorization")`
	if covered != expect {
		return "", errors.New("wrong covered old")
	}
	tu := targetURI(r)
	auth := r.Header.Get("Authorization")
	lines := []string{
		fmt.Sprintf("\"@method\": %s", r.Method),
		fmt.Sprintf("\"@target-uri\": %s", tu),
		fmt.Sprintf("\"content-digest\": %s", cd),
		fmt.Sprintf("\"authorization\": %s", auth),
		fmt.Sprintf("\"@signature-params\": %s%s", covered, params),
	}
	return strings.Join(lines, "\n"), nil
}

func buildBaseRotateNew(r *http.Request, cd, covered, params, oldLabel string, sis map[string]sigInput, sigs map[string]string) (string, error) {
	expect := `("@method" "@target-uri" "content-digest" "authorization" "signature";key="old-key" "signature-input";key="old-key")`
	if covered != expect {
		return "", errors.New("wrong covered new")
	}
	tu := targetURI(r)
	auth := r.Header.Get("Authorization")
	oldSigInput := "old-key=" + sis[oldLabel].Covered + sis[oldLabel].Params
	oldSig := ":" + sigs[oldLabel] + ":"
	lines := []string{
		fmt.Sprintf("\"@method\": %s", r.Method),
		fmt.Sprintf("\"@target-uri\": %s", tu),
		fmt.Sprintf("\"content-digest\": %s", cd),
		fmt.Sprintf("\"authorization\": %s", auth),
		fmt.Sprintf("\"signature\";key=\"old-key\": %s", oldSig),
		fmt.Sprintf("\"signature-input\";key=\"old-key\": %s", oldSigInput),
		fmt.Sprintf("\"@signature-params\": %s%s", covered, params),
	}
	return strings.Join(lines, "\n"), nil
}

func handleErr(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusUnauthorized)
}

func verifySig(label string, sigs map[string]string, pub ed25519.PublicKey, base string) bool {
	b64, ok := sigs[label]
	if !ok {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, []byte(base), raw)
}

func parseSignatureHeader(h string) (map[string]string, error) {
	// Signature: label=:b64: , label2=:b64:
	out := map[string]string{}
	if strings.TrimSpace(h) == "" {
		return out, nil
	}
	parts := splitTop(h, ',')
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			return nil, errors.New("bad sig kv")
		}
		lab := strings.TrimSpace(p[:eq])
		val := strings.Trim(strings.TrimSpace(p[eq+1:]), ":")
		out[lab] = val
	}
	return out, nil
}

type sigInput struct {
	Covered string
	Params  string
}

func parseSignatureInputHeader(h string) (map[string]sigInput, error) {
	// Signature-Input: lab=("..");param=..;..., lab2=("..");...
	out := map[string]sigInput{}
	if strings.TrimSpace(h) == "" {
		return out, nil
	}
	parts := splitTop(h, ',')
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			return nil, errors.New("bad sig-input kv")
		}
		lab := strings.TrimSpace(p[:eq])
		rest := strings.TrimSpace(p[eq+1:])
		i := strings.Index(rest, ")")
		if !strings.HasPrefix(rest, "(") || i < 0 {
			return nil, errors.New("bad inner list")
		}
		covered := rest[:i+1]
		params := rest[i+1:] // starts with ;...
		out[lab] = sigInput{Covered: covered, Params: params}
	}
	return out, nil
}

func parseParams(params string) map[string]string {
	out := map[string]string{}
	parts := strings.Split(params, ";")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			continue
		}
		k := p[:eq]
		v := p[eq+1:]
		out[k] = strings.Trim(v, `"`)
	}
	return out
}

func ed25519FromJWK(j JWK) (ed25519.PublicKey, error) {
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil || len(x) != ed25519.PublicKeySize {
		return nil, errors.New("bad x")
	}
	return ed25519.PublicKey(x), nil
}

func contentDigestSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

func checkFresh(created string) error {
	sec, err := strconv.ParseInt(created, 10, 64)
	if err != nil {
		return err
	}
	ts := time.Unix(sec, 0)
	if d := time.Since(ts); d > 5*time.Minute || d < -5*time.Minute {
		return errors.New("stale")
	}
	return nil
}

func replay(nonce string) bool {
	now := time.Now()
	mu.Lock()
	defer mu.Unlock()
	if t, ok := nonceSeen[nonce]; ok && now.Sub(t) < 5*time.Minute {
		return true
	}
	nonceSeen[nonce] = now
	return false
}

func targetURI(r *http.Request) string {
	return "http://" + r.Host + r.URL.RequestURI()
}

func randomB64(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil { // ✅ cryptographically secure
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// splitTop splits by sep at top level (no quoted parsing needed for this demo)
func splitTop(s string, sep rune) []string {
	var out []string
	start := 0
	for i, r := range s {
		if r == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
