package main

import (
	"bytes"
	"crypto/ed25519"
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
	"time"
)

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
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

type sigInput struct {
	Covered string
	Params  string
}

func main() {
	http.HandleFunc("/data", handleData)
	log.Println("RS on :8082")
	log.Fatal(http.ListenAndServe(":8082", nil))
}

func handleData(w http.ResponseWriter, r *http.Request) {
	// read body and restore
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))

	// must have Content-Digest
	cdWant := r.Header.Get("Content-Digest")
	cdGot := contentDigestSHA256(body)
	if cdWant == "" || cdWant != cdGot {
		http.Error(w, "bad Content-Digest", http.StatusBadRequest)
		return
	}

	// must have Authorization
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "GNAP ") {
		http.Error(w, "missing Authorization", http.StatusUnauthorized)
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "GNAP"))

	// ask AS for the token-bound key
	key, err := introspect("http://localhost:8081/introspect", token)
	if err != nil || key.Kid == "" {
		http.Error(w, "inactive token", http.StatusUnauthorized)
		return
	}
	pub, err := ed25519FromJWK(key)
	if err != nil {
		http.Error(w, "bad key", http.StatusUnauthorized)
		return
	}

	// parse Signature-Input and Signature
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
	si, ok := sigInputs["sig1"]
	if !ok {
		http.Error(w, "missing sig1", http.StatusUnauthorized)
		return
	}

	// enforce covered set
	expect := `("@method" "@target-uri" "content-digest" "authorization")`
	if si.Covered != expect {
		http.Error(w, "wrong covered", http.StatusUnauthorized)
		return
	}
	// params
	pm := parseParams(si.Params)
	if pm["tag"] != "gnap" || pm["created"] == "" || pm["nonce"] == "" || pm["keyid"] == "" {
		http.Error(w, "missing params", http.StatusUnauthorized)
		return
	}
	if pm["keyid"] != key.Kid {
		http.Error(w, "keyid mismatch", http.StatusUnauthorized)
		return
	}
	if err := checkFresh(pm["created"]); err != nil {
		http.Error(w, "stale created", http.StatusUnauthorized)
		return
	}
	// build base and verify
	base := strings.Join([]string{
		fmt.Sprintf("\"@method\": %s", r.Method),
		fmt.Sprintf("\"@target-uri\": %s", targetURI(r)),
		fmt.Sprintf("\"content-digest\": %s", cdGot),
		fmt.Sprintf("\"authorization\": %s", auth),
		fmt.Sprintf("\"@signature-params\": %s%s", si.Covered, si.Params),
	}, "\n")

	if !verifySig("sig1", sigs, pub, base) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func introspect(url, token string) (JWK, error) {
	var out JWK
	req := IntrospectReq{Token: token}
	b, _ := json.Marshal(req)
	res, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return out, err
	}
	defer res.Body.Close()
	var ir IntrospectResp
	if err := json.NewDecoder(res.Body).Decode(&ir); err != nil {
		return out, err
	}
	if !ir.Active {
		return out, errors.New("inactive")
	}
	return ir.Key.JWK, nil
}

func parseSignatureHeader(h string) (map[string]string, error) {
	out := map[string]string{}
	if strings.TrimSpace(h) == "" {
		return out, nil
	}
	parts := strings.Split(h, ",")
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

func parseSignatureInputHeader(h string) (map[string]sigInput, error) {
	out := map[string]sigInput{}
	if strings.TrimSpace(h) == "" {
		return out, nil
	}
	parts := strings.Split(h, ",")
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
		params := rest[i+1:]
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
		v := strings.Trim(p[eq+1:], `"`)
		out[k] = v
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

func targetURI(r *http.Request) string {
	return "http://" + r.Host + r.URL.RequestURI()
}
