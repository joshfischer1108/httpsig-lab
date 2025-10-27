package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
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

func main() {
	// 1) Generate client keypair and JWK
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	jwk1 := toJWK("client-key-1", pub1)

	//fmt.Printf("JWK kid=%s alg=%s x=%s\n", jwk1.Kid, jwk1.Alg, jwk1.X)
	// 2) Initial GNAP grant to AS with httpsig proof
	token := doGrant("http://localhost:8081/gnap/tx", priv1, jwk1)

	// 3) Call RS with token, covering authorization
	callRS("http://localhost:8082/data", priv1, jwk1, token)

	// 4) Optional: rotate to a new key using dual signatures
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	jwk2 := toJWK("client-key-2", pub2)
	rotateKey("http://localhost:8081/rotate-key", priv1, jwk1, priv2, jwk2, token)

	// 5) Call RS again with new key to prove rotation worked
	callRS("http://localhost:8082/data", priv2, jwk2, token)
}

func doGrant(url string, priv ed25519.PrivateKey, jwk JWK) string {
	var gr GrantReq
	gr.Client.Key.Proof = "httpsig"
	gr.Client.Key.JWK = jwk
	body, _ := json.Marshal(gr)

	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	cd := contentDigestSHA256(body)
	req.Header.Set("Content-Digest", cd)

	covered := `("@method" "@target-uri" "content-digest")`
	created := fmt.Sprintf("%d", time.Now().Unix())
	nonce := randB64(16)
	params := fmt.Sprintf(`;created=%s;keyid="%s";nonce="%s";tag="gnap"`, created, jwk.Kid, nonce)
	req.Header.Set("Signature-Input", "sig1="+covered+params)

	base := fmt.Sprintf("\"@method\": %s\n\"@target-uri\": %s\n\"content-digest\": %s\n\"@signature-params\": %s%s",
		req.Method, url, cd, covered, params)
	//fmt.Println("----- SIGNATURE BASE (AS Call) -----")
	//fmt.Println(base)
	//fmt.Println("----- END BASE -----")
	sig := ed25519.Sign(priv, []byte(base))
	req.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		log.Fatalf("grant failed: %s %s", res.Status, string(b))
	}
	var grr GrantResp
	_ = json.NewDecoder(res.Body).Decode(&grr)
	fmt.Println("token:", grr.AccessToken.Value)
	return grr.AccessToken.Value
}

func callRS(url string, priv ed25519.PrivateKey, jwk JWK, token string) {
	body := []byte(`{"hello":"world"}`)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	cd := contentDigestSHA256(body)
	req.Header.Set("Content-Digest", cd)
	//TEMP: tamper the body AFTER computing the digest to trigger a server rejection
	//body = []byte(`{”hello”:”tampered”}`)
	//req.Body = io.NopCloser(bytes.NewReader(body))
	req.Header.Set("Authorization", "GNAP "+token)

	covered := `("@method" "@target-uri" "content-digest" "authorization")`
	created := fmt.Sprintf("%d", time.Now().Unix())
	nonce := randB64(16)
	params := fmt.Sprintf(`;created=%s;keyid="%s";nonce="%s";tag="gnap"`, created, jwk.Kid, nonce)
	req.Header.Set("Signature-Input", "sig1="+covered+params)
	//fmt.Println("Signature-Input:", req.Header.Get("Signature-Input"))
	base := fmt.Sprintf("\"@method\": %s\n\"@target-uri\": %s\n\"content-digest\": %s\n\"authorization\": %s\n\"@signature-params\": %s%s",
		req.Method, url, cd, "GNAP "+token, covered, params)
	//fmt.Println("----- SIGNATURE BASE (RS Call) -----")
	//fmt.Println(base)
	//fmt.Println("----- END BASE -----")
	sig := ed25519.Sign(priv, []byte(base))
	req.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	fmt.Println("RS:", res.Status, string(b))
}

func rotateKey(url string, oldPriv ed25519.PrivateKey, oldJWK JWK, newPriv ed25519.PrivateKey, newJWK JWK, token string) {
	payload := struct {
		Key struct {
			Proof string `json:"proof"`
			JWK   JWK    `json:"jwk"`
		} `json:"key"`
	}{}
	payload.Key.Proof = "httpsig"
	payload.Key.JWK = newJWK
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "GNAP "+token)
	cd := contentDigestSHA256(body)
	req.Header.Set("Content-Digest", cd)

	// old-key signature
	oldCovered := `("@method" "@target-uri" "content-digest" "authorization")`
	oldParams := fmt.Sprintf(`;created=%d;keyid="%s";nonce="%s";tag="gnap"`, time.Now().Unix(), oldJWK.Kid, randB64(16))
	oldSI := "old-key=" + oldCovered + oldParams
	oldBase := fmt.Sprintf("\"@method\": %s\n\"@target-uri\": %s\n\"content-digest\": %s\n\"authorization\": %s\n\"@signature-params\": %s",
		req.Method, url, cd, "GNAP "+token, oldSI[len("old-key="):])
	oldSig := ed25519.Sign(oldPriv, []byte(oldBase))
	oldSigB64 := base64.StdEncoding.EncodeToString(oldSig)

	// new-key signature covers old signature + old signature-input
	newCovered := `("@method" "@target-uri" "content-digest" "authorization" "signature";key="old-key" "signature-input";key="old-key")`
	newParams := fmt.Sprintf(`;created=%d;keyid="%s";nonce="%s";tag="gnap-rotate"`, time.Now().Unix(), newJWK.Kid, randB64(16))
	newSI := "new-key=" + newCovered + newParams
	newBase := strings.Join([]string{
		fmt.Sprintf("\"@method\": %s", req.Method),
		fmt.Sprintf("\"@target-uri\": %s", url),
		fmt.Sprintf("\"content-digest\": %s", cd),
		fmt.Sprintf("\"authorization\": %s", "GNAP "+token),
		fmt.Sprintf("\"signature\";key=\"old-key\": :%s:", oldSigB64),
		fmt.Sprintf("\"signature-input\";key=\"old-key\": %s", oldSI),
		fmt.Sprintf("\"@signature-params\": %s", newSI[len("new-key="):]),
	}, "\n")
	newSig := ed25519.Sign(newPriv, []byte(newBase))
	newSigB64 := base64.StdEncoding.EncodeToString(newSig)

	// attach both signatures
	req.Header.Set("Signature-Input", oldSI+", "+newSI)
	req.Header.Set("Signature", "old-key=:"+oldSigB64+":, new-key=:"+newSigB64+":")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()
	fmt.Println("Rotate:", res.Status)
}

func toJWK(kid string, pub ed25519.PublicKey) JWK {
	return JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		Alg: "EdDSA",
		Kid: kid,
		X:   base64.RawURLEncoding.EncodeToString([]byte(pub)),
	}
}

func contentDigestSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

func randB64(n int) string {
	max := big.NewInt(256)
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		v, _ := rand.Int(rand.Reader, max)
		buf[i] = byte(v.Int64())
	}
	return base64.StdEncoding.EncodeToString(buf)
}
