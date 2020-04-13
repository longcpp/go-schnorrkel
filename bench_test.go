package schnorrkel

import (
	"fmt"
	"testing"

	"github.com/gtank/merlin"
)

func BenchmarkSigning(b *testing.B) {
	message := "hello world"
	priv, _, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}

	signingTranscript := merlin.NewTranscript(message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := priv.Sign(signingTranscript)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	message := "hello world"
	priv, pub, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}

	signingTranscript := merlin.NewTranscript(message)
	sig, err := priv.Sign(signingTranscript)
	if err != nil {
		fmt.Println(err)
		return
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verificationTranscript := merlin.NewTranscript(message)
		ok := pub.Verify(sig, verificationTranscript)
		if !ok {
			b.Fatalf("pub.Verify failed")
		}
	}
}
