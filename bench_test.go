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

func benchmarkVerifyBatch(batchSize int, b *testing.B) {
	message := "hello world"

	transcripts := make([]*merlin.Transcript, batchSize, batchSize)
	pubkeys := make([]*PublicKey, batchSize, batchSize)
	privkeys := make([]*SecretKey, batchSize, batchSize)
	signatures := make([]*Signature, batchSize, batchSize)


	var err error
	for i, _ := range transcripts {
		privkeys[i], pubkeys[i], err = GenerateKeypair()
		if err != nil {
			fmt.Println(err)
			return
		}

		signingTranscript := merlin.NewTranscript(message)
		signatures[i], err = privkeys[i].Sign(signingTranscript)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j, _ := range pubkeys {
			transcripts[j] = merlin.NewTranscript(message)
		}
		ok, _ := VerifyBatch(transcripts, pubkeys, signatures)
		if !ok {
			b.Fatalf("VerifyBatch failed")
		}
	}
}

func BenchmarkVerifyBatch1(b *testing.B) {
	benchmarkVerifyBatch(1, b)
}

func BenchmarkVerifyBatch2(b *testing.B) {
	benchmarkVerifyBatch(2, b)
}

func BenchmarkVerifyBatch4(b *testing.B) {
	benchmarkVerifyBatch(4, b)
}

func BenchmarkVerifyBatch8(b *testing.B) {
	benchmarkVerifyBatch(8, b)
}

func BenchmarkVerifyBatch16(b *testing.B) {
	benchmarkVerifyBatch(16, b)
}

func BenchmarkVerifyBatch32(b *testing.B) {
	benchmarkVerifyBatch(32, b)
}

