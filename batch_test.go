package schnorrkel

import (
	"fmt"
	"github.com/gtank/merlin"
	"testing"
)

func TestVerifyBatch(t *testing.T) {
	batchSize := 8

	message := "hello world"

	transcripts := make([]*merlin.Transcript, batchSize, batchSize)
	pubkeys := make([]*PublicKey, batchSize, batchSize)
	privkeys := make([]*SecretKey, batchSize, batchSize)
	signatures := make([]*Signature, batchSize, batchSize)


	var err error
	for i, _ := range transcripts {

		transcripts[i] = merlin.NewTranscript(message)

		privkeys[i], pubkeys[i], err = GenerateKeypair()
		if err != nil {
			fmt.Println(err)
			return
		}

		// produce signatres and make sure all are correct signatures
		signingTranscript := merlin.NewTranscript(message)
		signatures[i], err = privkeys[i].Sign(signingTranscript)
		if err != nil {
			fmt.Println(err)
			return
		}

		verificationTranscript := merlin.NewTranscript(message)
		ok := pubkeys[i].Verify(signatures[i], verificationTranscript)
		if !ok {
			t.Fatalf("bad signature")
		}
	}

	ok, _ := VerifyBatch(transcripts, pubkeys, signatures)
	if !ok {
		t.Fatalf("VerifyBatch failed")
	}

	// swap two public keys, VerifyBatch should fail
	pubkeys[0], pubkeys[1] = pubkeys[1], pubkeys[0]
	ok, _ = VerifyBatch(transcripts, pubkeys, signatures)
	if ok {
		t.Fatalf("VerifyBatch failed")
	}
}