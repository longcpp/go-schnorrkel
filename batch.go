package schnorrkel

import (
	"errors"
	"github.com/gtank/merlin"
	r255 "github.com/gtank/ristretto255"
)

func VerifyBatch(transcripts []*merlin.Transcript, publicKeys []*PublicKey, signatures []*Signature) (bool, error) {
	if transcripts == nil || len(transcripts) == 0 {
		return false, errors.New("transcripts must be an array with one or more elementranscripts")
	}
	if publicKeys == nil || len(publicKeys) == 0 {
		return false, errors.New("publicKeys must be an array with one or more elementranscripts")
	}
	if signatures == nil || len(signatures) == 0 {
		return false, errors.New("signatures must be an array with one or more elementranscripts")
	}
	if len(publicKeys) != len(transcripts) ||
		len(transcripts) != len(signatures) ||
		len(signatures) != len(publicKeys) {
		return false, errors.New("all parameters must be an array of the same length")
	}

	// (- \sum z[i]s[i]) B + \sum z[i]R[i] + \sum (z[i]h[i]) pk[i] = Identity

	num := len(publicKeys)
	// H(m||pk||sig) for each sig to be verified
	zs := make([]*r255.Scalar, num, num)
	zss := make([]*r255.Scalar, num, num)
	zhs := make([]*r255.Scalar, num, num)
	zsSum := r255.NewScalar()

	Rs := make([]*r255.Element, num, num)
	Ps := make([]*r255.Element, num, num)

	var err error

	for i, _ := range transcripts {
		transcripts[i].AppendMessage([]byte("proto-name"), []byte("Schnorr-sig"))

		pubkey := publicKeys[i]
		pubkeyCompressed := pubkey.Compress()
		transcripts[i].AppendMessage([]byte("sign:pk"), pubkeyCompressed[:])

		signature := signatures[i]
		transcripts[i].AppendMessage([]byte("sign:R"), signature.R.Encode([]byte{}))

		hb := transcripts[i].ExtractBytes([]byte("sign:c"), 64)

		// generate 256-bit random scalar with system RNG
		// TODO change to merlin transcript style & 128-bit random scalar should be enough
		zs[i], err = NewRandomScalar() // z[i]
		if err != nil {
			return false, err
		}

		zhs[i] = r255.NewScalar()
		zhs[i].FromUniformBytes(hb) // h[i]
		zhs[i].Multiply(zhs[i], zs[i]) //  zhs[i] = z[i] * h[i]

		zss[i] = r255.NewScalar()
		zss[i].Multiply(signature.S, zs[i]) // zss[i] = z[i] * s[i]
		zsSum.Add(zsSum, zss[i]) // zsSum += z[i]*s[i]

		Rs[i] = signature.R
		Ps[i] = pubkey.key
	}
	zsSum.Negate(zsSum) // zsSum = -\sum z[i] * s[i]

	scalars := append(append([]*r255.Scalar{zsSum}, zs...), zhs...)
	points := append(append([]*r255.Element{NewRistrettoBasepoint()}, Rs...), Ps...)

	res := r255.NewElement()
	res.VarTimeMultiScalarMult(scalars, points)

	// (- \sum z[i]s[i]) B + \sum z[i]R[i] + \sum (z[i]h[i]) pk[i] = Identity
	if res.Equal(r255.NewElement()) == 1 {
		return true, nil
	} else {
		return false, nil
	}
}
