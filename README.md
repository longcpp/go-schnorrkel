你好！
很冒昧用这样的方式来和你沟通，如有打扰请忽略我的提交哈。我是光年实验室（gnlab.com）的HR，在招Golang开发工程师，我们是一个技术型团队，技术氛围非常好。全职和兼职都可以，不过最好是全职，工作地点杭州。
我们公司是做流量增长的，Golang负责开发SAAS平台的应用，我们做的很多应用是全新的，工作非常有挑战也很有意思，是国内很多大厂的顾问。
如果有兴趣的话加我微信：13515810775  ，也可以访问 https://gnlab.com/，联系客服转发给HR。
# go-schnorrkel

Go implementation of the sr25519 signature algorithm (schnorr over ristretto25519). The existing rust implementation is [here.](https://github.com/w3f/schnorrkel)

This library is currently able to create sr25519 keys, import sr25519 keys, and sign and verify messages. It is interoperable with
the rust implementation. 

The BIP39 implementation in this library is compatible with the rust [substrate-bip39](https://github.com/paritytech/substrate-bip39) implementation.  Note that this is not a standard bip39 implementation.

### dependencies

go 1.13

### usage

Example: key generation, signing, and verification

```
package main 

import (
	"fmt"
	
	schnorrkel "github.com/ChainSafe/go-schnorrkel"
)

func main() {
	msg := []byte("hello friends")
	signingCtx := []byte("example")

	signingTranscript := schnorrkel.NewSigningContext(signingCtx, msg)
	verifyTranscript := schnorrkel.NewSigningContext(signingCtx, msg)

	priv, pub, err := schnorrkel.GenerateKeypair()
	if err != nil {
		fmt.Println(err)
		return
	}

	sig, err := priv.Sign(signingTranscript)
	if err != nil {
		fmt.Println(err)
		return
	}

	ok := pub.Verify(sig, verifyTranscript)
	if !ok {
		fmt.Println("did not verify :(")
		return
	}
}

```
