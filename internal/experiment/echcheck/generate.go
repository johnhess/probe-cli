package echcheck

// Generates a 'GREASE ECH' extension, as described in section 6.2 of
// ietf.org/archive/id/draft-ietf-tls-esni-14.html

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
	"golang.org/x/crypto/cryptobyte"
)

const clientHelloOuter uint8 = 0

// echTLSExtension is the Encrypted Client Hello extension that is part of
// ClientHelloOuter as specified in:
// ietf.org/archive/id/draft-ietf-tls-esni-14.html#section-5
type echTLSExtension struct {
	kdfID    uint16
	aeadID   uint16
	configID uint8
	enc      []byte
	payload  []byte
}

func (ech *echTLSExtension) marshal() []byte {
	var b cryptobyte.Builder
	b.AddUint8(clientHelloOuter)
	b.AddUint16(ech.kdfID)
	b.AddUint16(ech.aeadID)
	b.AddUint8(ech.configID)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(ech.enc)
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(ech.payload)
	})
	return b.BytesOrPanic()
}

// generateGreaseExtension generates an ECH extension with random values as
// specified in ietf.org/archive/id/draft-ietf-tls-esni-14.html#section-6.2
func generateGreaseExtension(rand io.Reader) ([]byte, error) {
	// This makes this extension type.  I think what we really want
	// for our test is to generate ECHConfigList.
	// struct {
	// 	ECHClientHelloType type;
	// 	select (ECHClientHello.type) {
	// 		case outer:
	// 			HpkeSymmetricCipherSuite cipher_suite;
	// 			uint8 config_id;
	// 			opaque enc<0..2^16-1>;
	// 			opaque payload<1..2^16-1>;
	// 	};
	// } ECHClientHello; (Outer)

	// initialize HPKE suite parameters

	// TODO: Make this random instead of hardcoded
	kem := hpke.KEM(uint16(hpke.KEM_X25519_HKDF_SHA256))
	kdf := hpke.KDF(uint16(hpke.KDF_HKDF_SHA256))
	aead := hpke.AEAD(uint16(hpke.AEAD_AES128GCM))

	if !kem.IsValid() || !kdf.IsValid() || !aead.IsValid() {
		return nil, fmt.Errorf("required parameters not supported")
	}

	defaultHPKESuite := hpke.NewSuite(kem, kdf, aead)

	// generate a public key to place in 'enc' field
	publicKey, _, err := kem.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %s", err)
	}

	// initiate HPKE Sender
	sender, err := defaultHPKESuite.NewSender(publicKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create sender: %s", err)
	}

	// Set ECH Extension Fields
	var ech echTLSExtension

	ech.kdfID = uint16(kdf)
	ech.aeadID = uint16(aead)

	randomByte := make([]byte, 1)
	_, err = io.ReadFull(rand, randomByte)
	if err != nil {
		return nil, err
	}
	ech.configID = randomByte[0]

	ech.enc, _, err = sender.Setup(rand)
	if err != nil {
		return nil, err
	}

	// TODO: compute this correctly as per https://www.ietf.org/archive/id/draft-ietf-tls-esni-14.html#name-recommended-padding-scheme
	randomEncodedClientHelloInnerLen := 100
	cipherLen := int(aead.CipherLen(uint(randomEncodedClientHelloInnerLen)))
	ech.payload = make([]byte, randomEncodedClientHelloInnerLen+cipherLen)
	if _, err = io.ReadFull(rand, ech.payload); err != nil {
		return nil, err
	}

	return ech.marshal(), nil
}

func generateGreaseyECHConfigList(rand io.Reader, publicName string) ([]byte, error) {
	// From ESNI-22:
	// opaque HpkePublicKey<1..2^16-1>;
	// uint16 HpkeKemId;              // Defined in RFC9180
	// uint16 HpkeKdfId;              // Defined in RFC9180
	// uint16 HpkeAeadId;             // Defined in RFC9180
	// uint16 ECHConfigExtensionType; // Defined in Section 11.3

	// struct {
	//     HpkeKdfId kdf_id;
	//     HpkeAeadId aead_id;
	// } HpkeSymmetricCipherSuite;

	// struct {
	//     uint8 config_id;
	//     HpkeKemId kem_id;
	//     HpkePublicKey public_key;
	//     HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
	// } HpkeKeyConfig;

	// struct {
	//     ECHConfigExtensionType type;
	//     opaque data<0..2^16-1>;
	// } ECHConfigExtension;

	// struct {
	//     HpkeKeyConfig key_config;
	//     uint8 maximum_name_length;
	//     opaque public_name<1..255>;
	//     ECHConfigExtension extensions<0..2^16-1>;
	// } ECHConfigContents;

	// struct {
	//     uint16 version;
	//     uint16 length;
	//     select (ECHConfig.version) {
	//       case 0xfe0d: ECHConfigContents contents;
	//     }
	// } ECHConfig;

	// Start ECHConfig
	var c cryptobyte.Builder
	version := uint16(0xfe0d)
	c.AddUint16(version)

	// Start ECHConfigContents
	var ecc cryptobyte.Builder
	// Start HpkeKeyConfig
	randConfigId := make([]byte, 1)
	if _, err := io.ReadFull(rand, randConfigId); err != nil {
		return nil, err
	}
	ecc.AddUint8(randConfigId[0])
	ecc.AddUint16(uint16(hpke.KEM_X25519_HKDF_SHA256))
	// Generate a public key
	kem := hpke.KEM(uint16(hpke.KEM_X25519_HKDF_SHA256))
	publicKey, _, err := kem.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	publicKeyBytes, err := publicKey.MarshalBinary()
	ecc.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(publicKeyBytes)
	})
	// Start HpkeSymmetricCipherSuite
	kdf := hpke.KDF(uint16(hpke.KDF_HKDF_SHA256))
	aead := hpke.AEAD(uint16(hpke.AEAD_AES128GCM))
	var cs cryptobyte.Builder
	cs.AddUint16(uint16(kdf))
	cs.AddUint16(uint16(aead))
	ecc.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(cs.BytesOrPanic())
	})
	// End HpkeSymmetricCipherSuite
	// End HpkeKeyConfig
	maxNameLength := uint8(42)
	ecc.AddUint8(maxNameLength)
	publicNameBytes := []byte(publicName)
	ecc.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(publicNameBytes)
	})
	// Start ECHConfigExtension
	var ece cryptobyte.Builder
	ecc.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(ece.BytesOrPanic())
	})
	// End ECHConfigExtension
	// End ECHConfigContents
	c.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(ecc.BytesOrPanic())
	})
	// End ECHConfig
	var l cryptobyte.Builder
	l.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(c.BytesOrPanic())
	})

	return l.BytesOrPanic(), nil
}
