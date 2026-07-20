import Foundation
import NedwonsKit

// Emits a (public key, message, signature) triple as three hex lines: a Swift device signs
// a login transcript, and the Rust backend example `verify_interop` verifies it. This is a
// real cross-language proof that the iOS client's ECDSA-P256 signatures over the canonical
// transcript are accepted by the server's verifier. Run:
//
//   swift run --package-path apps/ios/NedwonsKit InteropEmit \
//     | cargo run -q --manifest-path services/auth-core/Cargo.toml --example verify_interop

let signer = SoftwareDeviceSigner()
let input = AuthTranscript.sampleLoginVectorInput(publicKey: signer.publicKeyX963)
let message = AuthTranscript.encode(input)

do {
    let signature = try signer.sign(message)
    print(Hex.encode(signer.publicKeyX963))
    print(Hex.encode(message))
    print(Hex.encode(signature))
} catch {
    FileHandle.standardError.write(Data("InteropEmit: signing failed: \(error)\n".utf8))
    exit(1)
}
