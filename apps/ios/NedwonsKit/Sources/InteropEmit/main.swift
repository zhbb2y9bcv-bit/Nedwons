import Foundation
import NedwonsKit

// Emits a (public key, message, signature) hex triple for the Rust `verify_interop` example:
// cross-language proof that the client's signatures are accepted by the server's verifier. Run:
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
