import Foundation
import XCTest

@testable import NedwonsKit

/// The backup container (docs/BACKUPS.md): opaque without the passphrase, fail-closed on tamper,
/// strict about its own shape. Iterations are the enforced minimum so the suite stays fast.
final class BackupTests: XCTestCase {
    private let iterations: UInt32 = 100_000

    private func sample() -> Backup.Archive {
        Backup.Archive(
            atRestRoot: Data(repeating: 7, count: 32),
            files: [
                ("index.json", Data("{\"conversations\":{}}".utf8)),
                ("store-abc", Data(repeating: 0xAB, count: 1024)),
                ("store-abc.archive", Data(repeating: 0xCD, count: 2048)),
            ])
    }

    func testRoundTrip() throws {
        let sealed = try Backup.seal(sample(), passphrase: "correct horse", iterations: iterations)
        let opened = try Backup.open(sealed, passphrase: "correct horse")
        XCTAssertEqual(opened, sample())
    }

    func testWrongPassphraseAndTamperFailIdentically() throws {
        var sealed = try Backup.seal(sample(), passphrase: "correct horse", iterations: iterations)
        XCTAssertThrowsError(try Backup.open(sealed, passphrase: "wrong horse")) { error in
            XCTAssertEqual(error as? Backup.BackupError, .cannotOpen)
        }
        sealed[sealed.count - 20] ^= 0x01
        XCTAssertThrowsError(try Backup.open(sealed, passphrase: "correct horse")) { error in
            XCTAssertEqual(error as? Backup.BackupError, .cannotOpen)
        }
    }

    func testFutureVersionAndGarbageAreRefused() throws {
        var sealed = try Backup.seal(sample(), passphrase: "p8charsss", iterations: iterations)
        sealed[Backup.magic.count] = 9
        XCTAssertThrowsError(try Backup.open(sealed, passphrase: "p8charsss")) { error in
            XCTAssertEqual(error as? Backup.BackupError, .unsupportedVersion(9))
        }
        XCTAssertThrowsError(try Backup.open(Data("not a backup".utf8), passphrase: "x")) { error in
            XCTAssertEqual(error as? Backup.BackupError, .malformed)
        }
    }

    /// A crafted payload must not smuggle a path outside the store directory.
    func testTraversalFileNamesAreRefused() throws {
        let evil = Backup.Archive(
            atRestRoot: Data(repeating: 1, count: 32),
            files: [("../../etc/hosts", Data([1]))])
        // Bypass `seal`'s honest path: encode + decode directly, as an attacker-crafted file would.
        XCTAssertThrowsError(try Backup.decode(Backup.encode(evil))) { error in
            XCTAssertEqual(error as? Backup.BackupError, .malformed)
        }
    }

    /// An archive claiming a weakened KDF is refused outright.
    func testWeakenedIterationsAreRefused() throws {
        var sealed = try Backup.seal(sample(), passphrase: "p8charsss", iterations: iterations)
        let at = Backup.magic.count + 1 + 16
        sealed.replaceSubrange(at..<at + 4, with: [0, 0, 0, 1]) // iterations = 1
        XCTAssertThrowsError(try Backup.open(sealed, passphrase: "p8charsss")) { error in
            XCTAssertEqual(error as? Backup.BackupError, .malformed)
        }
    }

    func testFreshSaltPerBackup() throws {
        let a = try Backup.seal(sample(), passphrase: "p8charsss", iterations: iterations)
        let b = try Backup.seal(sample(), passphrase: "p8charsss", iterations: iterations)
        XCTAssertNotEqual(a, b, "identical content must not produce linkable files")
    }
}
