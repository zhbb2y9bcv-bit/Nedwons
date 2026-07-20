import Foundation

/// Minimal hex helpers for test vectors and the interop tool. Not used on hot paths.
public enum Hex {
    public static func encode(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    public static func decode(_ string: String) -> Data? {
        let chars = Array(string)
        guard chars.count % 2 == 0 else { return nil }
        var out = Data(capacity: chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = chars[i].hexDigitValue, let lo = chars[i + 1].hexDigitValue else {
                return nil
            }
            out.append(UInt8(hi << 4 | lo))
            i += 2
        }
        return out
    }
}
