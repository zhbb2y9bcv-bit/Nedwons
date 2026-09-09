import AVFoundation
import NedwonsKit
import SwiftUI

#if os(iOS)
    import QuickLook
    import UIKit
#endif

// MARK: - Voice notes

/// Records a voice note as AAC (`audio/mp4`). AVAudioRecorder needs a file URL, so the capture
/// lands briefly in a temp file that is read and deleted the moment recording ends — the sent
/// bytes then follow the normal attachment path (sealed before anything leaves the device).
@MainActor
final class VoiceNoteRecorder: NSObject, ObservableObject {
    @Published private(set) var isRecording = false
    @Published private(set) var elapsed: TimeInterval = 0

    private var recorder: AVAudioRecorder?
    private var url: URL?
    private var ticker: Timer?

    /// Max length keeps a forgotten recording from filling the 25 MB attachment cap.
    static let maxSeconds: TimeInterval = 300

    func start() async -> Bool {
        #if os(iOS)
            let granted = await AVAudioApplication.requestRecordPermission()
            guard granted else { return false }
            try? AVAudioSession.sharedInstance().setCategory(.playAndRecord, mode: .default)
            try? AVAudioSession.sharedInstance().setActive(true)
        #endif
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("nedwons-voice-\(UUID().uuidString).m4a")
        let settings: [String: Any] = [
            AVFormatIDKey: kAudioFormatMPEG4AAC,
            AVSampleRateKey: 24_000,
            AVNumberOfChannelsKey: 1,
            AVEncoderAudioQualityKey: AVAudioQuality.medium.rawValue,
        ]
        guard let recorder = try? AVAudioRecorder(url: url, settings: settings) else {
            return false
        }
        self.url = url
        self.recorder = recorder
        recorder.record(forDuration: Self.maxSeconds)
        isRecording = true
        elapsed = 0
        ticker = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, let recorder = self.recorder else { return }
                self.elapsed = recorder.currentTime
                if !recorder.isRecording { self.isRecording = false }
            }
        }
        return true
    }

    /// Stop and hand back the recorded bytes; the temp file is deleted either way.
    func finish() -> Data? {
        defer { cleanup() }
        recorder?.stop()
        guard let url, let data = try? Data(contentsOf: url), !data.isEmpty else { return nil }
        return data
    }

    func cancel() {
        recorder?.stop()
        cleanup()
    }

    private func cleanup() {
        ticker?.invalidate()
        ticker = nil
        isRecording = false
        recorder = nil
        if let url { try? FileManager.default.removeItem(at: url) }
        url = nil
    }
}

/// Plays a downloaded voice note from MEMORY (`AVAudioPlayer(data:)`) — the decrypted audio never
/// touches disk to be heard.
@MainActor
final class VoiceNotePlayer: NSObject, ObservableObject, AVAudioPlayerDelegate {
    @Published private(set) var isPlaying = false
    @Published private(set) var progress: Double = 0
    @Published private(set) var duration: TimeInterval = 0

    private var player: AVAudioPlayer?
    private var ticker: Timer?

    func toggle(data: Data) {
        if isPlaying {
            player?.pause()
            isPlaying = false
            ticker?.invalidate()
            return
        }
        if player == nil {
            guard let p = try? AVAudioPlayer(data: data) else { return }
            p.delegate = self
            player = p
            duration = p.duration
        }
        #if os(iOS)
            try? AVAudioSession.sharedInstance().setCategory(.playback)
        #endif
        player?.play()
        isPlaying = true
        ticker = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, let p = self.player else { return }
                self.progress = p.duration > 0 ? p.currentTime / p.duration : 0
            }
        }
    }

    nonisolated func audioPlayerDidFinishPlaying(_ player: AVAudioPlayer, successfully flag: Bool) {
        Task { @MainActor in
            self.isPlaying = false
            self.progress = 0
            self.ticker?.invalidate()
        }
    }
}

/// A voice-note bubble: play/pause, a progress bar, and the duration once known.
struct VoiceNoteBubbleView: View {
    let data: Data
    let mine: Bool
    let palette: Nedwons.Palette
    @StateObject private var player = VoiceNotePlayer()

    var body: some View {
        HStack(spacing: Nedwons.Spacing.sm) {
            Button {
                player.toggle(data: data)
            } label: {
                Image(systemName: player.isPlaying ? "pause.circle.fill" : "play.circle.fill")
                    .imageScale(.large)
            }
            .accessibilityLabel(player.isPlaying ? "Pause voice message" : "Play voice message")
            ProgressView(value: player.progress)
                .frame(width: 120)
            if player.duration > 0 {
                Text(Self.clock(player.duration))
                    .font(Nedwons.TypeScale.caption)
                    .monospacedDigit()
            }
        }
        .foregroundStyle(mine ? .white : palette.textPrimary)
        .accessibilityElement(children: .combine)
    }

    static func clock(_ t: TimeInterval) -> String {
        String(format: "%d:%02d", Int(t) / 60, Int(t) % 60)
    }
}

// MARK: - Viewing videos & documents (QuickLook over a protected temp copy)

/// Videos and documents cannot be viewed from memory — AVPlayer and QuickLook require a file. So
/// viewing writes ONE decrypted temp copy with complete file protection, shows it, and deletes it
/// when the viewer closes. That is a deliberate, stated exception to the images-stay-in-memory
/// rule (and the honest baseline every mainstream messenger shares).
@MainActor
struct MediaTempFile {
    let url: URL

    init?(data: Data, filename: String) {
        let safe = filename
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "..", with: "_")
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nedwons-view-\(UUID().uuidString)", isDirectory: true)
        let url = dir.appendingPathComponent(safe.isEmpty ? "file" : safe)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            #if os(iOS)
                try data.write(to: url, options: [.atomic, .completeFileProtection])
            #else
                try data.write(to: url, options: [.atomic])
            #endif
        } catch {
            return nil
        }
        self.url = url
    }

    func remove() {
        try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
    }
}

#if os(iOS)
    /// QuickLook previews both documents and videos — one viewer, OS-rendered.
    struct QuickLookPreview: UIViewControllerRepresentable {
        let url: URL

        func makeUIViewController(context: Context) -> QLPreviewController {
            let controller = QLPreviewController()
            controller.dataSource = context.coordinator
            return controller
        }

        func updateUIViewController(_ controller: QLPreviewController, context: Context) {}

        func makeCoordinator() -> Coordinator { Coordinator(url: url) }

        final class Coordinator: NSObject, QLPreviewControllerDataSource {
            let url: URL
            init(url: URL) { self.url = url }
            func numberOfPreviewItems(in controller: QLPreviewController) -> Int { 1 }
            func previewController(_ controller: QLPreviewController, previewItemAt index: Int)
                -> QLPreviewItem
            { url as NSURL }
        }
    }
#endif

/// Sheet wrapper owning the temp copy's lifecycle: created when shown, removed on dismiss.
struct MediaPreviewSheet: View {
    let data: Data
    let filename: String
    @Environment(\.dismiss) private var dismiss
    @State private var temp: MediaTempFile?

    var body: some View {
        Group {
            #if os(iOS)
                if let temp {
                    QuickLookPreview(url: temp.url)
                } else {
                    ProgressView()
                }
            #else
                Text("Preview isn't available on this platform.")
            #endif
        }
        .onAppear { temp = MediaTempFile(data: data, filename: filename) }
        .onDisappear {
            temp?.remove()
            temp = nil
        }
    }
}
