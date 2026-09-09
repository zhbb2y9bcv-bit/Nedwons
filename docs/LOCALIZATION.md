# Localization — state and plan

**State (2026-09-09), honestly:** every user-facing string is authored in English directly in the
SwiftUI views and models. Both packages now declare `defaultLocalization: "en"`, so the resource
pipeline is ready, but **no string is wrapped for translation yet** — this file exists so nobody
mistakes groundwork for done.

**Plan (mechanical, not started):**
1. Adopt a String Catalog (`Localizable.xcstrings`) in `NedwonsUI`; Xcode extracts SwiftUI
   `Text`/`Label` literals automatically at build time, which covers most of the surface without
   code changes.
2. Wrap the non-view strings (model banners, `errorText`, notification copy in `NedwonsPush`) in
   `String(localized:)` — these do NOT auto-extract. Banner-asserting tests compare English
   source strings and stay valid until a translation for the test locale exists.
3. Audit for concatenated sentences (several banners build strings with `+`); convert to
   interpolated format strings so word order can differ per language.
4. Pseudo-localization pass (Xcode scheme option) to catch clipped layouts before any real
   translation is commissioned.

**Why it was deferred:** wrapping several hundred strings is a large mechanical diff with real
regression surface and zero user-visible change until translations exist; it was traded for
functional arcs. It remains on the launch checklist — an English-only messenger is not
"comparable to the big players" outside the anglosphere.
