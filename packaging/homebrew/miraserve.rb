# Homebrew formula template for MiraServe (macOS & Linuxbrew).
# For a tagged release (or `--HEAD` against the publishing repository), use the
# stamped `miraserve.rb` asset published on that GitHub Release (stamped by
# `.github/workflows/release.yml` with the publishing `github.repository` for
# `homepage`, `url`, and `head`, plus the tag and frozen
# `miraserve-<tag>-src.tar.gz` SHA-256; never point this formula at pre-fork
# v0.1.3 or another repository).
class Miraserve < Formula
  desc "Web server and edge gateway in memory-safe Rust with post-quantum HTTPS"
  homepage "https://github.com/REPLACE_WITH_GITHUB_REPOSITORY"
  url "https://github.com/REPLACE_WITH_GITHUB_REPOSITORY/releases/download/REPLACE_WITH_RELEASE_TAG/miraserve-REPLACE_WITH_RELEASE_TAG-src.tar.gz"
  sha256 "REPLACE_WITH_SOURCE_TARBALL_SHA256"
  license any_of: ["Apache-2.0", "MIT"]
  head "https://github.com/REPLACE_WITH_GITHUB_REPOSITORY.git", branch: "main"

  depends_on "cmake" => :build
  depends_on "rust" => :build

  def install
    system "cargo", "install", "--locked", "--path", "crates/miraserve-bin", "--root", prefix
    (etc/"miraserve").mkpath
    (etc/"miraserve/certs").mkpath
    (var/"lib/miraserve/acme").mkpath
    (var/"lib/miraserve/releases").mkpath
    (var/"www/miraserve").mkpath
    (var/"log").mkpath

    (buildpath/"homebrew-miraserve.kdl").write <<~KDL
      server {
          listen "127.0.0.1:8443" protocols="h3,h2,h1"
          listen "127.0.0.1:8080" redirect-https=#true
          tls {
              min-version "1.3"
              pqc-hybrid #true
              cert "#{etc}/miraserve/certs/starter.crt"
              key "#{etc}/miraserve/certs/starter.key"
          }
      }
      site "localhost" {
          security-headers "strict"
          root "#{var}/www/miraserve"
      }
    KDL
    etc.install buildpath/"homebrew-miraserve.kdl" => "miraserve/miraserve.kdl"
    pkgshare.install "examples/miraserve.kdl"
    prefix.install "vendor/h2/LICENSE" => "LICENSE-h2-MIT"
    (var/"www/miraserve/index.html").write(File.read("packaging/nfpm/index.html")) unless (var/"www/miraserve/index.html").exist?
  end

  def post_install
    (etc/"miraserve/certs").mkpath
    cert = etc/"miraserve/certs/starter.crt"
    key  = etc/"miraserve/certs/starter.key"
    if !cert.exist? || !key.exist?
      system opt_bin/"miraserve", "cert", "generate-dev",
             "--hosts", "localhost",
             "--cert", cert,
             "--key", key,
             "--force"
    end
  end

  service do
    run [
      opt_bin/"miraserve",
      "run",
      etc/"miraserve/miraserve.kdl",
      "--acme-dir",
      var/"lib/miraserve/acme",
    ]
    keep_alive crashed: true
    working_dir var/"lib/miraserve"
    log_path var/"log/miraserve.out.log"
    error_log_path var/"log/miraserve.err.log"
  end

  def caveats
    <<~EOS
      A starter KDL configuration was installed to:
        #{etc}/miraserve/miraserve.kdl

      A unique per-host self-signed localhost starter certificate was generated at:
        #{etc}/miraserve/certs/starter.crt (and starter.key, mode 0600)
      Replace with ACME or production certificates before exposing MiraServe publicly.

      Validate your configuration and on-disk files before starting or reloading:
        miraserve check --fs --strict #{etc}/miraserve/miraserve.kdl

      Full multi-site reference example:
        #{opt_pkgshare}/miraserve.kdl

      To generate a hardened LaunchDaemon plist (append --dev-tls if omitting static certs):
        miraserve service generate --target launchd --binary #{opt_bin}/miraserve --log-dir #{var}/log
    EOS
  end

  test do
    assert_match "X25519MLKEM768", shell_output("#{bin}/miraserve version")
    (testpath/"test.kdl").write <<~KDL
      server {
        listen "127.0.0.1:8443" protocols="h3,h2,h1"
      }
      site "localhost" {
        root "#{testpath}"
      }
    KDL
    system bin/"miraserve", "check", "--strict", "--dev-tls", testpath/"test.kdl"
  end
end
