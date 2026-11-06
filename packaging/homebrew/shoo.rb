class Shoo < Formula
  desc "Block ads in Safari on macOS, including YouTube ads"
  homepage "https://github.com/kornelkaa/shoo"
  url "https://github.com/kornelkaa/shoo/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  head "https://github.com/kornelkaa/shoo.git", branch: "main"

  depends_on "go" => :build
  depends_on :macos

  def install
    system "go", "build", *std_go_args(ldflags: "-X main.version=#{version}"), "./cmd/shoo"
  end

  def caveats
    <<~EOS
      To finish, run (asks for your password twice):
        shoo setup

      Before `brew uninstall shoo`, turn shoo off:
        shoo uninstall
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/shoo version")
    assert_match "shoo setup", shell_output("#{bin}/shoo 2>&1", 2)
  end
end
