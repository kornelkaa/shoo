class Ytblock < Formula
  desc "Block ads in Safari on macOS, including YouTube ads"
  homepage "https://github.com/kornelkaa/ytblock"
  url "https://github.com/kornelkaa/ytblock/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  head "https://github.com/kornelkaa/ytblock.git", branch: "main"

  depends_on "go" => :build
  depends_on :macos

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w -X main.version=#{version}"), "./cmd/ytblock"
  end

  def caveats
    <<~EOS
      To finish, run (asks for your password twice):
        ytblock setup

      Before `brew uninstall ytblock`, turn ytblock off:
        ytblock uninstall
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/ytblock version")
    assert_match "ytblock setup", shell_output("#{bin}/ytblock 2>&1", 2)
  end
end
