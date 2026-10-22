class Orvpass < Formula
  desc "Ultra-fast, zero-knowledge terminal password & secrets manager"
  homepage "https://github.com/krtvysinghhhh/Orvpass"
  url "https://github.com/krtvysinghhhh/Orvpass/archive/refs/tags/v5.5.0.tar.gz"
  sha256 "2699bd0e7b9405a6974e1ce421eab78913ec6663eb4b1ad022d0590c77b26d02"
  license "Apache-2.0"
  head "https://github.com/krtvysinghhhh/Orvpass.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "cli")
  end

  test do
    assert_match "orvpass", shell_output("#{bin}/orvpass --version")
  end
end
