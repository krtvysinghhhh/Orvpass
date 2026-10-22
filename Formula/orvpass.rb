class Orvpass < Formula
  desc "Ultra-fast, zero-knowledge terminal password & secrets manager"
  homepage "https://github.com/krtvysinghhhh/Orvpass"
  url "https://github.com/krtvysinghhhh/Orvpass/archive/refs/tags/v5.5.0.tar.gz"
  sha256 "355ad0f0198a075f9507fe21aab91b80c78f8e4bda7c58a4704ae63b04fbe5e6"
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
