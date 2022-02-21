class StructurizrCli < Formula
  desc "Command-line utility for Structurizr"
  homepage "https://structurizr.com"
  url "https://github.com/structurizr/cli/releases/download/v1.18.0/structurizr-cli-1.18.0.zip"
  sha256 "fad2fdff2e6002a5a0d9d890c3eb824c98b2f626855d2d941bede80e6d4aedca"
  license "Apache-2.0"

  bottle do
    sha256 cellar: :any_skip_relocation, all: "c88252fdd70a140ace00ec88851f122619dc60dc985a888b617570285f2ba7d4"
  end

  depends_on "openjdk"

  def install
    rm_f Dir["*.bat"]
    libexec.install Dir["*"]
    (bin/"structurizr-cli").write_env_script libexec/"structurizr.sh", Language::Java.overridable_java_home_env
  end

  test do
    expected_output = <<~EOS.strip
      Structurizr CLI v#{version}
      Structurizr DSL v#{version}
      Usage: structurizr push|pull|lock|unlock|export|validate|list [options]
    EOS
    result = pipe_output("#{bin}/structurizr-cli").strip
    assert_equal result, expected_output
  end
end
