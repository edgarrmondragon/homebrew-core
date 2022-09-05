require "language/node"

class OpensearchDashboards < Formula
  desc "Open source visualization dashboards for OpenSearch"
  homepage "https://opensearch.org/docs/dashboards/index/"
  url "https://github.com/opensearch-project/OpenSearch-Dashboards.git",
      tag:      "2.2.1",
      revision: "d630bc4fb3740cdb0d18e70b4f750b856432441b"
  license "Apache-2.0"

  bottle do
    sha256 cellar: :any_skip_relocation, monterey:     "24451df323a5b5f0e3d331559f39609fcc9b19823f6739e8671f2e823a3b5b72"
    sha256 cellar: :any_skip_relocation, big_sur:      "24451df323a5b5f0e3d331559f39609fcc9b19823f6739e8671f2e823a3b5b72"
    sha256 cellar: :any_skip_relocation, catalina:     "24451df323a5b5f0e3d331559f39609fcc9b19823f6739e8671f2e823a3b5b72"
    sha256 cellar: :any_skip_relocation, x86_64_linux: "741f3ab9118fd19fc98806b5bc69f7035efec59c3950eb45588d1fffa597d34a"
  end

  depends_on "yarn" => :build
  depends_on arch: :x86_64 # https://github.com/opensearch-project/OpenSearch-Dashboards/issues/1630
  depends_on "node@14" # use `node@16` after https://github.com/opensearch-project/OpenSearch-Dashboards/issues/406

  def install
    inreplace "package.json", /"node": "14\.\d+\.\d+"/, %Q("node": "#{Formula["node@14"].version}")

    # Do not download node and discard all actions related to this node
    inreplace "src/dev/build/build_distributables.ts" do |s|
      s.gsub! "await run(options.downloadFreshNode ? Tasks.DownloadNodeBuilds : Tasks.VerifyExistingNodeBuilds);", ""
      s.gsub! "await run(Tasks.ExtractNodeBuilds);", ""
    end
    inreplace "src/dev/build/tasks/create_archives_sources_task.ts",
              Regexp.new(<<~EOS), ""
                \\s*await scanCopy\\(\\{
                \\s*  source: getNodeDownloadInfo\\(config, platform\\).extractDir,
                \\s*  destination: build.resolvePathForPlatform\\(platform, 'node'\\),
                \\s*\\}\\);
              EOS
    inreplace "src/dev/notice/generate_build_notice_text.js",
              "generateNodeNoticeText(nodeDir, nodeVersion)", "''"

    system "yarn", "osd", "bootstrap"
    system "node", "scripts/build", "--release", "--skip-os-packages", "--skip-archives", "--skip-node-download"

    os = OS.kernel_name.downcase
    arch = Hardware::CPU.intel? ? "x64" : Hardware::CPU.arch.to_s
    cd "build/opensearch-dashboards-#{version}-#{os}-#{arch}" do
      inreplace Dir["bin/*"],
                "\"${DIR}/node/bin/node\"",
                "\"#{Formula["node@14"].opt_bin/"node"}\""

      inreplace "config/opensearch_dashboards.yml",
                /#\s*pid\.file: .+$/,
                "pid.file: #{var}/run/opensearchDashboards.pid"

      (etc/"opensearch-dashboards").install Dir["config/*"]
      rm_rf Dir["{config,data,node,plugins}"]

      prefix.install Dir["*"]
    end
  end

  def post_install
    (var/"log/opensearch-dashboards").mkpath

    (var/"lib/opensearch-dashboards").mkpath
    ln_s var/"lib/opensearch-dashboards", prefix/"data" unless (prefix/"data").exist?

    (var/"opensearch-dashboards/plugins").mkpath
    ln_s var/"opensearch-dashboards/plugins", prefix/"plugins" unless (prefix/"plugins").exist?

    ln_s etc/"opensearch-dashboards", prefix/"config" unless (prefix/"config").exist?
  end

  def caveats
    <<~EOS
      Data:    #{var}/lib/opensearch-dashboards/
      Logs:    #{var}/log/opensearch-dashboards/opensearch-dashboards.log
      Plugins: #{var}/opensearch-dashboards/plugins/
      Config:  #{etc}/opensearch-dashboards/
    EOS
  end

  plist_options manual: "opensearch-dashboards"
  service do
    run opt_bin/"opensearch-dashboards"
    log_path var/"log/opensearch-dashboards.log"
    error_log_path var/"log/opensearch-dashboards.log"
  end

  test do
    ENV["BABEL_CACHE_PATH"] = testpath/".babelcache.json"

    (testpath/"data").mkdir
    (testpath/"config.yml").write <<~EOS
      path.data: #{testpath}/data
    EOS

    port = free_port
    fork do
      exec bin/"opensearch-dashboards", "-p", port.to_s, "-c", testpath/"config.yml"
    end
    sleep 15
    output = shell_output("curl -s 127.0.0.1:#{port}")
    # opensearch-dashboards returns this message until it connects to opensearch
    assert_equal "OpenSearch Dashboards server is not ready yet", output
  end
end
