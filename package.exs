defmodule Hackney.Mixfile do
  use Mix.Project

  def project do
    [app: :ssl_verify_hostname,
     version: "1.0.5",
     description: description,
     package: package,
     fetch: fetch]
  end

  defp description do
    """
    Hostname verification library for Erlang
    """
  end

  defp package do
    [contributors: ["Ilya Khaprov"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/deadtrickster/ssl_verify_hostname.erl"},
     files: ["src", "README.md", "LICENSE", "Makefile"]]
  end

  defp fetch do
    [scm: :git,
     url: "git://github.com/deadtrickster/ssl_verify_hostname.erl.git",
     tag: "1.0.5"]
  end
end
