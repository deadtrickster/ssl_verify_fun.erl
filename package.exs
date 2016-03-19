defmodule SSLVerifyFun.Mixfile do
  use Mix.Project

  def project do
    [app: :ssl_verify_fun,
     version: "1.0.8",
     description: description,
     package: package,
     fetch: fetch]
  end

  defp description do
    """
    SSL verification functions for Erlang
    """
  end

  defp package do
    [maintainers: ["Ilya Khaprov"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/deadtrickster/ssl_verify_fun.erl"},
     files: ["src", "README.md", "LICENSE", "Makefile", "rebar.config"]]
  end
end
