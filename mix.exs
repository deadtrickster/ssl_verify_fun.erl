defmodule SSLVerifyFun.Mixfile do
  use Mix.Project

  {:ok, [{:application, :ssl_verify_fun, props}]} = :file.consult("src/ssl_verify_fun.app.src")
  {:vsn, app_vsn} = List.keyfind(props, :vsn, 0)
  {:description, app_description} = List.keyfind(props, :description, 0)
  @version to_string(app_vsn)
  @description to_string(app_description)

  # ssl is the only OTP application this library calls into. kernel and stdlib
  # are implicit, and naming :applications explicitly would drop the dep apps
  # that Mix uses to decide which dependency paths to load.
  def application do
    [extra_applications: [:ssl]]
  end

  def project do
    [app: :ssl_verify_fun,
     language: :erlang,
     version: @version,
     description: @description,
     package: package(),
     deps: deps(),
     name: "ssl_verify_fun",
     source_url: "https://github.com/deadtrickster/ssl_verify_fun.erl",
     docs: docs()]
  end

  defp deps() do
    [{:ex_doc, ">= 0.0.0", only: :dev, runtime: false}]
  end

  # src carries no edoc annotations, so the README is the only documentation page
  defp docs() do
    [main: "readme",
     api_reference: false,
     extras: ["README.md", "CHANGELOG.md"]]
  end

  defp package() do
    [maintainers: ["Ilya Khaprov"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/deadtrickster/ssl_verify_fun.erl"},
     files: ["src", "README.md", "CHANGELOG.md", "LICENSE", "Makefile", "rebar.config", "mix.exs"]]
  end
end
