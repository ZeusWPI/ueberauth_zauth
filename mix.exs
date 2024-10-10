defmodule UeberauthZauth.MixProject do
  use Mix.Project

  def project do
    [
      app: :ueberauth_zauth,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :ueberauth, :oauth2]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:oauth2, "~> 1.0 or ~> 2.0"},
      {:ueberauth, "~> 0.10"}
    ]
  end

  defp package do
    [
      description: "An Ueberauth strategy for using Zauth to authenticate your users.",
      files: ["lib", "mix.exs", "README.md", "LICENSE"],
      links: %{
        GitHub: "https://github.com/zeusWPI/ueberauth_zauth"
      }
    ]
  end
end
