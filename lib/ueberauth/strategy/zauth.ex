defmodule Ueberauth.Strategy.Zauth do
  @moduledoc false

  use Ueberauth.Strategy,
    uid: :id,
    default_scope: "",
    send_redirect_uri: true,
    oauth2_module: Ueberauth.Strategy.Zauth.OAuth

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  def handle_request!(conn) do
    opts =
      []
      |> with_scopes(conn)
      |> with_state_param(conn)
      |> with_redirect_uri(conn)

    module = option(conn, :oauth2_module)
    redirect!(conn, apply(module, :authorize_url!, [opts]))
  end

  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    module = option(conn, :oauth2_module)
    token = apply(module, :get_token!, [[code: code]])

    if token.access_token == nil do
      set_errors!(conn, [
        error(token.other_params["error"], token.other_params["error_description"])
      ])
    else
      fetch_user(conn, token)
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc """
  Cleans up the private area of the connection used for passing the raw Zauth
  response around during the callback.
  """
  def handle_cleanup!(conn) do
    conn
    |> put_private(:zauth_user, nil)
    |> put_private(:zauth_token, nil)
  end

  def info(conn) do
    user = conn.private.zauth_user

    %Info{
      name: user["username"],
      admin: user["admin"]
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from Zauth
  callback.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.zauth_token,
        user: conn.private.zauth_user
      }
    }
  end

  defp fetch_user(conn, token) do
    conn = put_private(conn, :zauth_token, token)
    # Will be better with Elixir 1.3 with/else
    case Ueberauth.Strategy.Zauth.OAuth.get(token, "/current_user") do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])

      {:ok, %OAuth2.Response{status_code: status_code, body: user}}
      when status_code in 200..399 ->
        put_private(conn, :zauth_user, user)

      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])

      {:error, %OAuth2.Response{body: %{"message" => reason}}} ->
        set_errors!(conn, [error("OAuth2", reason)])

      {:error, _} ->
        set_errors!(conn, [error("OAuth2", "unknown error")])
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end

  defp with_scopes(opts, conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)

    opts |> Keyword.put(:scope, scopes)
  end

  defp with_redirect_uri(opts, conn) do
    if option(conn, :send_redirect_uri) do
      opts |> Keyword.put(:redirect_uri, callback_url(conn))
    else
      opts
    end
  end
end
