defmodule WhoisTest do
  use ExUnit.Case

  test "org whois server" do
    assert Whois.server("org") == {:ok, {199, 15, 84, 131}}
  end
end

