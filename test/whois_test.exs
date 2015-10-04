defmodule WhoisTest do
  use ExUnit.Case

  test "afilias whois" do
    response = %{
    "domain"          => "AFILIAS.INFO",
    "created"         => "2001-07-25T14:11:20Z",
    "updated"         => "2014-06-30T14:22:47Z",
    "expire"          => "2021-07-25T14:11:20Z",
    "registrar"       => "Afilias (R145-LRMS)",
    "status"          => "ok -- http://www.icann.org/epp#ok",
    "owner_ccode"     => "IE",
    "owner_city"      => "Dublin",
    "owner_company"   => "Afilias",
    "owner_fax"       => "+353.17918569",
    "owner_mail"      => "support@afilias.info",
    "owner_name"      => "Afilias",
    "owner_pcode"     => "D01 K8F1",
    "owner_phone"     => "+353.18541100",
    "owner_state"     => "",
    "owner_street"    => "",
    "admin_ccode"     => "IE",
    "admin_city"      => "Dublin",
    "admin_company"   => "Afilias",
    "admin_fax"       => "+353.17918569",
    "admin_mail"      => "support@afilias.info",
    "admin_name"      => "Afilias",
    "admin_pcode"     => "D01 K8F1",
    "admin_phone"     => "+353.18541100",
    "admin_state"     => "",
    "admin_street"    => "",
    "billing_ccode"   => "IE", 
    "billing_city"    => "Dublin",
    "billing_company" => "Afilias",
    "billing_fax"     => "+353.17918569",
    "billing_mail"    => "support@afilias.info",
    "billing_name"    => "Afilias",
    "billing_pcode"   => "D01 K8F1",
    "billing_phone"   => "+353.18541100",
    "billing_state"   => "",
    "billing_street"  => "",
    "tech_ccode"      => "IE",
    "tech_city"       => "Dublin",
    "tech_company"    => "Afilias",
    "tech_fax"        => "+353.17918569",
    "tech_mail"       => "support@afilias.info",
    "tech_name"       => "Afilias",
    "tech_pcode"      => "D01 K8F1",
    "tech_phone"      => "+353.18541100",
    "tech_state"      => "",
    "tech_street"     => "",
    "ns" =>
        "A0.DIG.AFILIAS-NST.INFO\nB0.DIG.AFILIAS-NST.INFO\nC0.DIG.AFILIAS-NST.INFO\nD0.DIG.AFILIAS-NST.INFO",
    }
    assert Whois.get("afilias.info") == response
  end

  test "dotMe whois" do
	response = %{}
    assert Whois.get("nic.me") == response
  end
end

