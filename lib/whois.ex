defmodule Whois do

  require Logger

  def lookup(domain) do
    Whois.get(domain)
  end

  def get(domain) do
    {:ok, pid} = WhoisWorker.start_link()
    [tld | _] = :lists.reverse(String.split(domain, "."))
    server = ExWhois.Map.to_whois(tld)
    WhoisWorker.whois(pid, domain, server)
    whois = receive do
      {:ok, whois} ->

        whois
      _ ->
        IO.puts :stderr, "Unexpected message received"
    after 5000 ->
      IO.puts :stderr, "No message in 5 seconds"
    end
    WhoisWorker.stop(pid)
    whois
    |> parse(server)
  end
  
  def parse(whois, "whois.afilias.net") do

    regex_list = [~r/Domain Name:(?<domain>.+)\n/,
      ~r/Creation Date:(?<created>.+)\n/,
      ~r/Updated Date:(?<updated>.+)\n/,
      ~r/Registry Expiry Date:(?<expire>.+)\n/,
      ~r/Sponsoring Registrar:(?<registrar>.+)\n/,
      ~r/Domain Status:(?<status>.+)\n/,
      ~r/Name Server:(?<ns>.+)\n/] ++ handle_regex_01()


    Enum.reduce(regex_list, %{}, fn(regex, acc) ->
      Map.merge(acc, parse_line(regex, whois)) end)
  end
  def parse(whois, "whois.nic.me") do

    regex_list = [~r/Domain Name:(?<domain>.+)\n/,
      ~r/Domain Create Date:(?<created>.+)\n/,
      ~r/Domain Last Updated Date:(?<updated>.+)\n/,
      ~r/Domain Expiration Date:(?<expire>.+)\n/,
      ~r/Sponsoring Registrar:(?<registrar>.+)\n/,
      ~r/Domain Status:(?<status>.+)\n/,
      ~r/Nameservers:(?<ns>.+)\n/] ++ handle_regex_01()


    Enum.reduce(regex_list, %{}, fn(regex, acc) ->
      Map.merge(acc, parse_line(regex, whois)) end)
  end


  def parse(whois, server) do
    Logger.error("Whois server: #{server} not yet supported")
    whois
  end

  def parse_line(regex, whois) do
    # Logger.debug("Parsing regex: #{inspect regex}")

    match = Enum.map(Regex.scan(regex, whois), fn([_ | [str]]) -> String.strip(str) end)
      |> Enum.filter(fn(x) -> String.match?(x, ~r/^[\w\d\+]/) end)
      |> Enum.join("\n")

    [key] = Regex.names(regex)
    Map.put(%{}, key, match)
  end

  defp handle_regex_01 do
    [
      ~r/Registrant Name:(?<owner_name>.+)\n/,
      ~r/Registrant Organization:(?<owner_company>.+)\n/,
      ~r/Registrant Street:(?<owner_street>.+)\n/,
      ~r/Registrant Address.*:(?<owner_street>.+)\n/,
      ~r/Registrant City:(?<owner_city>.+)\n/,
      ~r/Registrant State\/Province:(?<owner_state>.+)\n/,
      ~r/Registrant Postal Code:(?<owner_pcode>.+)\n/,
      ~r/Registrant Country.*:(?<owner_ccode>.+)\n/,
      ~r/Registrant Phone:(?<owner_phone>.+)\n/,
      ~r/Registrant Fax:(?<owner_fax>.+)\n/,
      ~r/Registrant E.*mail:(?<owner_mail>.+)\n/,
      ~r/Admin Name:(?<admin_name>.+)\n/,
      ~r/Admin Organization:(?<admin_company>.+)\n/,
      ~r/Admin Street:(?<admin_street>.+)\n/,
      ~r/Admin Address.*:(?<admin_street>.+)\n/,
      ~r/Admin City:(?<admin_city>.+)\n/,
      ~r/Admin State\/Province:(?<admin_state>.+)\n/,
      ~r/Admin Postal Code:(?<admin_pcode>.+)\n/,
      ~r/Admin Country.*:(?<admin_ccode>.+)\n/,
      ~r/Admin Phone:(?<admin_phone>.+)\n/,
      ~r/Admin Fax:(?<admin_fax>.+)\n/,
      ~r/Admin E.*mail:(?<admin_mail>.+)\n/,
      ~r/Billing Name:(?<billing_name>.+)\n/,
      ~r/Billing Organization:(?<billing_company>.+)\n/,
      ~r/Billing [Street|Address].*:(?<billing_street>.+)\n/,
      ~r/Billing City:(?<billing_city>.+)\n/,
      ~r/Billing State\/Province:(?<billing_state>.+)\n/,
      ~r/Billing Postal Code:(?<billing_pcode>.+)\n/,
      ~r/Billing Country.*:(?<billing_ccode>.+)\n/,
      ~r/Billing Phone:(?<billing_phone>.+)\n/,
      ~r/Billing Fax:(?<billing_fax>.+)\n/,
      ~r/Billing E.*mail:(?<billing_mail>.+)\n/,
      ~r/Tech Name:(?<tech_name>.+)\n/,
      ~r/Tech Organization:(?<tech_company>.+)\n/,
      ~r/Tech Street:(?<tech_street>.+)\n/,
      ~r/Tech Address.*:(?<tech_street>.+)\n/,
      ~r/Tech City:(?<tech_city>.+)\n/,
      ~r/Tech State\/Province:(?<tech_state>.+)\n/,
      ~r/Tech Postal Code:(?<tech_pcode>.+)\n/,
      ~r/Tech Country.*:(?<tech_ccode>.+)\n/,
      ~r/Tech Phone:(?<tech_phone>.+)\n/,
      ~r/Tech Fax:(?<tech_fax>.+)\n/,
      ~r/Tech E.*mail:(?<tech_mail>.+)\n/
   ] 
  end

end
