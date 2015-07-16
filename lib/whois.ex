defmodule Whois do
  
  def get(domain) do
    {:ok, pid} = WhoisWorker.start_link()
    WhoisWorker.whois(pid, domain)
    whois = receive do
      {:ok, whois} ->

        whois
      _ ->
        IO.puts :stderr, "Unexpected message received"
    after
      5000 ->
        IO.puts :stderr, "No message in 5 seconds"
    end
    WhoisWorker.stop(pid)
    whois
  end
end
