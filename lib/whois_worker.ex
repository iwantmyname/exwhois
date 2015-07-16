defmodule WhoisWorker do
  require Logger
  use GenServer

  # public API
  def start_link() do
    GenServer.start_link(__MODULE__, %{whois: ""})
  end

  def whois(pid, domain) do
    GenServer.call(pid, {:whois, domain})
  end

  def stop(pid) do
    GenServer.cast(pid, :stop)
  end

  ## GenServer callbacks

  def handle_call({:whois, domain}, {pid, _ref}, state) do
    [tld | _] = :lists.reverse(String.split(domain, "."))
    {:ok, ip} = server(tld)
    Logger.info("Got #{inspect ip} for #{tld}")
    {:ok, socket} = :gen_tcp.connect(ip, 43, [:binary, packet: :line])
    :gen_tcp.send(socket, "#{domain}\n")
    state1 = Map.put(state, :client, pid)

    {:reply, {:ok, :started}, %{state1 | whois: ""}}
  end
  def handle_call(stuff, _from, state) do
    Logger.debug("Got unhandeled call: #{inspect stuff}")

    {:reply, nil, state}
  end
  def handle_cast(:stop, state) do
    {:stop, :normal, state}
  end
  def handle_cast(stuff, state) do
    Logger.debug("Got unhandeled cast: #{inspect stuff}")

    {:noreply, state}
  end

  def handle_info({:tcp, _port, data}, state) do
    # Logger.debug("Got data: #{data}")

    whois = state.whois <> data
    {:noreply, %{state | whois: whois}}
  end
  def handle_info({:tcp_closed, _port}, state) do
    Logger.debug("Got whois: #{state.whois}")
    send state.client, {:ok, state.whois}

    {:noreply, %{state | client: nil}}
  end
  def handle_info(stuff, state) do
    Logger.debug("Got unhandeled info: #{inspect stuff}")

    {:noreply, state}
  end

  # internal stuff

  defp server(tld) do
    :inet.getaddr(:erlang.binary_to_list("#{tld}.whois-servers.net"), :inet)
  end
end
